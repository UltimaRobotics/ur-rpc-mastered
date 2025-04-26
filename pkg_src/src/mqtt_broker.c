/**
 * @file mqtt_broker.c
 * @brief Main MQTT broker implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mqtt_broker.h"
#include "logger.h"
#include "config.h"
#include "session.h"
#include "topic_tree.h"
#include "persistence.h"
#include "auth.h"
#include "disconnect_handler.h"
#include "net.h"
#include "utils.h"

// Global broker state
static int server_socket = -1;
static volatile int running = 0;
static pthread_t accept_thread;
static pthread_mutex_t broker_mutex = PTHREAD_MUTEX_INITIALIZER;

// Parse log level from string
static log_level_t parse_log_level(const char *level_str) {
    if (!level_str) {
        return LOG_LEVEL_INFO;
    }
    
    if (strcasecmp(level_str, "debug") == 0) {
        return LOG_LEVEL_DEBUG;
    } else if (strcasecmp(level_str, "info") == 0) {
        return LOG_LEVEL_INFO;
    } else if (strcasecmp(level_str, "warn") == 0) {
        return LOG_LEVEL_WARN;
    } else if (strcasecmp(level_str, "error") == 0) {
        return LOG_LEVEL_ERROR;
    } else if (strcasecmp(level_str, "fatal") == 0) {
        return LOG_LEVEL_FATAL;
    }
    
    return LOG_LEVEL_INFO;
}

// Structure to hold client connection data for thread
typedef struct {
    int socket;
    struct sockaddr_in addr;
} client_conn_t;

// Basic MQTT packet types
#define MQTT_CONNECT     1
#define MQTT_CONNACK     2
#define MQTT_PUBLISH     3
#define MQTT_PUBACK      4
#define MQTT_PUBREC      5
#define MQTT_PUBREL      6
#define MQTT_PUBCOMP     7
#define MQTT_SUBSCRIBE   8
#define MQTT_SUBACK      9
#define MQTT_UNSUBSCRIBE 10
#define MQTT_UNSUBACK    11
#define MQTT_PINGREQ     12
#define MQTT_PINGRESP    13
#define MQTT_DISCONNECT  14

// MQTT Connect Return Codes
#define MQTT_CONNACK_ACCEPTED                0
#define MQTT_CONNACK_REFUSED_PROTO_VERSION   1
#define MQTT_CONNACK_REFUSED_ID_REJECTED     2
#define MQTT_CONNACK_REFUSED_SERVER_UNAVAIL  3
#define MQTT_CONNACK_REFUSED_BAD_CREDS       4
#define MQTT_CONNACK_REFUSED_NOT_AUTH        5

// Read MQTT variable length field
static int read_mqtt_remaining_length(int socket, uint32_t *remaining_length) {
    uint8_t byte;
    uint32_t value = 0;
    int multiplier = 1;
    int bytes_read;
    int i = 0;
    
    do {
        bytes_read = recv(socket, &byte, 1, 0);
        if (bytes_read <= 0) {
            return -1;
        }
        
        value += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        i++;
    } while ((byte & 0x80) && i < 4);
    
    // Check if we've read too many bytes (4 is the maximum for MQTT)
    if (i == 4 && (byte & 0x80)) {
        return -1;
    }
    
    *remaining_length = value;
    return i;
}

// Read MQTT packet (returns packet type or -1 on error)
static int read_mqtt_packet(int socket, uint8_t *buf, size_t buf_size, uint32_t *packet_len) {
    uint8_t first_byte;
    uint32_t remaining_length;
    int bytes_read;
    int len_bytes;
    
    // Read first byte (packet type + flags)
    bytes_read = recv(socket, &first_byte, 1, 0);
    if (bytes_read <= 0) {
        return -1;
    }
    
    // Read variable length
    len_bytes = read_mqtt_remaining_length(socket, &remaining_length);
    if (len_bytes < 0) {
        return -1;
    }
    
    // Check if buffer is large enough
    if (1 + len_bytes + remaining_length > buf_size) {
        log_error("Packet too large for buffer: %d bytes needed", 1 + len_bytes + remaining_length);
        return -1;
    }
    
    // Store the first byte and length in the buffer
    buf[0] = first_byte;
    for (int i = 0; i < len_bytes; i++) {
        buf[1 + i] = (remaining_length >> (i * 7)) & 0x7F;
        if (i < len_bytes - 1) {
            buf[1 + i] |= 0x80;
        }
    }
    
    // Read the rest of the packet
    if (remaining_length > 0) {
        bytes_read = recv(socket, buf + 1 + len_bytes, remaining_length, 0);
        if (bytes_read != remaining_length) {
            log_error("Failed to read complete packet: expected %d bytes, got %d", 
                      remaining_length, bytes_read);
            return -1;
        }
    }
    
    // Set the total packet length
    *packet_len = 1 + len_bytes + remaining_length;
    
    // Return the packet type (high 4 bits of the first byte)
    return (first_byte & 0xF0) >> 4;
}

// Process CONNECT packet and send CONNACK
static int process_connect_packet(int socket, uint8_t *buf, uint32_t packet_len) {
    uint8_t resp[4];
    uint16_t protocol_name_len;
    uint8_t protocol_level;
    uint8_t connect_flags;
    uint16_t keep_alive;
    uint16_t client_id_len;
    char client_id[256];
    int pos = 0;
    
    // MQTT Fixed Header is already in buf[0] and buf[1]
    pos = 2;  // Skip fixed header
    
    // Extract protocol name
    if (pos + 2 > packet_len) return -1;
    protocol_name_len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    
    // Check protocol name (should be "MQTT" or "MQIsdp")
    if (pos + protocol_name_len > packet_len) return -1;
    // We'll skip actual name validation for simplicity
    pos += protocol_name_len;
    
    // Extract protocol level
    if (pos + 1 > packet_len) return -1;
    protocol_level = buf[pos];
    pos++;
    
    // Extract connect flags
    if (pos + 1 > packet_len) return -1;
    connect_flags = buf[pos];
    pos++;
    
    // Extract keep alive time
    if (pos + 2 > packet_len) return -1;
    keep_alive = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    
    // Log connection details
    log_debug("CONNECT: Protocol level=%d, Flags=0x%02x, Keep-alive=%d", 
              protocol_level, connect_flags, keep_alive);
    
    // Extract client ID
    if (pos + 2 > packet_len) return -1;
    client_id_len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    
    if (pos + client_id_len > packet_len) return -1;
    if (client_id_len > 255) client_id_len = 255;  // Prevent buffer overflow
    
    memcpy(client_id, &buf[pos], client_id_len);
    client_id[client_id_len] = '\0';
    pos += client_id_len;
    
    log_debug("Client ID: %s", client_id);
    
    // For now, we accept all connections
    // In a production implementation, we would check username/password here if provided
    // and validate against the authentication module
    
    // Prepare CONNACK packet
    resp[0] = MQTT_CONNACK << 4;
    resp[1] = 2;  // Remaining length
    resp[2] = 0;  // No session present for now
    resp[3] = MQTT_CONNACK_ACCEPTED;  // Return code
    
    // Send CONNACK
    if (send(socket, resp, 4, 0) != 4) {
        log_error("Failed to send CONNACK packet");
        return -1;
    }
    
    log_info("Accepted CONNECT from %s", client_id);
    return 0;
}

// Process SUBSCRIBE packet and send SUBACK
static int process_subscribe_packet(int socket, uint8_t *buf, uint32_t packet_len) {
    uint16_t packet_id;
    uint16_t topic_len;
    char topic[256];
    uint8_t requested_qos;
    int pos = 0;
    
    uint8_t *resp;
    uint32_t resp_len;
    int topic_count = 0;
    
    // Skip fixed header
    pos = 2;  // Assuming fixed header is 2 bytes for simplicity
    
    // Extract packet ID
    if (pos + 2 > packet_len) return -1;
    packet_id = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    
    log_debug("SUBSCRIBE: Packet ID=%d", packet_id);
    
    // Count topics and prepare response
    int temp_pos = pos;
    while (temp_pos + 2 <= packet_len) {
        // Extract topic length
        topic_len = (buf[temp_pos] << 8) | buf[temp_pos + 1];
        temp_pos += 2;
        
        // Skip topic
        if (temp_pos + topic_len + 1 > packet_len) break;
        temp_pos += topic_len;
        
        // Skip QoS
        temp_pos++;
        
        topic_count++;
    }
    
    // Prepare SUBACK packet (fixed header + packet ID + one byte per topic)
    resp_len = 2 + 2 + topic_count;
    resp = (uint8_t *)malloc(resp_len);
    if (!resp) {
        log_error("Failed to allocate memory for SUBACK packet");
        return -1;
    }
    
    resp[0] = MQTT_SUBACK << 4;
    resp[1] = 2 + topic_count;  // Remaining length
    resp[2] = packet_id >> 8;   // Packet ID MSB
    resp[3] = packet_id & 0xFF; // Packet ID LSB
    
    // Process each topic
    int resp_pos = 4;
    while (pos + 2 <= packet_len) {
        // Extract topic length
        topic_len = (buf[pos] << 8) | buf[pos + 1];
        pos += 2;
        
        if (pos + topic_len + 1 > packet_len) break;
        
        if (topic_len > 255) topic_len = 255;  // Prevent buffer overflow
        memcpy(topic, &buf[pos], topic_len);
        topic[topic_len] = '\0';
        pos += topic_len;
        
        // Extract QoS
        requested_qos = buf[pos] & 0x03;  // QoS is bottom 2 bits
        pos++;
        
        log_debug("  Topic: %s, QoS: %d", topic, requested_qos);
        
        // Find the client session associated with this socket
        session_t *session = NULL;
        // Iterate through all sessions to find the one with this socket
        for (int i = 0; ; i++) {
            session_t *temp = session_find_by_index(i);
            if (!temp) break;
            
            if (session_get_socket(temp) == socket) {
                session = temp;
                log_debug("Found session for socket %d: client ID %s", 
                         socket, session_get_client_id(session));
                break;
            }
        }
        
        if (session) {
            // Add subscription to topic tree
            log_debug("Adding subscription for client %s to topic %s (QoS %d)", 
                     session_get_client_id(session), topic, requested_qos);
            
            if (topic_tree_subscribe(topic, session, requested_qos) == 0) {
                log_info("Subscription added for client %s to topic %s (QoS %d)", 
                        session_get_client_id(session), topic, requested_qos);
                resp[resp_pos++] = requested_qos;  // Grant requested QoS
            } else {
                log_error("Failed to add subscription for client %s to topic %s", 
                         session_get_client_id(session), topic);
                resp[resp_pos++] = 0x80;  // Subscription failure
            }
        } else {
            log_error("No session found for socket %d, cannot add subscription", socket);
            resp[resp_pos++] = 0x80;  // Subscription failure
        }
    }
    
    // Send SUBACK
    if (send(socket, resp, resp_len, 0) != resp_len) {
        log_error("Failed to send SUBACK packet");
        free(resp);
        return -1;
    }
    
    free(resp);
    log_info("Processed %d topic subscriptions", topic_count);
    return 0;
}

// Process PUBLISH packet
static int process_publish_packet(int socket, uint8_t *buf, uint32_t packet_len) {
    uint8_t flags = buf[0] & 0x0F;
    uint8_t dup = (flags & 0x08) >> 3;
    uint8_t qos = (flags & 0x06) >> 1;
    uint8_t retain = flags & 0x01;
    uint16_t topic_len;
    char topic[256];
    uint16_t packet_id = 0;
    const uint8_t *payload;
    uint32_t payload_len;
    int pos = 0;
    int remaining_len_bytes = 0;
    uint32_t remaining_length = 0;
    
    // Get variable header start position by calculating the length of the fixed header
    // Decode the remaining length field
    pos = 1;  // Skip the first byte of fixed header
    do {
        if (pos >= packet_len) {
            log_error("Packet too short when decoding remaining length");
            return -1;
        }
        remaining_len_bytes++;
        pos++;
    } while ((buf[pos-1] & 0x80) && remaining_len_bytes < 4);
    
    if (remaining_len_bytes == 4 && (buf[pos-1] & 0x80)) {
        log_error("Invalid remaining length encoding");
        return -1;
    }
    
    // Calculate remaining length
    for (int i = 0; i < remaining_len_bytes; i++) {
        remaining_length += (buf[i+1] & 0x7F) << (7 * i);
    }
    
    log_debug("PUBLISH packet: fixed header length=%d, remaining length=%d", 
              1 + remaining_len_bytes, remaining_length);
    
    // Check for valid packet length
    if (1 + remaining_len_bytes + remaining_length != packet_len) {
        log_error("PUBLISH packet length mismatch: expected %d, got %d", 
                  1 + remaining_len_bytes + remaining_length, packet_len);
    }
    
    // Position now at start of variable header
    pos = 1 + remaining_len_bytes;
    
    // Extract topic length
    if (pos + 2 > packet_len) {
        log_error("PUBLISH packet too short for topic length");
        return -1;
    }
    topic_len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    
    // Extract topic
    if (pos + topic_len > packet_len) {
        log_error("PUBLISH packet too short for topic");
        return -1;
    }
    if (topic_len > 255) {
        log_error("Topic too long");
        topic_len = 255;  // Prevent buffer overflow
    }
    
    memcpy(topic, &buf[pos], topic_len);
    topic[topic_len] = '\0';
    pos += topic_len;
    
    // Extract packet ID for QoS 1 or 2
    if (qos > 0) {
        if (pos + 2 > packet_len) {
            log_error("PUBLISH packet too short for packet ID");
            return -1;
        }
        packet_id = (buf[pos] << 8) | buf[pos + 1];
        pos += 2;
    }
    
    // The rest is payload
    payload = &buf[pos];
    payload_len = packet_len - pos;
    
    log_debug("PUBLISH: Topic=%s, QoS=%d, Retain=%d, ID=%d, Payload=%d bytes", 
              topic, qos, retain, packet_id, payload_len);
    
    // Log payload for debugging (if not too large)
    if (payload_len < 100) {
        char payload_str[101] = {0};
        memcpy(payload_str, payload, payload_len < 100 ? payload_len : 100);
        log_debug("Payload: %s", payload_str);
    }
    
    // Publish to topic tree to forward to all subscribers
    log_debug("Publishing message to topic tree: %s", topic);
    if (topic_tree_publish(topic, payload, payload_len, qos, retain) != 0) {
        log_error("Failed to publish message to topic tree");
    } else {
        log_debug("Message published to topic tree successfully");
    }
    
    // Send acknowledgement for QoS 1
    if (qos == 1) {
        uint8_t puback[4];
        puback[0] = MQTT_PUBACK << 4;
        puback[1] = 2;  // Remaining length
        puback[2] = packet_id >> 8;   // Packet ID MSB
        puback[3] = packet_id & 0xFF; // Packet ID LSB
        
        if (send(socket, puback, 4, 0) != 4) {
            log_error("Failed to send PUBACK packet");
            return -1;
        }
        log_debug("Sent PUBACK for packet ID %d", packet_id);
    }
    
    log_info("Received PUBLISH on %s (%d bytes)", topic, payload_len);
    return 0;
}

// Client handler thread function
static void *client_handler_func(void *arg) {
    client_conn_t *conn = (client_conn_t *)arg;
    int client_socket = conn->socket;
    struct sockaddr_in client_addr = conn->addr;
    uint8_t buf[4096];  // Larger buffer for MQTT packets
    uint32_t packet_len;
    int packet_type;
    int result;
    
    // Free the connection structure
    free(conn);
    
    // Handle client communications
    while (running) {
        // Read an MQTT packet
        packet_type = read_mqtt_packet(client_socket, buf, sizeof(buf), &packet_len);
        if (packet_type < 0) {
            // Client disconnected or error
            log_debug("Client connection closed or error reading packet");
            break;
        }
        
        // Process the packet based on type
        switch (packet_type) {
            case MQTT_CONNECT:
                log_debug("Received CONNECT packet");
                result = process_connect_packet(client_socket, buf, packet_len);
                if (result < 0) {
                    log_error("Failed to process CONNECT packet");
                    close(client_socket);
                    return NULL;
                }
                
                // Extract client ID from the CONNECT packet for session management
                if (packet_len > 14) { // Minimum packet length for a CONNECT
                    int pos = 0;
                    uint8_t first_byte = buf[0];
                    uint8_t flags = first_byte & 0x0F;
                    uint8_t remaining_len_bytes = 0;
                    uint32_t remaining_length = 0;
                    uint16_t protocol_name_len = 0;
                    uint8_t protocol_level = 0;
                    uint8_t connect_flags = 0;
                    uint16_t keep_alive = 0;
                    uint16_t client_id_len = 0;
                    char client_id[256] = {0};
                    session_t *session = NULL;
                    
                    // Skip fixed header
                    pos = 2;
                    
                    // Extract protocol name length
                    protocol_name_len = (buf[pos] << 8) | buf[pos + 1];
                    pos += 2;
                    pos += protocol_name_len; // Skip protocol name
                    
                    // Skip protocol level and connect flags
                    pos += 2;
                    
                    // Skip keep-alive
                    pos += 2;
                    
                    // Extract client ID length
                    if (pos + 2 <= packet_len) {
                        client_id_len = (buf[pos] << 8) | buf[pos + 1];
                        pos += 2;
                        
                        // Extract client ID
                        if (pos + client_id_len <= packet_len && client_id_len < 256) {
                            memcpy(client_id, &buf[pos], client_id_len);
                            client_id[client_id_len] = '\0';
                            
                            // Create or get existing session and set the socket
                            session = session_find(client_id);
                            if (!session) {
                                // Connect flags contain clean session bit at bit 1
                                connect_flags = buf[10]; // Connect flags are at fixed position
                                int clean_session = (connect_flags & 0x02) >> 1;
                                session = session_create(client_id, clean_session);
                            }
                            
                            if (session) {
                                session_set_socket(session, client_socket);
                                log_debug("Socket %d associated with session for client %s", 
                                         client_socket, client_id);
                            } else {
                                log_error("Failed to create or find session for client %s", client_id);
                            }
                        }
                    }
                }
                break;
                
            case MQTT_PUBLISH:
                log_debug("Received PUBLISH packet");
                result = process_publish_packet(client_socket, buf, packet_len);
                if (result < 0) {
                    log_error("Failed to process PUBLISH packet");
                } else {
                    // Extract publish details for topic tree distribution
                    if (packet_len > 5) { // Minimum packet length for a PUBLISH
                        int pos = 0;
                        uint8_t first_byte = buf[0];
                        uint8_t flags = first_byte & 0x0F;
                        uint8_t dup = (flags & 0x08) >> 3;
                        uint8_t qos = (flags & 0x06) >> 1;
                        uint8_t retain = flags & 0x01;
                        uint8_t remaining_len_bytes = 0;
                        uint32_t remaining_length = 0;
                        uint16_t topic_len = 0;
                        char topic[256] = {0};
                        uint16_t packet_id = 0;
                        const uint8_t *payload = NULL;
                        uint32_t payload_len = 0;
                        
                        // Skip fixed header - find variable header start
                        pos = 1; // Skip the first byte of fixed header
                        // Decode the remaining length field
                        do {
                            if (pos >= packet_len) {
                                log_error("Packet too short when decoding remaining length");
                                break;
                            }
                            remaining_len_bytes++;
                            pos++;
                        } while ((buf[pos-1] & 0x80) && remaining_len_bytes < 4);
                        
                        if (remaining_len_bytes == 4 && (buf[pos-1] & 0x80)) {
                            log_error("Invalid remaining length encoding");
                            break;
                        }
                        
                        // Calculate remaining length
                        for (int i = 0; i < remaining_len_bytes; i++) {
                            remaining_length += (buf[i+1] & 0x7F) << (7 * i);
                        }
                        
                        // Position now at start of variable header
                        pos = 1 + remaining_len_bytes;
                        
                        // Extract topic length
                        if (pos + 2 > packet_len) {
                            log_error("PUBLISH packet too short for topic length");
                            break;
                        }
                        topic_len = (buf[pos] << 8) | buf[pos + 1];
                        pos += 2;
                        
                        // Extract topic
                        if (pos + topic_len > packet_len) {
                            log_error("PUBLISH packet too short for topic");
                            break;
                        }
                        if (topic_len > 255) {
                            log_error("Topic too long");
                            break;
                        }
                        
                        memcpy(topic, &buf[pos], topic_len);
                        topic[topic_len] = '\0';
                        pos += topic_len;
                        
                        // Extract packet ID for QoS 1 or 2
                        if (qos > 0) {
                            if (pos + 2 > packet_len) {
                                log_error("PUBLISH packet too short for packet ID");
                                break;
                            }
                            packet_id = (buf[pos] << 8) | buf[pos + 1];
                            pos += 2;
                        }
                        
                        // The rest is payload
                        payload = &buf[pos];
                        payload_len = packet_len - pos;
                        
                        log_debug("Publishing message to topic tree: Topic=%s, QoS=%d, Retain=%d, Payload=%d bytes", 
                                 topic, qos, retain, payload_len);
                        
                        // Publish to topic tree
                        log_debug("About to publish message to topic tree: Topic='%s', QoS=%d, Retain=%d, Payload=%zu bytes", 
                                 topic, qos, retain, payload_len);
                        int pub_result = topic_tree_publish(topic, payload, payload_len, qos, retain);
                        if (pub_result != 0) {
                            log_error("Failed to publish message to topic tree: return code=%d", pub_result);
                        } else {
                            log_debug("Message published to topic tree successfully");
                            
                            // Dump first few subscribers from the topic tree for this topic
                            log_debug("Looking up subscribers for topic: %s", topic);
                            topic_tree_dump_subscribers(topic);
                        }
                    }
                }
                break;
                
            case MQTT_SUBSCRIBE:
                log_debug("Received SUBSCRIBE packet");
                result = process_subscribe_packet(client_socket, buf, packet_len);
                if (result < 0) {
                    log_error("Failed to process SUBSCRIBE packet");
                }
                
                // Extract subscription details and client ID
                if (packet_len > 6) { // Minimum packet length for a SUBSCRIBE
                    int pos = 0;
                    uint16_t packet_id = 0;
                    session_t *session = NULL;
                    
                    // Skip fixed header
                    pos = 2;
                    
                    // Extract packet ID
                    packet_id = (buf[pos] << 8) | buf[pos + 1];
                    pos += 2;
                    
                    // We need to find the client ID for this socket
                    // Iterate through all sessions to find the one with this socket
                    // In a real implementation, we would maintain a lookup table
                    for (int i = 0; ; i++) {
                        const char *client_id = NULL;
                        session = NULL;
                        
                        // Find all clients
                        session_t *temp = session_find_by_index(i);
                        if (!temp) break;
                        
                        // Check if this session has our socket
                        if (session_get_socket(temp) == client_socket) {
                            session = temp;
                            client_id = session_get_client_id(session);
                            log_debug("Found client ID %s for socket %d", client_id, client_socket);
                            break;
                        }
                    }
                    
                    if (session) {
                        // Process each topic in the SUBSCRIBE packet
                        while (pos + 2 <= packet_len) {
                            uint16_t topic_len = (buf[pos] << 8) | buf[pos + 1];
                            pos += 2;
                            
                            if (pos + topic_len + 1 > packet_len) break;
                            
                            char topic[256] = {0};
                            if (topic_len < 256) {
                                memcpy(topic, &buf[pos], topic_len);
                                topic[topic_len] = '\0';
                                pos += topic_len;
                                
                                // Get QoS
                                uint8_t requested_qos = buf[pos] & 0x03;
                                pos++;
                                
                                log_debug("Adding subscription for client ID %s: %s (QoS %d)",
                                         session_get_client_id(session), topic, requested_qos);
                                
                                // Add subscription to topic tree
                                if (topic_tree_subscribe(topic, session, requested_qos) != 0) {
                                    log_error("Failed to add subscription to topic tree");
                                } else {
                                    log_debug("Subscription added to topic tree successfully");
                                }
                                
                                // Add subscription to session
                                if (session_add_subscription(session, topic, requested_qos) != 0) {
                                    log_error("Failed to add subscription to session");
                                } else {
                                    log_debug("Subscription added to session successfully");
                                }
                            }
                        }
                    } else {
                        log_error("Could not find session for socket %d", client_socket);
                    }
                }
                break;
                
            case MQTT_PUBACK:
                log_debug("Received PUBACK packet");
                // Process acknowledgement for QoS 1
                if (packet_len >= 4) {
                    uint16_t packet_id = (buf[2] << 8) | buf[3];
                    log_debug("PUBACK for packet ID: %d", packet_id);
                }
                break;
                
            case MQTT_PUBREC:
                log_debug("Received PUBREC packet");
                // Process QoS 2 publish received
                if (packet_len >= 4) {
                    uint16_t packet_id = (buf[2] << 8) | buf[3];
                    log_debug("PUBREC for packet ID: %d", packet_id);
                    
                    // Send PUBREL response
                    uint8_t pubrel[4];
                    pubrel[0] = (MQTT_PUBREL << 4) | 0x02; // PUBREL has bit 1 set in flags
                    pubrel[1] = 2;  // Remaining length
                    pubrel[2] = buf[2];  // Packet ID MSB
                    pubrel[3] = buf[3];  // Packet ID LSB
                    
                    if (send(client_socket, pubrel, 4, 0) != 4) {
                        log_error("Failed to send PUBREL packet");
                    } else {
                        log_debug("Sent PUBREL for packet ID: %d", packet_id);
                    }
                }
                break;
                
            case MQTT_PUBREL:
                log_debug("Received PUBREL packet");
                // Process QoS 2 publish release
                if (packet_len >= 4) {
                    uint16_t packet_id = (buf[2] << 8) | buf[3];
                    log_debug("PUBREL for packet ID: %d", packet_id);
                    
                    // Send PUBCOMP response
                    uint8_t pubcomp[4];
                    pubcomp[0] = MQTT_PUBCOMP << 4;
                    pubcomp[1] = 2;  // Remaining length
                    pubcomp[2] = buf[2];  // Packet ID MSB
                    pubcomp[3] = buf[3];  // Packet ID LSB
                    
                    if (send(client_socket, pubcomp, 4, 0) != 4) {
                        log_error("Failed to send PUBCOMP packet");
                    } else {
                        log_debug("Sent PUBCOMP for packet ID: %d", packet_id);
                    }
                }
                break;
                
            case MQTT_PUBCOMP:
                log_debug("Received PUBCOMP packet");
                // Process QoS 2 publish complete
                if (packet_len >= 4) {
                    uint16_t packet_id = (buf[2] << 8) | buf[3];
                    log_debug("PUBCOMP for packet ID: %d", packet_id);
                }
                break;
                
            case MQTT_UNSUBSCRIBE:
                log_debug("Received UNSUBSCRIBE packet");
                // Process unsubscribe request
                if (packet_len >= 4) {
                    uint16_t packet_id = (buf[2] << 8) | buf[3];
                    log_debug("UNSUBSCRIBE for packet ID: %d", packet_id);
                    
                    // Send UNSUBACK response
                    uint8_t unsuback[4];
                    unsuback[0] = MQTT_UNSUBACK << 4;
                    unsuback[1] = 2;  // Remaining length
                    unsuback[2] = buf[2];  // Packet ID MSB
                    unsuback[3] = buf[3];  // Packet ID LSB
                    
                    if (send(client_socket, unsuback, 4, 0) != 4) {
                        log_error("Failed to send UNSUBACK packet");
                    } else {
                        log_debug("Sent UNSUBACK for packet ID: %d", packet_id);
                    }
                }
                break;
                
            case MQTT_PINGREQ:
                log_debug("Received PINGREQ packet");
                // Send PINGRESP packet
                buf[0] = MQTT_PINGRESP << 4;
                buf[1] = 0;  // Zero remaining length
                if (send(client_socket, buf, 2, 0) != 2) {
                    log_error("Failed to send PINGRESP packet");
                } else {
                    log_debug("Sent PINGRESP");
                }
                break;
                
            case MQTT_DISCONNECT:
                log_debug("Received DISCONNECT packet");
                // Client is disconnecting gracefully
                log_info("Client disconnected gracefully");
                close(client_socket);
                return NULL;
                
            default:
                log_debug("Received packet type: %d (unhandled)", packet_type);
                // Ignore unhandled packets
                break;
        }
    }
    
    // Clean up
    log_info("Client connection closed");
    close(client_socket);
    return NULL;
}

// Accept thread function
static void *accept_thread_func(void *arg) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_socket;
    pthread_t client_thread;
    client_conn_t *conn;
    
    log_info("Accept thread started");
    
    while (running) {
        // Accept a client connection
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (client_socket < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, check if we're still running
                continue;
            }
            
            log_error("Failed to accept client connection: %s", strerror(errno));
            continue;
        }
        
        log_info("Client connected from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Create connection data structure
        conn = (client_conn_t *)malloc(sizeof(client_conn_t));
        if (!conn) {
            log_error("Failed to allocate client connection data");
            close(client_socket);
            continue;
        }
        
        conn->socket = client_socket;
        conn->addr = client_addr;
        
        // Create a thread to handle this client
        if (pthread_create(&client_thread, NULL, client_handler_func, conn) != 0) {
            log_error("Failed to create client handler thread: %s", strerror(errno));
            free(conn);
            close(client_socket);
            continue;
        }
        
        // Detach the thread so it cleans up automatically when done
        pthread_detach(client_thread);
    }
    
    log_info("Accept thread stopped");
    return NULL;
}

int mqtt_broker_init(const mqtt_broker_config_t *config) {
    log_level_t log_level;
    
    if (!config) {
        fprintf(stderr, "No broker configuration provided\n");
        return -1;
    }
    
    // Initialize logger
    log_level = parse_log_level(config->log_level);
    if (log_init(log_level, NULL) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return -1;
    }
    
    log_info("MQTT Broker initializing");
    
    // Initialize topic tree
    if (topic_tree_init() != 0) {
        log_error("Failed to initialize topic tree");
        log_cleanup();
        return -1;
    }
    
    // Initialize session manager
    if (session_manager_init(config->max_connections) != 0) {
        log_error("Failed to initialize session manager");
        topic_tree_cleanup();
        log_cleanup();
        return -1;
    }
    
    // Initialize persistence
    if (persistence_init(config->persistence_dir) != 0) {
        log_error("Failed to initialize persistence");
        session_manager_cleanup();
        topic_tree_cleanup();
        log_cleanup();
        return -1;
    }
    
    // Initialize authentication
    if (auth_init(config->auth_file) != 0) {
        log_error("Failed to initialize authentication");
        persistence_cleanup();
        session_manager_cleanup();
        topic_tree_cleanup();
        log_cleanup();
        return -1;
    }
    
    // Initialize disconnect handler
    if (disconnect_handler_init(config->disconnect_handler_config) != 0) {
        log_error("Failed to initialize disconnect handler");
        auth_cleanup();
        persistence_cleanup();
        session_manager_cleanup();
        topic_tree_cleanup();
        log_cleanup();
        return -1;
    }
    
    log_info("MQTT Broker initialized");
    return 0;
}

int mqtt_broker_start(void) {
    struct sockaddr_in server_addr;
    int opt = 1;
    const broker_config_t *config;
    
    // Check if we're already running
    if (running) {
        log_error("MQTT Broker is already running");
        return -1;
    }
    
    // Get broker configuration
    config = config_get_broker();
    if (!config) {
        log_error("Failed to get broker configuration");
        return -1;
    }
    
    log_info("MQTT Broker starting on port %d", config->port);
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        log_error("Failed to create server socket: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error("Failed to set socket options: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config->port);
    
    // Bind the socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to bind server socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        log_error("Failed to listen on server socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    // Set the running flag
    running = 1;
    
    // Create the accept thread
    if (pthread_create(&accept_thread, NULL, accept_thread_func, NULL) != 0) {
        log_error("Failed to create accept thread: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        running = 0;
        return -1;
    }
    
    log_info("MQTT Broker started on port %d", config->port);
    return 0;
}

void mqtt_broker_stop(void) {
    // Check if we're running
    if (!running) {
        log_error("MQTT Broker is not running");
        return;
    }
    
    log_info("MQTT Broker stopping");
    
    // Clear the running flag
    running = 0;
    
    // Close the server socket
    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
    
    // Wait for the accept thread to finish
    pthread_join(accept_thread, NULL);
    
    log_info("MQTT Broker stopped");
}

void mqtt_broker_cleanup(void) {
    log_info("MQTT Broker cleaning up");
    
    // Stop the broker if it's running
    if (running) {
        mqtt_broker_stop();
    }
    
    // Clean up components
    disconnect_handler_cleanup();
    auth_cleanup();
    persistence_cleanup();
    session_manager_cleanup();
    topic_tree_cleanup();
    
    log_info("MQTT Broker cleaned up");
    log_cleanup();
}