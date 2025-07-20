#include "message_handler.h"
#include "mqtt_broker.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static int handle_mqtt_packet(mqtt_client_t *client, mqtt_broker_t *broker, 
                              const mqtt_fixed_header_t *header, const uint8_t *payload, uint32_t payload_len);

int message_handler_process_client(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) return -1;
    
    uint8_t buffer[MQTT_BUFFER_SIZE];
    ssize_t received = client_manager_recv(client, buffer, sizeof(buffer));
    
    if (received < 0) {
        LOG_WARNING("Failed to receive data from client fd=%d", client->socket_fd);
        return -1;
    }
    
    if (received == 0) {
        // No data available
        return 0;
    }
    
    // Add received data to client's read buffer
    if (client->read_buffer_len + received > sizeof(client->read_buffer)) {
        LOG_WARNING("Client fd=%d read buffer overflow", client->socket_fd);
        return -1;
    }
    
    memcpy(client->read_buffer + client->read_buffer_len, buffer, received);
    client->read_buffer_len += received;
    
    // Process complete MQTT packets
    while (client->read_buffer_len > 0) {
        mqtt_fixed_header_t header;
        uint32_t header_bytes;
        
        // Try to parse fixed header
        int result = mqtt_parse_fixed_header(client->read_buffer, client->read_buffer_len, 
                                           &header, &header_bytes);
        
        if (result == 1) {
            // Need more data for header
            break;
        }
        
        if (result < 0) {
            LOG_WARNING("Invalid MQTT header from client fd=%d", client->socket_fd);
            return -1;
        }
        
        uint32_t total_packet_len = header_bytes + header.remaining_length;
        
        if (client->read_buffer_len < total_packet_len) {
            // Need more data for complete packet
            break;
        }
        
        // Process the packet
        const uint8_t *payload = client->read_buffer + header_bytes;
        result = handle_mqtt_packet(client, broker, &header, payload, header.remaining_length);
        
        if (result < 0) {
            LOG_WARNING("Failed to handle MQTT packet from client fd=%d", client->socket_fd);
            return -1;
        }
        
        // Remove processed packet from buffer
        memmove(client->read_buffer, client->read_buffer + total_packet_len, 
                client->read_buffer_len - total_packet_len);
        client->read_buffer_len -= total_packet_len;
        
        client->messages_received++;
        broker->total_messages++;
    }
    
    return 0;
}

static int handle_mqtt_packet(mqtt_client_t *client, mqtt_broker_t *broker, 
                              const mqtt_fixed_header_t *header, const uint8_t *payload, uint32_t payload_len) {
    
    switch (header->msg_type) {
        case MQTT_CONNECT: {
            mqtt_connect_t connect;
            if (mqtt_parse_connect(payload, payload_len, &connect) != 0) {
                LOG_WARNING("Failed to parse CONNECT packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_connect(client, broker, &connect);
            mqtt_free_connect(&connect);
            return result;
        }
        
        case MQTT_PUBLISH: {
            mqtt_publish_t publish;
            if (mqtt_parse_publish(payload, payload_len, header, &publish) != 0) {
                LOG_WARNING("Failed to parse PUBLISH packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_publish(client, broker, &publish);
            mqtt_free_publish(&publish);
            return result;
        }
        
        case MQTT_SUBSCRIBE: {
            mqtt_subscribe_t subscribe;
            if (mqtt_parse_subscribe(payload, payload_len, &subscribe) != 0) {
                LOG_WARNING("Failed to parse SUBSCRIBE packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_subscribe(client, broker, &subscribe);
            mqtt_free_subscribe(&subscribe);
            return result;
        }
        
        case MQTT_UNSUBSCRIBE: {
            mqtt_unsubscribe_t unsubscribe;
            if (mqtt_parse_unsubscribe(payload, payload_len, &unsubscribe) != 0) {
                LOG_WARNING("Failed to parse UNSUBSCRIBE packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_unsubscribe(client, broker, &unsubscribe);
            mqtt_free_unsubscribe(&unsubscribe);
            return result;
        }
        
        case MQTT_PUBACK: {
            if (payload_len < 2) {
                LOG_WARNING("Invalid PUBACK packet length from client fd=%d", client->socket_fd);
                return -1;
            }
            
            uint16_t packet_id = ntohs(*(uint16_t*)payload);
            return message_handler_puback(client, broker, packet_id);
        }
        
        case MQTT_PINGREQ: {
            return message_handler_pingreq(client, broker);
        }
        
        case MQTT_DISCONNECT: {
            return message_handler_disconnect(client, broker);
        }
        
        default:
            LOG_WARNING("Unsupported MQTT message type %d from client fd=%d", 
                       header->msg_type, client->socket_fd);
            return -1;
    }
}

int message_handler_connect(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_connect_t *connect) {
    if (!client || !broker || !connect) return -1;
    
    mqtt_connack_code_t return_code = MQTT_CONNACK_ACCEPTED;
    bool session_present = false;
    
    // Validate protocol version
    if (connect->protocol_version != MQTT_PROTOCOL_VERSION) {
        return_code = MQTT_CONNACK_REFUSED_PROTOCOL_VERSION;
        LOG_WARNING("Unsupported protocol version %d from client fd=%d", 
                   connect->protocol_version, client->socket_fd);
    }
    
    // Validate client ID
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        if (!connect->client_id || strlen(connect->client_id) == 0) {
            if (!(connect->flags & 0x02)) { // Clean session not set
                return_code = MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED;
            } else {
                // Generate client ID
                snprintf(client->client_id, sizeof(client->client_id), "auto_%d_%lu", 
                        client->socket_fd, time(NULL));
            }
        } else if (strlen(connect->client_id) >= MAX_CLIENT_ID_LEN) {
            return_code = MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED;
        } else {
            strncpy(client->client_id, connect->client_id, sizeof(client->client_id) - 1);
        }
    }
    
    // Check for duplicate client ID
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        mqtt_client_t *existing = client_manager_get_client_by_id(&broker->client_manager, client->client_id);
        if (existing && existing != client) {
            LOG_INFO("Disconnecting existing client with same ID: %s", client->client_id);
            existing->state = MQTT_CLIENT_DISCONNECTED;
        }
    }
    
    // Authenticate client
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        if (!message_handler_authenticate(broker, connect->username, connect->password)) {
            return_code = broker->config.allow_anonymous ? 
                         MQTT_CONNACK_ACCEPTED : MQTT_CONNACK_REFUSED_NOT_AUTHORIZED;
        }
    }
    
    // Store connection details
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        client->keep_alive = connect->keep_alive;
        client->clean_session = (connect->flags & 0x02) != 0;
        
        // Store will message
        if (connect->flags & 0x04) { // Will flag
            client->will_flag = true;
            client->will_qos = (connect->flags >> 3) & 0x03;
            client->will_retain = (connect->flags & 0x20) != 0;
            
            if (connect->will_topic) {
                client->will_topic = strdup(connect->will_topic);
            }
            if (connect->will_message) {
                client->will_message = strdup(connect->will_message);
            }
        }
        
        // Store credentials
        if (connect->username) {
            client->username = strdup(connect->username);
        }
        if (connect->password) {
            client->password = strdup(connect->password);
        }
        
        client->state = MQTT_CLIENT_CONNECTED;
        LOG_INFO("Client connected: %s (fd=%d, keepalive=%d, clean=%s)", 
                client->client_id, client->socket_fd, client->keep_alive,
                client->clean_session ? "yes" : "no");
    }
    
    // Send CONNACK
    uint8_t connack_buffer[4];
    int connack_len = mqtt_serialize_connack(connack_buffer, sizeof(connack_buffer), 
                                           session_present, return_code);
    
    if (connack_len > 0) {
        message_handler_send_packet(client, connack_buffer, connack_len);
    }
    
    return return_code == MQTT_CONNACK_ACCEPTED ? 0 : -1;
}

int message_handler_publish(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_publish_t *publish) {
    if (!client || !broker || !publish) return -1;
    
    // Validate topic
    if (!mqtt_validate_topic(publish->topic)) {
        LOG_WARNING("Invalid topic from client %s: %s", client->client_id, publish->topic);
        return -1;
    }
    
    // Check authorization
    if (!message_handler_authorize_topic(broker, client, publish->topic, 1)) {
        LOG_WARNING("Client %s not authorized to publish to %s", client->client_id, publish->topic);
        return -1;
    }
    
    // Check rate limiting
    if (!client_manager_check_rate_limit(client, broker->config.max_publish_rate)) {
        return -1;
    }
    
    LOG_DEBUG("PUBLISH from %s: %s (QoS %d, retain=%s, len=%u)", 
             client->client_id, publish->topic, publish->qos, 
             publish->retain ? "yes" : "no", publish->payload_len);
    
    // Send PUBACK for QoS 1
    if (publish->qos == 1) {
        uint8_t puback_buffer[4];
        int puback_len = mqtt_serialize_puback(puback_buffer, sizeof(puback_buffer), publish->packet_id);
        if (puback_len > 0) {
            message_handler_send_packet(client, puback_buffer, puback_len);
        }
    }
    
    // Broadcast to subscribers
    int subscriber_count = message_handler_broadcast(broker, publish->topic, 
                                                   publish->payload, publish->payload_len,
                                                   publish->qos, publish->retain, client);
    
    LOG_DEBUG("Published to %d subscribers", subscriber_count);
    return 0;
}

int message_handler_subscribe(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_subscribe_t *subscribe) {
    if (!client || !broker || !subscribe) return -1;
    
    uint8_t *return_codes = malloc(subscribe->topic_count);
    if (!return_codes) {
        LOG_ERROR("Failed to allocate return codes");
        return -1;
    }
    
    for (uint16_t i = 0; i < subscribe->topic_count; i++) {
        const char *topic_filter = subscribe->topics[i];
        uint8_t qos = subscribe->qos_levels[i];
        
        // Validate topic filter
        if (!topic_filter || strlen(topic_filter) == 0) {
            return_codes[i] = 0x80; // Failure
            continue;
        }
        
        // Check authorization
        if (!message_handler_authorize_topic(broker, client, topic_filter, 0)) {
            LOG_WARNING("Client %s not authorized to subscribe to %s", client->client_id, topic_filter);
            return_codes[i] = 0x80; // Failure
            continue;
        }
        
        // Add subscription
        if (client_manager_add_subscription(client, topic_filter, qos) == 0) {
            return_codes[i] = qos; // Success
            
            // Send retained messages
            message_handler_send_retained(broker, client, topic_filter, qos);
            
            LOG_DEBUG("Client %s subscribed to %s (QoS %d)", client->client_id, topic_filter, qos);
        } else {
            return_codes[i] = 0x80; // Failure
        }
    }
    
    // Send SUBACK
    uint8_t suback_buffer[256];
    int suback_len = mqtt_serialize_suback(suback_buffer, sizeof(suback_buffer), 
                                         subscribe->packet_id, return_codes, subscribe->topic_count);
    
    if (suback_len > 0) {
        message_handler_send_packet(client, suback_buffer, suback_len);
    }
    
    free(return_codes);
    return 0;
}

int message_handler_unsubscribe(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_unsubscribe_t *unsubscribe) {
    if (!client || !broker || !unsubscribe) return -1;
    
    for (uint16_t i = 0; i < unsubscribe->topic_count; i++) {
        const char *topic_filter = unsubscribe->topics[i];
        
        if (client_manager_remove_subscription(client, topic_filter) == 0) {
            LOG_DEBUG("Client %s unsubscribed from %s", client->client_id, topic_filter);
        }
    }
    
    // Send UNSUBACK
    uint8_t unsuback_buffer[4];
    int unsuback_len = mqtt_serialize_unsuback(unsuback_buffer, sizeof(unsuback_buffer), 
                                             unsubscribe->packet_id);
    
    if (unsuback_len > 0) {
        message_handler_send_packet(client, unsuback_buffer, unsuback_len);
    }
    
    return 0;
}

int message_handler_puback(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id) {
    if (!client || !broker) return -1;
    
    // Remove pending message
    if (client_manager_remove_pending_message(client, packet_id, true) == 0) {
        LOG_DEBUG("Received PUBACK from client %s for packet %u", client->client_id, packet_id);
    }
    
    return 0;
}

int message_handler_pingreq(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) return -1;
    
    LOG_DEBUG("PING from client %s", client->client_id);
    
    // Create PINGRESP packet (fixed header: 0xD0, 0x00)
    uint8_t pingresp_buffer[2] = {0xD0, 0x00};
    
    // Send PINGRESP directly
    int result = message_handler_send_packet(client, pingresp_buffer, 2);
    if (result == 0) {
        LOG_DEBUG("PINGRESP sent to client %s", client->client_id);
    }
    
    return result;
}

int message_handler_disconnect(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) return -1;
    
    LOG_INFO("Client %s disconnected gracefully", client->client_id);
    
    // Clear will message on graceful disconnect
    client->will_flag = false;
    client->state = MQTT_CLIENT_DISCONNECTED;
    
    return 0;
}

int message_handler_broadcast(mqtt_broker_t *broker, const char *topic, 
                             const uint8_t *payload, uint32_t payload_len,
                             uint8_t qos, bool retain, mqtt_client_t *sender_client) {
    if (!broker || !topic) return 0;
    
    int subscriber_count = 0;
    mqtt_client_t *client = broker->client_manager.clients;
    
    while (client) {
        if (client->state == MQTT_CLIENT_CONNECTED && client != sender_client) {
            uint8_t client_qos;
            if (client_manager_is_subscribed(client, topic, &client_qos)) {
                // Use minimum QoS
                uint8_t effective_qos = (qos < client_qos) ? qos : client_qos;
                
                // Create PUBLISH packet
                mqtt_publish_t publish = {0};
                publish.topic = (char*)topic;
                publish.payload = (uint8_t*)payload;
                publish.payload_len = payload_len;
                publish.qos = effective_qos;
                publish.retain = retain;
                
                if (effective_qos > 0) {
                    publish.packet_id = client_manager_get_next_packet_id(client);
                }
                
                uint8_t publish_buffer[MQTT_BUFFER_SIZE];
                int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
                
                if (publish_len > 0) {
                    if (message_handler_send_packet(client, publish_buffer, publish_len) == 0) {
                        subscriber_count++;
                        
                        // Add to pending for QoS > 0
                        if (effective_qos > 0) {
                            client_manager_add_pending_message(client, publish.packet_id, 
                                                             publish_buffer, publish_len, effective_qos);
                        }
                    }
                }
            }
        }
        client = client->next;
    }
    
    return subscriber_count;
}

int message_handler_publish_will(mqtt_broker_t *broker, mqtt_client_t *client) {
    if (!broker || !client || !client->will_flag) return -1;
    
    LOG_INFO("Publishing will message for client %s: %s", client->client_id, client->will_topic);
    
    return message_handler_broadcast(broker, client->will_topic, 
                                   (uint8_t*)client->will_message, strlen(client->will_message),
                                   client->will_qos, client->will_retain, NULL);
}

int message_handler_send_packet(mqtt_client_t *client, const uint8_t *data, uint32_t length) {
    if (!client || !data || length == 0) return -1;
    
    ssize_t sent = client_manager_send(client, data, length);
    if (sent == length) {
        client->messages_sent++;
        return 0;
    }
    
    LOG_WARNING("Failed to send complete packet to client %s", client->client_id);
    return -1;
}

bool message_handler_authenticate(mqtt_broker_t *broker, const char *username, const char *password) {
    if (!broker) return false;
    
    // Allow anonymous if configured
    if (broker->config.allow_anonymous && (!username || strlen(username) == 0)) {
        return true;
    }
    
    // Simple authentication (in production, use proper authentication)
    if (username && password) {
        // TODO: Implement proper authentication from auth file
        return true;
    }
    
    return broker->config.allow_anonymous;
}



bool message_handler_authorize_topic(mqtt_broker_t *broker, mqtt_client_t *client, const char *topic, int action) {
    if (!broker || !client || !topic) return false;
    
    // Basic authorization - allow everything for now
    // TODO: Implement proper ACL from configuration
    (void)action; // Suppress unused parameter warning
    
    return true;
}

int message_handler_send_retained(mqtt_broker_t *broker, mqtt_client_t *client, const char *topic_filter, uint8_t qos) {
    if (!broker || !client || !topic_filter) return 0;
    
    // TODO: Implement retained message storage and retrieval
    // For now, return 0 (no retained messages)
    (void)qos; // Suppress unused parameter warning
    
    return 0;
}
