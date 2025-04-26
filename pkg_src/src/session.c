/**
 * @file session.c
 * @brief Client session management for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include "session.h"
#include "logger.h"
#include "utils.h"

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

// Session subscription structure
typedef struct subscription {
    char *topic;
    int qos;
    struct subscription *next;
} subscription_t;

// Session structure
struct session {
    char *client_id;
    int clean_session;
    int socket;                  // Socket to communicate with the client
    subscription_t *subscriptions;
    struct session *next;
};

// Global session manager state
static session_t *sessions = NULL;
static int max_sessions_allowed = 0;
static int session_count = 0;
static int initialized = 0;

int session_manager_init(int max_sessions) {
    if (initialized) {
        return 0;
    }
    
    max_sessions_allowed = max_sessions;
    initialized = 1;
    
    log_info("Session manager initialized with max sessions: %d", max_sessions);
    return 0;
}

void session_manager_cleanup(void) {
    session_t *session, *next_session;
    
    if (!initialized) {
        return;
    }
    
    // Free all sessions
    session = sessions;
    while (session) {
        next_session = session->next;
        session_destroy(session);
        session = next_session;
    }
    
    sessions = NULL;
    session_count = 0;
    initialized = 0;
}

session_t *session_create(const char *client_id, int clean_session) {
    session_t *session, *prev = NULL, *current;
    
    if (!initialized || !client_id) {
        return NULL;
    }
    
    // Check if session already exists
    session = session_find(client_id);
    if (session) {
        // Clean up existing session
        subscription_t *sub, *next_sub;
        
        // Free all subscriptions
        sub = session->subscriptions;
        while (sub) {
            next_sub = sub->next;
            free(sub->topic);
            free(sub);
            sub = next_sub;
        }
        
        session->subscriptions = NULL;
        session->clean_session = clean_session;
        
        log_info("Session reused for client: %s", client_id);
        return session;
    }
    
    // Check if we've reached the maximum number of sessions
    if (session_count >= max_sessions_allowed && max_sessions_allowed > 0) {
        log_error("Maximum number of sessions reached: %d", max_sessions_allowed);
        return NULL;
    }
    
    // Create new session
    session = (session_t *)calloc(1, sizeof(session_t));
    if (!session) {
        log_error("Failed to allocate memory for session");
        return NULL;
    }
    
    session->client_id = utils_strdup(client_id);
    if (!session->client_id) {
        free(session);
        log_error("Failed to allocate memory for client ID");
        return NULL;
    }
    
    session->clean_session = clean_session;
    session->subscriptions = NULL;
    
    // Add to the session list (alphabetically sorted by client ID)
    if (!sessions || strcmp(sessions->client_id, client_id) > 0) {
        // Insert at the beginning
        session->next = sessions;
        sessions = session;
    } else {
        // Find the right position
        current = sessions;
        while (current && strcmp(current->client_id, client_id) <= 0) {
            prev = current;
            current = current->next;
        }
        
        // Insert after prev
        session->next = current;
        if (prev) {
            prev->next = session;
        }
    }
    
    session_count++;
    log_info("Session created for client: %s", client_id);
    
    return session;
}

session_t *session_find(const char *client_id) {
    session_t *session;
    
    if (!initialized || !client_id) {
        return NULL;
    }
    
    // Find the session
    for (session = sessions; session; session = session->next) {
        if (strcmp(session->client_id, client_id) == 0) {
            return session;
        }
    }
    
    return NULL;
}

session_t *session_find_by_index(int index) {
    session_t *session;
    int i = 0;
    
    if (!initialized || index < 0) {
        return NULL;
    }
    
    // Find the session at the given index
    for (session = sessions; session; session = session->next, i++) {
        if (i == index) {
            return session;
        }
    }
    
    return NULL;
}

void session_destroy(session_t *session) {
    session_t *prev, *current;
    subscription_t *sub, *next_sub;
    
    if (!initialized || !session) {
        return;
    }
    
    // Remove from the session list
    if (sessions == session) {
        sessions = session->next;
    } else {
        prev = NULL;
        current = sessions;
        
        while (current && current != session) {
            prev = current;
            current = current->next;
        }
        
        if (current && prev) {
            prev->next = current->next;
        }
    }
    
    // Free all subscriptions
    sub = session->subscriptions;
    while (sub) {
        next_sub = sub->next;
        free(sub->topic);
        free(sub);
        sub = next_sub;
    }
    
    // Free the session
    free(session->client_id);
    free(session);
    
    session_count--;
}

int session_add_subscription(session_t *session, const char *topic, int qos) {
    subscription_t *sub, *prev = NULL, *current;
    
    if (!initialized || !session || !topic) {
        return -1;
    }
    
    // Check if subscription already exists
    for (sub = session->subscriptions; sub; sub = sub->next) {
        if (strcmp(sub->topic, topic) == 0) {
            // Update QoS
            sub->qos = qos;
            return 0;
        }
    }
    
    // Create new subscription
    sub = (subscription_t *)calloc(1, sizeof(subscription_t));
    if (!sub) {
        log_error("Failed to allocate memory for subscription");
        return -1;
    }
    
    sub->topic = utils_strdup(topic);
    if (!sub->topic) {
        free(sub);
        log_error("Failed to allocate memory for topic");
        return -1;
    }
    
    sub->qos = qos;
    
    // Add to the subscription list (alphabetically sorted by topic)
    if (!session->subscriptions || strcmp(session->subscriptions->topic, topic) > 0) {
        // Insert at the beginning
        sub->next = session->subscriptions;
        session->subscriptions = sub;
    } else {
        // Find the right position
        current = session->subscriptions;
        while (current && strcmp(current->topic, topic) <= 0) {
            prev = current;
            current = current->next;
        }
        
        // Insert after prev
        sub->next = current;
        if (prev) {
            prev->next = sub;
        }
    }
    
    log_debug("Subscription added: %s (QoS %d)", topic, qos);
    return 0;
}

int session_remove_subscription(session_t *session, const char *topic) {
    subscription_t *sub, *prev = NULL;
    
    if (!initialized || !session || !topic) {
        return -1;
    }
    
    // Find the subscription
    for (sub = session->subscriptions; sub; prev = sub, sub = sub->next) {
        if (strcmp(sub->topic, topic) == 0) {
            // Remove from list
            if (prev) {
                prev->next = sub->next;
            } else {
                session->subscriptions = sub->next;
            }
            
            // Free the subscription
            free(sub->topic);
            free(sub);
            
            log_debug("Subscription removed: %s", topic);
            return 0;
        }
    }
    
    log_debug("Subscription not found: %s", topic);
    return -1;
}

int session_has_subscription(const session_t *session, const char *topic, int *qos) {
    subscription_t *sub;
    
    if (!initialized || !session || !topic) {
        return 0;
    }
    
    // Check all subscriptions
    for (sub = session->subscriptions; sub; sub = sub->next) {
        if (utils_topic_matches_subscription(topic, sub->topic)) {
            if (qos) {
                *qos = sub->qos;
            }
            return 1;
        }
    }
    
    return 0;
}

const char *session_get_client_id(const session_t *session) {
    if (!initialized || !session) {
        return NULL;
    }
    
    return session->client_id;
}

int session_get_clean_session(const session_t *session) {
    if (!initialized || !session) {
        return -1;
    }
    
    return session->clean_session;
}

int session_get_subscription_count(const session_t *session) {
    subscription_t *sub;
    int count = 0;
    
    if (!initialized || !session) {
        return -1;
    }
    
    // Count subscriptions
    for (sub = session->subscriptions; sub; sub = sub->next) {
        count++;
    }
    
    return count;
}

int session_get_subscription(const session_t *session, int index, const char **topic, int *qos) {
    subscription_t *sub;
    int i = 0;
    
    if (!initialized || !session || index < 0) {
        return -1;
    }
    
    // Find subscription at index
    for (sub = session->subscriptions; sub; sub = sub->next, i++) {
        if (i == index) {
            if (topic) {
                *topic = sub->topic;
            }
            
            if (qos) {
                *qos = sub->qos;
            }
            
            return 0;
        }
    }
    
    return -1;
}

int session_set_socket(session_t *session, int socket) {
    if (!initialized || !session) {
        return -1;
    }
    
    session->socket = socket;
    log_debug("Socket set for session %s: %d", session->client_id, socket);
    
    return 0;
}

int session_get_socket(const session_t *session) {
    if (!initialized || !session) {
        return -1;
    }
    
    return session->socket;
}

int session_forward_message(session_t *session, const char *topic, const void *payload, size_t payload_len, int qos) {
    uint8_t *packet;
    uint32_t packet_len;
    uint16_t topic_len;
    uint16_t packet_id = 0;
    uint32_t pos = 0;
    uint32_t remaining_length;
    int result;
    
    if (!initialized || !session || !topic || !payload) {
        log_error("Invalid parameters for session_forward_message");
        return -1;
    }
    
    log_debug("Preparing to forward message to %s on topic '%s' (payload: %zu bytes, QoS: %d)",
             session->client_id, topic, payload_len, qos);
    
    // Check if session has a socket
    if (session->socket <= 0) {
        log_warn("Session %s has no socket (socket=%d), cannot forward message", 
                session->client_id, session->socket);
        return -1;
    }
    
    topic_len = strlen(topic);
    log_debug("Topic length: %d", topic_len);
    
    // Calculate packet length
    // Fixed header (2 bytes) + Topic length field (2 bytes) + Topic + Payload
    // Plus 2 bytes for packet ID if QoS > 0
    remaining_length = 2 + topic_len + payload_len;
    if (qos > 0) {
        remaining_length += 2;
    }
    
    // Handle variable length encoding of remaining_length
    // For simplicity, we're assuming it fits in 1 byte (remaining_length < 128)
    if (remaining_length >= 128) {
        log_warn("Message size too large for simple encoding, needs variable length encoding");
        // We should implement proper variable length encoding here
    }
    
    packet_len = 1 + 1 + remaining_length; // First byte of fixed header + remaining length field (1 byte assuming small messages) + remaining length
    log_debug("Building PUBLISH packet of %u bytes", packet_len);
    
    // Allocate packet buffer
    packet = (uint8_t *)malloc(packet_len);
    if (!packet) {
        log_error("Failed to allocate memory for PUBLISH packet");
        return -1;
    }
    
    // Create PUBLISH packet
    // Fixed header
    packet[pos++] = (MQTT_PUBLISH << 4) | (qos << 1); // Set DUP=0, RETAIN=0, QoS as specified
    packet[pos++] = remaining_length; // Set remaining length (assuming it fits in 1 byte for simplicity)
    
    // Variable header
    // Topic
    packet[pos++] = topic_len >> 8;   // Topic length MSB
    packet[pos++] = topic_len & 0xFF; // Topic length LSB
    memcpy(&packet[pos], topic, topic_len);
    pos += topic_len;
    
    // Packet ID (only for QoS > 0)
    if (qos > 0) {
        // Generate packet ID
        static uint16_t next_packet_id = 1;
        packet_id = next_packet_id++;
        if (next_packet_id == 0) next_packet_id = 1;
        
        packet[pos++] = packet_id >> 8;   // Packet ID MSB
        packet[pos++] = packet_id & 0xFF; // Packet ID LSB
        log_debug("Using packet ID %u for QoS %d message", packet_id, qos);
    }
    
    // Payload
    memcpy(&packet[pos], payload, payload_len);
    pos += payload_len;
    
    if (pos != packet_len) {
        log_error("Packet construction error: expected length %u, got %u", packet_len, pos);
        free(packet);
        return -1;
    }
    
    // Send the packet
    log_debug("Sending %u byte PUBLISH packet to client socket %d", packet_len, session->socket);
    result = send(session->socket, packet, packet_len, 0);
    
    if (result < 0) {
        log_error("Socket error when sending to client %s: %s", 
                 session->client_id, strerror(errno));
        free(packet);
        return -1;
    }
    
    if ((uint32_t)result != packet_len) {
        log_error("Failed to send complete PUBLISH packet to client %s: sent %d of %u bytes", 
                 session->client_id, result, packet_len);
        free(packet);
        return -1;
    }
    
    free(packet);
    log_info("Message successfully forwarded to client %s on topic %s (%zu bytes)", 
             session->client_id, topic, payload_len);
    
    return 0;
}