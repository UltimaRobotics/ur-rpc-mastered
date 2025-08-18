#ifndef CLIENT_MANAGER_H
#define CLIENT_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include "ssl_wrapper.h"

#define MAX_CLIENT_ID_LEN 64
#define MAX_TOPIC_LEN 256
#define MAX_SUBSCRIPTIONS 32
#define MQTT_BUFFER_SIZE 8192

// Forward declarations
typedef struct mqtt_broker mqtt_broker_t;
typedef struct notification_manager notification_manager_t;

// MQTT subscription
typedef struct mqtt_subscription {
    char topic_filter[MAX_TOPIC_LEN];
    uint8_t qos;
    bool active;
    struct mqtt_subscription *next;
} mqtt_subscription_t;

// Pending message for QoS > 0
typedef struct pending_message {
    uint16_t packet_id;
    uint8_t *data;
    uint32_t data_len;
    time_t timestamp;
    uint8_t retry_count;
    uint8_t qos;
    struct pending_message *next;
} pending_message_t;

// MQTT client state
typedef enum {
    MQTT_CLIENT_CONNECTING = 0,
    MQTT_CLIENT_CONNECTED,
    MQTT_CLIENT_DISCONNECTING,
    MQTT_CLIENT_DISCONNECTED
} mqtt_client_state_t;

// MQTT client structure
typedef struct mqtt_client {
    int socket_fd;
    mqtt_client_state_t state;
    
    // SSL/TLS
    bool use_ssl;
    ssl_client_context_t *ssl_ctx;
    
    // Connection details
    char client_id[MAX_CLIENT_ID_LEN];
    char *username;
    char *password;
    uint16_t keep_alive;
    time_t last_activity;
    time_t connect_time;
    
    // Will message
    bool will_flag;
    char *will_topic;
    char *will_message;
    uint8_t will_qos;
    bool will_retain;
    
    // Session state
    bool clean_session;
    uint16_t next_packet_id;
    
    // Subscriptions
    mqtt_subscription_t *subscriptions;
    uint32_t subscription_count;
    
    // Message handling
    uint8_t read_buffer[MQTT_BUFFER_SIZE];
    uint32_t read_buffer_pos;
    uint32_t read_buffer_len;
    
    uint8_t write_buffer[MQTT_BUFFER_SIZE];
    uint32_t write_buffer_pos;
    uint32_t write_buffer_len;
    
    // Pending messages (QoS > 0)
    pending_message_t *pending_out; // Outgoing messages awaiting ACK
    pending_message_t *pending_in;  // Incoming messages awaiting PUBREL
    
    // Statistics
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    // Rate limiting
    time_t last_publish_time;
    uint32_t publish_count_minute;
    
    // Notification settings
    bool wants_notifications;
    char notification_topic[MAX_TOPIC_LEN];
    
    // Linked list
    struct mqtt_client *next;
} mqtt_client_t;

// Client manager
typedef struct client_manager {
    mqtt_client_t *clients;
    uint32_t max_clients;
    uint32_t active_count;
    uint32_t total_connections;
    time_t last_cleanup;
    
    // Notification manager reference
    notification_manager_t* notification_manager;
} client_manager_t;

/**
 * Initialize client manager
 * @param manager Pointer to client manager
 * @param max_clients Maximum number of concurrent clients
 * @return 0 on success, -1 on error
 */
int client_manager_init(client_manager_t *manager, uint32_t max_clients);

/**
 * Set notification manager reference
 * @param manager Pointer to client manager
 * @param notification_manager Pointer to notification manager
 */
void client_manager_set_notification_manager(client_manager_t* manager, 
                                            notification_manager_t* notification_manager);

/**
 * Cleanup client manager
 * @param manager Pointer to client manager
 */
void client_manager_cleanup(client_manager_t *manager);

/**
 * Create new client
 * @param manager Pointer to client manager
 * @param socket_fd Client socket file descriptor
 * @param use_ssl Whether to use SSL for this client
 * @return Pointer to client structure, NULL on error
 */
mqtt_client_t* client_manager_create_client(client_manager_t *manager, int socket_fd, bool use_ssl);

/**
 * Remove client
 * @param manager Pointer to client manager
 * @param socket_fd Client socket file descriptor
 */
void client_manager_remove_client(client_manager_t *manager, int socket_fd);

/**
 * Get client by socket file descriptor
 * @param manager Pointer to client manager
 * @param socket_fd Client socket file descriptor
 * @return Pointer to client structure, NULL if not found
 */
mqtt_client_t* client_manager_get_client(client_manager_t *manager, int socket_fd);

/**
 * Get client by client ID
 * @param manager Pointer to client manager
 * @param client_id Client identifier
 * @return Pointer to client structure, NULL if not found
 */
mqtt_client_t* client_manager_get_client_by_id(client_manager_t *manager, const char *client_id);

/**
 * Handle client connection (with notification support)
 * @param manager Pointer to client manager
 * @param client Pointer to client structure
 * @param client_id Client identifier
 * @return 0 on success, -1 on error
 */
int client_manager_handle_connect(client_manager_t* manager, mqtt_client_t* client, 
                                 const char* client_id);

/**
 * Handle client disconnection (with notification support)
 * @param manager Pointer to client manager
 * @param client Pointer to client structure
 * @return 0 on success, -1 on error
 */
int client_manager_handle_disconnect(client_manager_t* manager, mqtt_client_t* client);

/**
 * Enable notifications for client
 * @param client Pointer to client structure
 * @param notification_topic Topic to receive notifications on (NULL for default)
 * @return 0 on success, -1 on error
 */
int client_manager_enable_notifications(mqtt_client_t* client, const char* notification_topic);

/**
 * Disable notifications for client
 * @param client Pointer to client structure
 * @return 0 on success, -1 on error
 */
int client_manager_disable_notifications(mqtt_client_t* client);

/**
 * Add subscription for client
 * @param client Pointer to client structure
 * @param topic_filter Topic filter (may contain wildcards)
 * @param qos Quality of Service level
 * @return 0 on success, -1 on error
 */
int client_manager_add_subscription(mqtt_client_t *client, const char *topic_filter, uint8_t qos);

/**
 * Remove subscription for client
 * @param client Pointer to client structure
 * @param topic_filter Topic filter
 * @return 0 on success, -1 on error
 */
int client_manager_remove_subscription(mqtt_client_t *client, const char *topic_filter);

/**
 * Check if client is subscribed to topic
 * @param client Pointer to client structure
 * @param topic Topic name
 * @param qos Pointer to store QoS level
 * @return true if subscribed, false otherwise
 */
bool client_manager_is_subscribed(mqtt_client_t *client, const char *topic, uint8_t *qos);

/**
 * Get next packet ID for client
 * @param client Pointer to client structure
 * @return Next packet ID
 */
uint16_t client_manager_get_next_packet_id(mqtt_client_t *client);

/**
 * Add pending outgoing message
 * @param client Pointer to client structure
 * @param packet_id Packet identifier
 * @param data Message data
 * @param data_len Data length
 * @param qos Quality of Service level
 * @return 0 on success, -1 on error
 */
int client_manager_add_pending_message(mqtt_client_t *client, uint16_t packet_id, 
                                      const uint8_t *data, uint32_t data_len, uint8_t qos);

/**
 * Remove pending message
 * @param client Pointer to client structure
 * @param packet_id Packet identifier
 * @param outgoing True for outgoing messages, false for incoming
 * @return 0 on success, -1 on error
 */
int client_manager_remove_pending_message(mqtt_client_t *client, uint16_t packet_id, bool outgoing);

/**
 * Get pending message
 * @param client Pointer to client structure
 * @param packet_id Packet identifier
 * @param outgoing True for outgoing messages, false for incoming
 * @return Pointer to pending message, NULL if not found
 */
pending_message_t* client_manager_get_pending_message(mqtt_client_t *client, uint16_t packet_id, bool outgoing);

/**
 * Update client activity timestamp
 * @param client Pointer to client structure
 */
void client_manager_update_activity(mqtt_client_t *client);

/**
 * Check if client has exceeded keep-alive timeout
 * @param client Pointer to client structure
 * @return true if timed out, false otherwise
 */
bool client_manager_is_keepalive_expired(mqtt_client_t *client);

/**
 * Check rate limits for client
 * @param client Pointer to client structure
 * @param max_rate Maximum publish rate per minute
 * @return true if within limits, false if exceeded
 */
bool client_manager_check_rate_limit(mqtt_client_t *client, uint32_t max_rate);

/**
 * Cleanup disconnected clients
 * @param manager Pointer to client manager
 */
void client_manager_cleanup_disconnected(client_manager_t *manager);

/**
 * Get client statistics
 * @param client Pointer to client structure
 * @param uptime_seconds Pointer to store connection uptime
 * @param messages_sent Pointer to store sent message count
 * @param messages_received Pointer to store received message count
 * @param bytes_sent Pointer to store sent byte count
 * @param bytes_received Pointer to store received byte count
 */
void client_manager_get_stats(mqtt_client_t *client, uint64_t *uptime_seconds,
                             uint64_t *messages_sent, uint64_t *messages_received,
                             uint64_t *bytes_sent, uint64_t *bytes_received);

/**
 * Send data to client (handles both SSL and non-SSL)
 * @param client Pointer to client structure
 * @param data Data buffer
 * @param length Data length
 * @return Number of bytes sent, -1 on error
 */
ssize_t client_manager_send(mqtt_client_t *client, const void *data, size_t length);

/**
 * Receive data from client (handles both SSL and non-SSL)
 * @param client Pointer to client structure
 * @param buffer Data buffer
 * @param length Buffer size
 * @return Number of bytes received, -1 on error, 0 if would block
 */
ssize_t client_manager_recv(mqtt_client_t *client, void *buffer, size_t length);

#endif /* CLIENT_MANAGER_H */
