#ifndef MQTT_CLIENT_TEMPLATE_H
#define MQTT_CLIENT_TEMPLATE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "client_config.h"

/* MQTT QoS levels */
#define MQTT_QOS_0 0
#define MQTT_QOS_1 1
#define MQTT_QOS_2 2

/* Client state */
typedef enum {
    MQTT_CLIENT_STATE_DISCONNECTED,
    MQTT_CLIENT_STATE_CONNECTING,
    MQTT_CLIENT_STATE_CONNECTED,
    MQTT_CLIENT_STATE_DISCONNECTING,
    MQTT_CLIENT_STATE_RECONNECTING,
    MQTT_CLIENT_STATE_ERROR
} mqtt_client_state_t;

/* Message callback function type */
typedef void (*mqtt_message_callback_t)(const char *topic, const uint8_t *payload, 
                                       size_t payload_len, void *user_data);

/* Client structure */
typedef struct mqtt_client_template {
    /* Configuration */
    client_config_t config;
    char client_id[64];
    
    /* State */
    mqtt_client_state_t state;
    void *mqtt_client;  /* Opaque pointer to actual MQTT client implementation */
    
    /* Callback */
    mqtt_message_callback_t message_callback;
    void *user_data;
    
    /* Heartbeat */
    bool send_heartbeats;
    uint64_t last_heartbeat_time;
    pthread_t heartbeat_thread;
    bool stop_heartbeat_thread;
    
    /* Statistics */
    uint64_t messages_received;
    uint64_t messages_sent;
    uint64_t connection_attempts;
    uint64_t disconnections;
} mqtt_client_template_t;

/**
 * Initialize the MQTT client template with configuration from a file
 *
 * @param client Pointer to client structure to initialize
 * @param config_file Path to the client configuration file
 * @param client_id Unique identifier for this client
 * @return bool True on success, false on failure
 */
bool mqtt_client_init(mqtt_client_template_t *client, 
                     const char *config_file, 
                     const char *client_id);

/**
 * Initialize the MQTT client template with an already loaded configuration
 *
 * @param client Pointer to client structure to initialize
 * @param config Pointer to a loaded client configuration
 * @param client_id Unique identifier for this client
 * @return bool True on success, false on failure
 */
bool mqtt_client_init_with_config(mqtt_client_template_t *client,
                                 const client_config_t *config,
                                 const char *client_id);

/**
 * Add additional topics from a JSON configuration file
 *
 * @param client Pointer to initialized client
 * @param topics_file Path to the file containing additional topics
 * @return bool True on success, false on failure
 */
bool mqtt_client_add_topics(mqtt_client_template_t *client, const char *topics_file);

/**
 * Set the message callback function
 *
 * @param client Pointer to client structure
 * @param callback Function to call when a message is received
 * @param user_data User data to pass to callback function
 * @return bool True on success, false on failure
 */
bool mqtt_client_set_callback(mqtt_client_template_t *client,
                             mqtt_message_callback_t callback,
                             void *user_data);

/**
 * Connect to the MQTT broker
 *
 * @param client Pointer to client structure
 * @return bool True on success, false on failure
 */
bool mqtt_client_connect(mqtt_client_template_t *client);

/**
 * Disconnect from the MQTT broker
 *
 * @param client Pointer to client structure
 * @return bool True on success, false on failure
 */
bool mqtt_client_disconnect(mqtt_client_template_t *client);

/**
 * Subscribe to a topic
 *
 * @param client Pointer to client structure
 * @param topic Topic to subscribe to
 * @param qos QoS level for the subscription
 * @return bool True on success, false on failure
 */
bool mqtt_client_subscribe(mqtt_client_template_t *client, const char *topic, int qos);

/**
 * Subscribe to all configured subscription topics
 *
 * @param client Pointer to client structure
 * @param qos QoS level for the subscriptions
 * @return bool True on success, false on failure
 */
bool mqtt_client_subscribe_all(mqtt_client_template_t *client, int qos);

/**
 * Publish a message to a topic
 *
 * @param client Pointer to client structure
 * @param topic Topic to publish to
 * @param payload Message payload
 * @param payload_len Length of payload
 * @param qos QoS level
 * @param retain Whether to retain message
 * @return bool True on success, false on failure
 */
bool mqtt_client_publish(mqtt_client_template_t *client,
                        const char *topic,
                        const uint8_t *payload, size_t payload_len,
                        int qos, bool retain);

/**
 * Send a heartbeat message
 *
 * @param client Pointer to client structure
 * @param status Status message to include in heartbeat
 * @return bool True on success, false on failure
 */
bool mqtt_client_send_heartbeat(mqtt_client_template_t *client, const char *status);

/**
 * Enable automatic heartbeat sending
 *
 * @param client Pointer to client structure
 * @param enable Whether to enable heartbeats
 * @return bool True on success, false on failure
 */
bool mqtt_client_enable_heartbeats(mqtt_client_template_t *client, bool enable);

/**
 * Get the current state of the client
 *
 * @param client Pointer to client structure
 * @return mqtt_client_state_t Current state
 */
mqtt_client_state_t mqtt_client_get_state(mqtt_client_template_t *client);

/**
 * Free resources used by the client
 *
 * @param client Pointer to client structure
 */
void mqtt_client_cleanup(mqtt_client_template_t *client);

#endif /* MQTT_CLIENT_TEMPLATE_H */