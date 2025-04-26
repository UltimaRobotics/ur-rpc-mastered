/**
 * @file mqtt_broker.h
 * @brief Main MQTT broker interface
 */

#ifndef MQTT_BROKER_H
#define MQTT_BROKER_H

/**
 * MQTT broker configuration structure
 */
typedef struct mqtt_broker_config {
    int port;
    int max_connections;
    int max_message_size;
    char *persistence_dir;
    char *log_level;
    char *auth_file;
    char *disconnect_handler_config;
} mqtt_broker_config_t;

/**
 * Initialize the MQTT broker
 * @param config The broker configuration
 * @return 0 on success, non-zero on error
 */
int mqtt_broker_init(const mqtt_broker_config_t *config);

/**
 * Start the MQTT broker
 * @return 0 on success, non-zero on error
 */
int mqtt_broker_start(void);

/**
 * Stop the MQTT broker
 */
void mqtt_broker_stop(void);

/**
 * Clean up the MQTT broker
 */
void mqtt_broker_cleanup(void);

#endif /* MQTT_BROKER_H */