/**
 * @file config.h
 * @brief Configuration utilities for MQTT broker
 */

#ifndef CONFIG_H
#define CONFIG_H

/**
 * Broker configuration structure
 */
typedef struct {
    int port;
    int max_connections;
    int max_message_size;
    char *persistence_dir;
    char *log_level;
    char *auth_file;
    char *disconnect_handler_config;
} broker_config_t;

/**
 * Initialize the configuration
 * @param config_file The path to the configuration file
 * @return 0 on success, non-zero on error
 */
int config_init(const char *config_file);

/**
 * Clean up the configuration
 */
void config_cleanup(void);

/**
 * Get the broker configuration
 * @return The broker configuration
 */
const broker_config_t *config_get_broker(void);

#endif /* CONFIG_H */