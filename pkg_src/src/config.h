#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_PATH_LENGTH 256
#define MAX_ADDRESS_LENGTH 64
#define MAX_USERNAME_LENGTH 64

typedef struct {
    // Network settings
    char bind_address[MAX_ADDRESS_LENGTH];
    uint16_t port;
    uint16_t ssl_port;
    uint32_t max_clients;
    uint32_t max_message_size;
    uint16_t keep_alive_interval;
    
    // SSL/TLS settings
    bool ssl_enabled;
    char ca_cert_file[MAX_PATH_LENGTH];
    char server_cert_file[MAX_PATH_LENGTH];
    char server_key_file[MAX_PATH_LENGTH];
    bool require_client_cert;
    
    // Authentication
    bool allow_anonymous;
    char auth_file[MAX_PATH_LENGTH];
    
    // Broker settings
    uint32_t max_inflight_messages;
    uint32_t max_queued_messages;
    uint32_t message_retry_interval;
    bool retain_available;
    bool wildcard_subscriptions;
    bool subscription_identifier_available;
    bool shared_subscriptions;
    
    // Persistence
    bool persistence_enabled;
    char persistence_location[MAX_PATH_LENGTH];
    uint32_t autosave_interval;
    
    // Logging
    char log_file[MAX_PATH_LENGTH];
    int log_level; // 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG
    bool log_to_console;
    
    // Memory management
    uint32_t memory_limit;
    uint32_t connection_timeout;
    uint32_t client_timeout;
    
    // Performance
    uint32_t max_connections_per_ip;
    uint32_t max_publish_rate;
    uint32_t max_subscribe_rate;
} broker_config_t;

/**
 * Load configuration from JSON file
 * @param config Pointer to configuration structure
 * @param filename Path to configuration file
 * @return 0 on success, -1 on error
 */
int config_load(broker_config_t *config, const char *filename);

/**
 * Save configuration to JSON file
 * @param config Pointer to configuration structure
 * @param filename Path to configuration file
 * @return 0 on success, -1 on error
 */
int config_save(const broker_config_t *config, const char *filename);

/**
 * Set default configuration values
 * @param config Pointer to configuration structure
 */
void config_set_defaults(broker_config_t *config);

/**
 * Validate configuration values
 * @param config Pointer to configuration structure
 * @return 0 if valid, -1 if invalid
 */
int config_validate(const broker_config_t *config);

/**
 * Cleanup configuration resources
 * @param config Pointer to configuration structure
 */
void config_cleanup(broker_config_t *config);

/**
 * Print configuration to stdout (for debugging)
 * @param config Pointer to configuration structure
 */
void config_print(const broker_config_t *config);

#endif /* CONFIG_H */
