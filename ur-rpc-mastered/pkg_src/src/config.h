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
    
    // Notification system
    bool notification_enabled;
    char notification_destination_client_id[MAX_USERNAME_LENGTH];
    char notification_topic[MAX_PATH_LENGTH];
    
    // Certificate generation system
    bool cert_generation_enabled;
    char cert_ca_cert_file[MAX_PATH_LENGTH];
    char cert_ca_key_file[MAX_PATH_LENGTH];
    char cert_output_directory[MAX_PATH_LENGTH];
} broker_config_t;

// JSON Config Loading Error Tracking
typedef enum {
    CONFIG_ERROR_NONE = 0,
    CONFIG_ERROR_FILE_NOT_FOUND,
    CONFIG_ERROR_FILE_PERMISSION,
    CONFIG_ERROR_FILE_SIZE_INVALID,
    CONFIG_ERROR_FILE_READ_FAILED,
    CONFIG_ERROR_MEMORY_ALLOCATION,
    CONFIG_ERROR_JSON_PARSE_FAILED,
    CONFIG_ERROR_JSON_SYNTAX_ERROR,
    CONFIG_ERROR_JSON_INVALID_STRUCTURE,
    CONFIG_ERROR_JSON_TYPE_MISMATCH,
    CONFIG_ERROR_VALIDATION_FAILED,
    CONFIG_ERROR_MISSING_REQUIRED_FIELD,
    CONFIG_ERROR_INVALID_FIELD_VALUE,
    CONFIG_ERROR_CERTIFICATE_FILE_MISSING,
    CONFIG_ERROR_NETWORK_INVALID_RANGE,
    CONFIG_ERROR_SSL_CONFIG_INCONSISTENT
} config_error_code_t;

typedef struct {
    config_error_code_t error_code;
    char error_message[512];
    char problematic_field[128];
    char problematic_value[256];
    char error_location[256];  // JSON path or line info
    char suggested_fix[512];
    bool is_recoverable;
    int line_number;  // Approximate line number for JSON syntax errors
} config_error_details_t;

// Function declarations for error tracking
void config_error_init(config_error_details_t *error);
void config_error_set(config_error_details_t *error, config_error_code_t code, 
                      const char *message, const char *field, const char *value,
                      const char *location, const char *fix, bool recoverable);
const char* config_error_code_to_string(config_error_code_t code);
void config_error_log(const config_error_details_t *error, const char *filename);
void config_error_log_detailed_analysis(const config_error_details_t *error, const char *json_content);

/**
 * Load configuration from JSON file with enhanced error tracking
 * @param config Pointer to configuration structure
 * @param filename Path to configuration file
 * @param error_details Optional pointer to receive detailed error information
 * @return 0 on success, -1 on failure
 */
int config_load_with_error_tracking(broker_config_t *config, const char *filename, config_error_details_t *error_details);

/**
 * Load configuration from JSON file (legacy interface)
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
