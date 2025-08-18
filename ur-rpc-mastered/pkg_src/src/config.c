#include "config.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

void config_set_defaults(broker_config_t *config) {
    memset(config, 0, sizeof(broker_config_t));
    
    // Network settings
    strncpy(config->bind_address, "0.0.0.0", sizeof(config->bind_address) - 1);
    config->port = 1883;
    config->ssl_port = 8883;
    config->max_clients = 100;
    config->max_message_size = 1024 * 1024; // 1MB
    config->keep_alive_interval = 60;
    
    // SSL/TLS settings
    config->ssl_enabled = false;
    strncpy(config->ca_cert_file, "certs/ca.crt", sizeof(config->ca_cert_file) - 1);
    strncpy(config->server_cert_file, "certs/server.crt", sizeof(config->server_cert_file) - 1);
    strncpy(config->server_key_file, "certs/server.key", sizeof(config->server_key_file) - 1);
    config->require_client_cert = false;
    
    // Authentication
    config->allow_anonymous = true;
    
    // Broker settings
    config->max_inflight_messages = 20;
    config->max_queued_messages = 100;
    config->message_retry_interval = 5;
    config->retain_available = true;
    config->wildcard_subscriptions = true;
    config->subscription_identifier_available = false;
    config->shared_subscriptions = false;
    
    // Persistence
    config->persistence_enabled = false;
    strncpy(config->persistence_location, "/tmp/mqtt_broker", sizeof(config->persistence_location) - 1);
    config->autosave_interval = 300; // 5 minutes
    
    // Logging
    config->log_level = 2; // INFO
    config->log_to_console = true;
    
    // Memory management
    config->memory_limit = 512 * 1024; // 512KB
    config->connection_timeout = 30;
    config->client_timeout = 120;
    
    // Performance
    config->max_connections_per_ip = 10;
    config->max_publish_rate = 100;
    config->max_subscribe_rate = 50;
    
    // Notification system
    config->notification_enabled = false;
    memset(config->notification_destination_client_id, 0, sizeof(config->notification_destination_client_id));
    strncpy(config->notification_topic, "broker/notifications", sizeof(config->notification_topic) - 1);
    
    // Certificate generation system
    config->cert_generation_enabled = true;
    strncpy(config->cert_ca_cert_file, "certs/ca.crt", sizeof(config->cert_ca_cert_file) - 1);
    strncpy(config->cert_ca_key_file, "certs/ca.key", sizeof(config->cert_ca_key_file) - 1);
    strncpy(config->cert_output_directory, "certs/generated", sizeof(config->cert_output_directory) - 1);
}

// JSON Config Loading Error Tracking Implementation

void config_error_init(config_error_details_t *error) {
    if (!error) return;
    
    memset(error, 0, sizeof(config_error_details_t));
    error->error_code = CONFIG_ERROR_NONE;
    error->is_recoverable = true;
    error->line_number = -1;
}

void config_error_set(config_error_details_t *error, config_error_code_t code, 
                      const char *message, const char *field, const char *value,
                      const char *location, const char *fix, bool recoverable) {
    if (!error) return;
    
    error->error_code = code;
    error->is_recoverable = recoverable;
    
    if (message) {
        strncpy(error->error_message, message, sizeof(error->error_message) - 1);
        error->error_message[sizeof(error->error_message) - 1] = '\0';
    }
    
    if (field) {
        strncpy(error->problematic_field, field, sizeof(error->problematic_field) - 1);
        error->problematic_field[sizeof(error->problematic_field) - 1] = '\0';
    }
    
    if (value) {
        strncpy(error->problematic_value, value, sizeof(error->problematic_value) - 1);
        error->problematic_value[sizeof(error->problematic_value) - 1] = '\0';
    }
    
    if (location) {
        strncpy(error->error_location, location, sizeof(error->error_location) - 1);
        error->error_location[sizeof(error->error_location) - 1] = '\0';
    }
    
    if (fix) {
        strncpy(error->suggested_fix, fix, sizeof(error->suggested_fix) - 1);
        error->suggested_fix[sizeof(error->suggested_fix) - 1] = '\0';
    }
}

const char* config_error_code_to_string(config_error_code_t code) {
    switch (code) {
        case CONFIG_ERROR_NONE: return "No Error";
        case CONFIG_ERROR_FILE_NOT_FOUND: return "File Not Found";
        case CONFIG_ERROR_FILE_PERMISSION: return "File Permission Denied";
        case CONFIG_ERROR_FILE_SIZE_INVALID: return "File Size Invalid";
        case CONFIG_ERROR_FILE_READ_FAILED: return "File Read Failed";
        case CONFIG_ERROR_MEMORY_ALLOCATION: return "Memory Allocation Failed";
        case CONFIG_ERROR_JSON_PARSE_FAILED: return "JSON Parse Failed";
        case CONFIG_ERROR_JSON_SYNTAX_ERROR: return "JSON Syntax Error";
        case CONFIG_ERROR_JSON_INVALID_STRUCTURE: return "JSON Invalid Structure";
        case CONFIG_ERROR_JSON_TYPE_MISMATCH: return "JSON Type Mismatch";
        case CONFIG_ERROR_VALIDATION_FAILED: return "Validation Failed";
        case CONFIG_ERROR_MISSING_REQUIRED_FIELD: return "Missing Required Field";
        case CONFIG_ERROR_INVALID_FIELD_VALUE: return "Invalid Field Value";
        case CONFIG_ERROR_CERTIFICATE_FILE_MISSING: return "Certificate File Missing";
        case CONFIG_ERROR_NETWORK_INVALID_RANGE: return "Network Invalid Range";
        case CONFIG_ERROR_SSL_CONFIG_INCONSISTENT: return "SSL Config Inconsistent";
        default: return "Unknown Error";
    }
}

void config_error_log(const config_error_details_t *error, const char *filename) {
    if (!error || error->error_code == CONFIG_ERROR_NONE) return;
    
    LOG_ERROR("===============================================");
    LOG_ERROR("JSON CONFIG LOADING FAILURE ANALYSIS");
    LOG_ERROR("===============================================");
    LOG_ERROR("Configuration File: %s", filename ? filename : "unknown");
    LOG_ERROR("Error Code: %s (%d)", config_error_code_to_string(error->error_code), error->error_code);
    LOG_ERROR("Error Message: %s", error->error_message);
    LOG_ERROR("Recoverable: %s", error->is_recoverable ? "Yes" : "No");
    
    if (strlen(error->problematic_field) > 0) {
        LOG_ERROR("Problematic Field: %s", error->problematic_field);
    }
    
    if (strlen(error->problematic_value) > 0) {
        LOG_ERROR("Problematic Value: %s", error->problematic_value);
    }
    
    if (strlen(error->error_location) > 0) {
        LOG_ERROR("Error Location: %s", error->error_location);
    }
    
    if (error->line_number > 0) {
        LOG_ERROR("Approximate Line Number: %d", error->line_number);
    }
    
    if (strlen(error->suggested_fix) > 0) {
        LOG_ERROR("Suggested Fix: %s", error->suggested_fix);
    }
    
    LOG_ERROR("===============================================");
}

static int config_estimate_line_number(const char *json_content, const char *error_ptr) {
    if (!json_content || !error_ptr || error_ptr < json_content) {
        return -1;
    }
    
    int line_count = 1;
    const char *current = json_content;
    
    while (current < error_ptr && *current) {
        if (*current == '\n') {
            line_count++;
        }
        current++;
    }
    
    return line_count;
}

void config_error_log_detailed_analysis(const config_error_details_t *error, const char *json_content) {
    if (!error || error->error_code == CONFIG_ERROR_NONE || !json_content) return;
    
    LOG_ERROR("===============================================");
    LOG_ERROR("DETAILED JSON ANALYSIS");
    LOG_ERROR("===============================================");
    
    // Analyze JSON structure
    size_t json_length = strlen(json_content);
    LOG_ERROR("JSON Content Length: %zu bytes", json_length);
    
    // Count braces and brackets for structure analysis
    int open_braces = 0, close_braces = 0;
    int open_brackets = 0, close_brackets = 0;
    int quotes = 0;
    bool in_string = false;
    
    for (size_t i = 0; i < json_length; i++) {
        char c = json_content[i];
        
        if (c == '"' && (i == 0 || json_content[i-1] != '\\')) {
            quotes++;
            in_string = !in_string;
        } else if (!in_string) {
            switch (c) {
                case '{': open_braces++; break;
                case '}': close_braces++; break;
                case '[': open_brackets++; break;
                case ']': close_brackets++; break;
            }
        }
    }
    
    LOG_ERROR("Structure Analysis:");
    LOG_ERROR("  Open Braces: %d, Close Braces: %d", open_braces, close_braces);
    LOG_ERROR("  Open Brackets: %d, Close Brackets: %d", open_brackets, close_brackets);
    LOG_ERROR("  Quote Count: %d (should be even)", quotes);
    
    if (open_braces != close_braces) {
        LOG_ERROR("  ⚠️  ISSUE: Unmatched braces detected!");
    }
    if (open_brackets != close_brackets) {
        LOG_ERROR("  ⚠️  ISSUE: Unmatched brackets detected!");
    }
    if (quotes % 2 != 0) {
        LOG_ERROR("  ⚠️  ISSUE: Unmatched quotes detected!");
    }
    
    // Show context around error if available
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr && error_ptr >= json_content && error_ptr < json_content + json_length) {
        int line_num = config_estimate_line_number(json_content, error_ptr);
        LOG_ERROR("Error near line %d:", line_num);
        
        // Show context (50 characters before and after)
        size_t error_pos = error_ptr - json_content;
        size_t start = (error_pos > 50) ? error_pos - 50 : 0;
        size_t end = (error_pos + 50 < json_length) ? error_pos + 50 : json_length;
        
        char context[102];
        strncpy(context, json_content + start, end - start);
        context[end - start] = '\0';
        
        LOG_ERROR("Context: ...%s...", context);
        LOG_ERROR("Error position marked by ^");
        
        // Print pointer position
        char pointer[102];
        memset(pointer, ' ', sizeof(pointer) - 1);
        pointer[error_pos - start + 3] = '^';  // +3 for "..."
        pointer[error_pos - start + 4] = '\0';
        LOG_ERROR("         %s", pointer);
    }
    
    LOG_ERROR("===============================================");
}

static int config_parse_string(cJSON *json, const char *key, char *dest, size_t dest_size) {
    cJSON *item = cJSON_GetObjectItem(json, key);
    if (item && cJSON_IsString(item)) {
        strncpy(dest, cJSON_GetStringValue(item), dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 0;
    }
    return -1;
}

static int config_parse_uint32(cJSON *json, const char *key, uint32_t *dest) {
    cJSON *item = cJSON_GetObjectItem(json, key);
    if (item && cJSON_IsNumber(item)) {
        double value = cJSON_GetNumberValue(item);
        if (value >= 0 && value <= UINT32_MAX) {
            *dest = (uint32_t)value;
            return 0;
        }
    }
    return -1;
}

static int config_parse_uint16(cJSON *json, const char *key, uint16_t *dest) {
    cJSON *item = cJSON_GetObjectItem(json, key);
    if (item && cJSON_IsNumber(item)) {
        double value = cJSON_GetNumberValue(item);
        if (value >= 0 && value <= UINT16_MAX) {
            *dest = (uint16_t)value;
            return 0;
        }
    }
    return -1;
}

static int config_parse_bool(cJSON *json, const char *key, bool *dest) {
    cJSON *item = cJSON_GetObjectItem(json, key);
    if (item && cJSON_IsBool(item)) {
        *dest = cJSON_IsTrue(item);
        return 0;
    }
    return -1;
}

static int config_parse_int(cJSON *json, const char *key, int *dest) {
    cJSON *item = cJSON_GetObjectItem(json, key);
    if (item && cJSON_IsNumber(item)) {
        *dest = (int)cJSON_GetNumberValue(item);
        return 0;
    }
    return -1;
}

// Enhanced config loading with comprehensive error tracking
int config_load_with_error_tracking(broker_config_t *config, const char *filename, config_error_details_t *error_details) {
    config_error_details_t local_error;
    config_error_details_t *error = error_details ? error_details : &local_error;
    
    // Initialize error tracking
    config_error_init(error);
    
    if (!config || !filename) {
        config_error_set(error, CONFIG_ERROR_INVALID_FIELD_VALUE, 
                        "Invalid parameters provided to config loader",
                        "config/filename", "NULL", "function_parameters",
                        "Ensure both config pointer and filename are valid", false);
        config_error_log(error, filename);
        LOG_ERROR("Invalid parameters");
        return -1;
    }
    
    // Set defaults first
    config_set_defaults(config);
    
    // Check file existence and permissions
    struct stat file_stat;
    if (stat(filename, &file_stat) != 0) {
        if (errno == ENOENT) {
            config_error_set(error, CONFIG_ERROR_FILE_NOT_FOUND,
                            "Configuration file does not exist",
                            "file_path", filename, "filesystem",
                            "Create the configuration file or check the path", true);
            config_error_log(error, filename);
            LOG_WARNING("Configuration file %s not found, using defaults", filename);
            return 0; // Not an error, just use defaults
        } else if (errno == EACCES) {
            config_error_set(error, CONFIG_ERROR_FILE_PERMISSION,
                            "Permission denied when accessing configuration file",
                            "file_path", filename, "filesystem",
                            "Check file permissions and user access rights", false);
            config_error_log(error, filename);
            LOG_ERROR("Permission denied for configuration file %s", filename);
            return -1;
        }
    }
    
    // Check file size
    long file_size = file_stat.st_size;
    if (file_size <= 0) {
        config_error_set(error, CONFIG_ERROR_FILE_SIZE_INVALID,
                        "Configuration file is empty",
                        "file_size", "0", "filesystem",
                        "Add valid JSON content to the configuration file", true);
        config_error_log(error, filename);
        LOG_ERROR("Configuration file %s is empty", filename);
        return -1;
    }
    
    if (file_size > 1024 * 1024) { // Max 1MB config file
        char size_str[32];
        snprintf(size_str, sizeof(size_str), "%ld", file_size);
        config_error_set(error, CONFIG_ERROR_FILE_SIZE_INVALID,
                        "Configuration file is too large (max 1MB)",
                        "file_size", size_str, "filesystem",
                        "Reduce configuration file size or split into multiple files", false);
        config_error_log(error, filename);
        LOG_ERROR("Configuration file %s is too large: %ld bytes", filename, file_size);
        return -1;
    }
    
    // Open and read file
    FILE *file = fopen(filename, "r");
    if (!file) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to open configuration file: %s", strerror(errno));
        config_error_set(error, CONFIG_ERROR_FILE_READ_FAILED,
                        error_msg, "file_path", filename, "filesystem",
                        "Check file permissions and system resources", false);
        config_error_log(error, filename);
        LOG_ERROR("Failed to open configuration file %s: %s", filename, strerror(errno));
        return -1;
    }
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        config_error_set(error, CONFIG_ERROR_MEMORY_ALLOCATION,
                        "Failed to allocate memory for configuration parsing",
                        "memory_size", "file_size + 1", "system_memory",
                        "Increase available memory or reduce file size", false);
        config_error_log(error, filename);
        LOG_ERROR("Failed to allocate memory for configuration");
        return -1;
    }
    
    size_t bytes_read = fread(json_string, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        char read_info[64];
        snprintf(read_info, sizeof(read_info), "%zu/%ld", bytes_read, file_size);
        config_error_set(error, CONFIG_ERROR_FILE_READ_FAILED,
                        "Failed to read complete configuration file",
                        "bytes_read", read_info, "file_io",
                        "Check file integrity and disk space", false);
        config_error_log(error, filename);
        LOG_ERROR("Failed to read configuration file: %zu/%ld bytes", bytes_read, file_size);
        free(json_string);
        return -1;
    }
    
    json_string[file_size] = '\0';
    
    // Parse JSON with enhanced error tracking
    cJSON *json = cJSON_Parse(json_string);
    
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        int line_num = config_estimate_line_number(json_string, error_ptr);
        
        char line_info[32];
        snprintf(line_info, sizeof(line_info), "line_%d", line_num);
        
        config_error_set(error, CONFIG_ERROR_JSON_PARSE_FAILED,
                        "Failed to parse JSON configuration - syntax error detected",
                        "json_syntax", error_ptr ? error_ptr : "unknown", line_info,
                        "Fix JSON syntax errors (missing commas, brackets, quotes)", false);
        error->line_number = line_num;
        
        config_error_log(error, filename);
        config_error_log_detailed_analysis(error, json_string);
        
        LOG_ERROR("Failed to parse JSON configuration: %s", error_ptr ? error_ptr : "unknown error");
        free(json_string);
        return -1;
    }
    
    // Store original JSON for detailed analysis if needed later
    char *json_backup = strdup(json_string);
    free(json_string);
    
    // Validate JSON structure
    if (!cJSON_IsObject(json)) {
        config_error_set(error, CONFIG_ERROR_JSON_INVALID_STRUCTURE,
                        "Configuration file must contain a JSON object at root level",
                        "root_type", "non-object", "json_structure",
                        "Wrap configuration in curly braces { ... }", false);
        config_error_log(error, filename);
        if (json_backup) config_error_log_detailed_analysis(error, json_backup);
        cJSON_Delete(json);
        free(json_backup);
        return -1;
    }
    
    // Parse top-level settings (new format)
    config_parse_string(json, "bind_address", config->bind_address, sizeof(config->bind_address));
    config_parse_uint16(json, "tcp_port", &config->port);
    config_parse_uint16(json, "ssl_port", &config->ssl_port);
    config_parse_uint32(json, "max_clients", &config->max_clients);
    config_parse_bool(json, "ssl_enabled", &config->ssl_enabled);
    config_parse_bool(json, "cert_generation_enabled", &config->cert_generation_enabled);
    config_parse_bool(json, "allow_anonymous", &config->allow_anonymous);
    config_parse_uint32(json, "memory_limit_kb", &config->memory_limit);
    config_parse_uint32(json, "max_publish_rate", &config->max_publish_rate);
    config_parse_uint16(json, "keepalive_interval", &config->keep_alive_interval);
    config_parse_uint32(json, "max_packet_size", &config->max_message_size);
    config_parse_int(json, "log_level", &config->log_level);
    
    // Parse notification settings (new format)
    config_parse_bool(json, "notification_enabled", &config->notification_enabled);
    config_parse_string(json, "notification_destination_client_id", config->notification_destination_client_id, sizeof(config->notification_destination_client_id));
    config_parse_string(json, "default_notification_topic", config->notification_topic, sizeof(config->notification_topic));
    
    // Parse SSL configuration object with validation
    cJSON *ssl_config = cJSON_GetObjectItem(json, "ssl_config");
    if (ssl_config) {
        if (!cJSON_IsObject(ssl_config)) {
            config_error_set(error, CONFIG_ERROR_JSON_TYPE_MISMATCH,
                            "ssl_config must be a JSON object",
                            "ssl_config", "non-object", "ssl_config",
                            "Ensure ssl_config is enclosed in curly braces { ... }", false);
            config_error_log(error, filename);
            cJSON_Delete(json);
            free(json_backup);
            return -1;
        }
        config_parse_string(ssl_config, "ca_cert_file", config->ca_cert_file, sizeof(config->ca_cert_file));
        config_parse_string(ssl_config, "server_cert_file", config->server_cert_file, sizeof(config->server_cert_file));
        config_parse_string(ssl_config, "server_key_file", config->server_key_file, sizeof(config->server_key_file));
        config_parse_bool(ssl_config, "client_cert_required", &config->require_client_cert);
        
        // Validate SSL certificate files if SSL is enabled
        if (config->ssl_enabled) {
            struct stat cert_stat;
            if (strlen(config->ca_cert_file) > 0 && stat(config->ca_cert_file, &cert_stat) != 0) {
                config_error_set(error, CONFIG_ERROR_CERTIFICATE_FILE_MISSING,
                                "SSL CA certificate file not found",
                                "ca_cert_file", config->ca_cert_file, "ssl_config",
                                "Create the CA certificate file or disable SSL", false);
                config_error_log(error, filename);
                cJSON_Delete(json);
                free(json_backup);
                return -1;
            }
            
            if (strlen(config->server_cert_file) > 0 && stat(config->server_cert_file, &cert_stat) != 0) {
                config_error_set(error, CONFIG_ERROR_CERTIFICATE_FILE_MISSING,
                                "SSL server certificate file not found",
                                "server_cert_file", config->server_cert_file, "ssl_config",
                                "Create the server certificate file or disable SSL", false);
                config_error_log(error, filename);
                cJSON_Delete(json);
                free(json_backup);
                return -1;
            }
            
            if (strlen(config->server_key_file) > 0 && stat(config->server_key_file, &cert_stat) != 0) {
                config_error_set(error, CONFIG_ERROR_CERTIFICATE_FILE_MISSING,
                                "SSL server key file not found",
                                "server_key_file", config->server_key_file, "ssl_config",
                                "Create the server key file or disable SSL", false);
                config_error_log(error, filename);
                cJSON_Delete(json);
                free(json_backup);
                return -1;
            }
        }
    }
    
    // Parse network settings (legacy format support)
    cJSON *network = cJSON_GetObjectItem(json, "network");
    if (network) {
        config_parse_string(network, "bind_address", config->bind_address, sizeof(config->bind_address));
        config_parse_uint16(network, "port", &config->port);
        config_parse_uint16(network, "ssl_port", &config->ssl_port);
        config_parse_uint32(network, "max_clients", &config->max_clients);
        config_parse_uint32(network, "max_message_size", &config->max_message_size);
        config_parse_uint16(network, "keep_alive_interval", &config->keep_alive_interval);
    }
    
    // Parse SSL settings (legacy format support)
    cJSON *ssl = cJSON_GetObjectItem(json, "ssl");
    if (ssl) {
        config_parse_bool(ssl, "enabled", &config->ssl_enabled);
        config_parse_string(ssl, "ca_cert_file", config->ca_cert_file, sizeof(config->ca_cert_file));
        config_parse_string(ssl, "server_cert_file", config->server_cert_file, sizeof(config->server_cert_file));
        config_parse_string(ssl, "server_key_file", config->server_key_file, sizeof(config->server_key_file));
        config_parse_bool(ssl, "require_client_cert", &config->require_client_cert);
    }
    
    // Parse authentication settings
    cJSON *auth = cJSON_GetObjectItem(json, "authentication");
    if (auth) {
        config_parse_bool(auth, "allow_anonymous", &config->allow_anonymous);
        config_parse_string(auth, "auth_file", config->auth_file, sizeof(config->auth_file));
    }
    
    // Parse broker settings
    cJSON *broker = cJSON_GetObjectItem(json, "broker");
    if (broker) {
        config_parse_uint32(broker, "max_inflight_messages", &config->max_inflight_messages);
        config_parse_uint32(broker, "max_queued_messages", &config->max_queued_messages);
        config_parse_uint32(broker, "message_retry_interval", &config->message_retry_interval);
        config_parse_bool(broker, "retain_available", &config->retain_available);
        config_parse_bool(broker, "wildcard_subscriptions", &config->wildcard_subscriptions);
        config_parse_bool(broker, "subscription_identifier_available", &config->subscription_identifier_available);
        config_parse_bool(broker, "shared_subscriptions", &config->shared_subscriptions);
    }
    
    // Parse persistence settings
    cJSON *persistence = cJSON_GetObjectItem(json, "persistence");
    if (persistence) {
        config_parse_bool(persistence, "enabled", &config->persistence_enabled);
        config_parse_string(persistence, "location", config->persistence_location, sizeof(config->persistence_location));
        config_parse_uint32(persistence, "autosave_interval", &config->autosave_interval);
    }
    
    // Parse logging settings
    cJSON *logging = cJSON_GetObjectItem(json, "logging");
    if (logging) {
        config_parse_string(logging, "log_file", config->log_file, sizeof(config->log_file));
        config_parse_int(logging, "log_level", &config->log_level);
        config_parse_bool(logging, "log_to_console", &config->log_to_console);
    }
    
    // Parse memory settings
    cJSON *memory = cJSON_GetObjectItem(json, "memory");
    if (memory) {
        config_parse_uint32(memory, "memory_limit", &config->memory_limit);
        config_parse_uint32(memory, "connection_timeout", &config->connection_timeout);
        config_parse_uint32(memory, "client_timeout", &config->client_timeout);
    }
    
    // Parse performance settings
    cJSON *performance = cJSON_GetObjectItem(json, "performance");
    if (performance) {
        config_parse_uint32(performance, "max_connections_per_ip", &config->max_connections_per_ip);
        config_parse_uint32(performance, "max_publish_rate", &config->max_publish_rate);
        config_parse_uint32(performance, "max_subscribe_rate", &config->max_subscribe_rate);
    }
    
    // Parse notification settings (support both "notification" and "notifications")
    cJSON *notification = cJSON_GetObjectItem(json, "notifications");
    if (!notification) {
        notification = cJSON_GetObjectItem(json, "notification"); // Legacy support
    }
    if (notification) {
        config_parse_bool(notification, "enabled", &config->notification_enabled);
        config_parse_string(notification, "destination_client_id", config->notification_destination_client_id, sizeof(config->notification_destination_client_id));
        config_parse_string(notification, "topic", config->notification_topic, sizeof(config->notification_topic));
        LOG_DEBUG("Parsed notification config: enabled=%s, topic=%s", 
                config->notification_enabled ? "true" : "false", config->notification_topic);
    }
    
    // Parse certificate generation settings
    cJSON *cert_gen = cJSON_GetObjectItem(json, "certificate_generation");
    if (cert_gen) {
        config_parse_bool(cert_gen, "enabled", &config->cert_generation_enabled);
        config_parse_string(cert_gen, "ca_cert_file", config->cert_ca_cert_file, sizeof(config->cert_ca_cert_file));
        config_parse_string(cert_gen, "ca_key_file", config->cert_ca_key_file, sizeof(config->cert_ca_key_file));
        config_parse_string(cert_gen, "output_directory", config->cert_output_directory, sizeof(config->cert_output_directory));
    }
    
    cJSON_Delete(json);
    
    // Final configuration validation with detailed error tracking
    if (config->port == config->ssl_port) {
        config_error_set(error, CONFIG_ERROR_NETWORK_INVALID_RANGE,
                        "TCP port and SSL port cannot be the same",
                        "port/ssl_port", "same_value", "network_config",
                        "Use different port numbers for TCP and SSL", false);
        config_error_log(error, filename);
        free(json_backup);
        return -1;
    }
    
    if (config->max_clients == 0) {
        config_error_set(error, CONFIG_ERROR_INVALID_FIELD_VALUE,
                        "Maximum clients must be greater than 0",
                        "max_clients", "0", "network_config",
                        "Set max_clients to a positive integer", false);
        config_error_log(error, filename);
        free(json_backup);
        return -1;
    }
    
    if (config->memory_limit == 0) {
        config_error_set(error, CONFIG_ERROR_INVALID_FIELD_VALUE,
                        "Memory limit must be greater than 0",
                        "memory_limit", "0", "memory_config",
                        "Set memory_limit to a positive value in KB", false);
        config_error_log(error, filename);
        free(json_backup);
        return -1;
    }
    
    // Validate configuration using existing function
    if (config_validate(config) != 0) {
        config_error_set(error, CONFIG_ERROR_VALIDATION_FAILED,
                        "Configuration validation failed - invalid parameter combination",
                        "config_validation", "failed", "config_structure",
                        "Check all configuration parameters for valid ranges and combinations", false);
        config_error_log(error, filename);
        free(json_backup);
        return -1;
    }
    
    // Cleanup and success
    free(json_backup);
    LOG_INFO("Configuration loaded successfully from %s with enhanced error tracking", filename);
    return 0;
}

// Legacy config loading function - now uses enhanced error tracking
int config_load(broker_config_t *config, const char *filename) {
    // Use the enhanced error tracking function internally
    config_error_details_t error_details;
    int result = config_load_with_error_tracking(config, filename, &error_details);
    
    // If there was an error and it's not just a missing file, log the detailed error
    if (result != 0 && error_details.error_code != CONFIG_ERROR_FILE_NOT_FOUND) {
        LOG_ERROR("Configuration loading failed with detailed error tracking");
        config_error_log(&error_details, filename);
    }
    
    return result;
}

int config_validate(const broker_config_t *config) {
    if (!config) return -1;
    
    // Validate network settings
    if (config->port == 0 || config->port > 65535) {
        LOG_ERROR("Invalid port: %d", config->port);
        return -1;
    }
    
    if (config->ssl_enabled && (config->ssl_port == 0 || config->ssl_port > 65535)) {
        LOG_ERROR("Invalid SSL port: %d", config->ssl_port);
        return -1;
    }
    
    if (config->max_clients == 0) {
        LOG_ERROR("max_clients must be > 0");
        return -1;
    }
    
    if (config->max_message_size == 0) {
        LOG_ERROR("max_message_size must be > 0");
        return -1;
    }
    
    // Validate SSL settings
    if (config->ssl_enabled) {
        if (strlen(config->server_cert_file) == 0 || strlen(config->server_key_file) == 0) {
            LOG_ERROR("SSL enabled but certificate files not specified");
            return -1;
        }
    }
    
    // Validate log level
    if (config->log_level < 0 || config->log_level > 3) {
        LOG_ERROR("Invalid log level: %d", config->log_level);
        return -1;
    }
    
    // Validate memory limit
    if (config->memory_limit < 64 * 1024) { // Minimum 64KB
        LOG_ERROR("Memory limit too low: %u", config->memory_limit);
        return -1;
    }
    
    return 0;
}

void config_cleanup(broker_config_t *config) {
    // No dynamic memory to free in current implementation
    (void)config;
}

void config_print(const broker_config_t *config) {
    if (!config) return;
    
    printf("Broker Configuration:\n");
    printf("  Network:\n");
    printf("    Bind Address: %s\n", config->bind_address);
    printf("    Port: %d\n", config->port);
    printf("    SSL Port: %d\n", config->ssl_port);
    printf("    Max Clients: %d\n", config->max_clients);
    printf("    Max Message Size: %d bytes\n", config->max_message_size);
    printf("    Keep Alive Interval: %d seconds\n", config->keep_alive_interval);
    
    printf("  SSL/TLS:\n");
    printf("    Enabled: %s\n", config->ssl_enabled ? "yes" : "no");
    if (config->ssl_enabled) {
        printf("    CA Certificate: %s\n", config->ca_cert_file);
        printf("    Server Certificate: %s\n", config->server_cert_file);
        printf("    Server Key: %s\n", config->server_key_file);
        printf("    Require Client Certificate: %s\n", config->require_client_cert ? "yes" : "no");
    }
    
    printf("  Authentication:\n");
    printf("    Allow Anonymous: %s\n", config->allow_anonymous ? "yes" : "no");
    
    printf("  Broker Features:\n");
    printf("    Retain Available: %s\n", config->retain_available ? "yes" : "no");
    printf("    Wildcard Subscriptions: %s\n", config->wildcard_subscriptions ? "yes" : "no");
    
    printf("  Memory:\n");
    printf("    Memory Limit: %d bytes\n", config->memory_limit);
    printf("    Connection Timeout: %d seconds\n", config->connection_timeout);
    
    printf("  Logging:\n");
    printf("    Log Level: %d\n", config->log_level);
    printf("    Log to Console: %s\n", config->log_to_console ? "yes" : "no");
}
