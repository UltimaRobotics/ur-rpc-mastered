#include "config.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>

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

int config_load(broker_config_t *config, const char *filename) {
    if (!config || !filename) {
        LOG_ERROR("Invalid parameters");
        return -1;
    }
    
    // Set defaults first
    config_set_defaults(config);
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        LOG_WARNING("Configuration file %s not found, using defaults", filename);
        return 0; // Not an error, just use defaults
    }
    
    // Read file contents
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024 * 1024) { // Max 1MB config file
        LOG_ERROR("Invalid configuration file size: %ld", file_size);
        fclose(file);
        return -1;
    }
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        LOG_ERROR("Failed to allocate memory for configuration");
        fclose(file);
        return -1;
    }
    
    size_t bytes_read = fread(json_string, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != file_size) {
        LOG_ERROR("Failed to read configuration file");
        free(json_string);
        return -1;
    }
    
    json_string[file_size] = '\0';
    
    // Parse JSON
    cJSON *json = cJSON_Parse(json_string);
    free(json_string);
    
    if (!json) {
        LOG_ERROR("Failed to parse JSON configuration: %s", cJSON_GetErrorPtr());
        return -1;
    }
    
    // Parse network settings
    cJSON *network = cJSON_GetObjectItem(json, "network");
    if (network) {
        config_parse_string(network, "bind_address", config->bind_address, sizeof(config->bind_address));
        config_parse_uint16(network, "port", &config->port);
        config_parse_uint16(network, "ssl_port", &config->ssl_port);
        config_parse_uint32(network, "max_clients", &config->max_clients);
        config_parse_uint32(network, "max_message_size", &config->max_message_size);
        config_parse_uint16(network, "keep_alive_interval", &config->keep_alive_interval);
    }
    
    // Parse SSL settings
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
    
    cJSON_Delete(json);
    
    // Validate configuration
    if (config_validate(config) != 0) {
        LOG_ERROR("Configuration validation failed");
        return -1;
    }
    
    LOG_INFO("Configuration loaded successfully from %s", filename);
    return 0;
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
