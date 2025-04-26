/**
 * @file config.c
 * @brief Configuration utilities for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "logger.h"
#include "utils.h"
#include "json/cJSON.h"

// Global configuration state
static broker_config_t broker_config;
static int initialized = 0;

// Default configuration values
static const broker_config_t default_config = {
    .port = 1883,
    .max_connections = 100,
    .max_message_size = 65536,
    .persistence_dir = NULL,
    .log_level = NULL,
    .auth_file = NULL,
    .disconnect_handler_config = NULL
};

// Free allocated configuration memory
static void free_config(void) {
    free(broker_config.persistence_dir);
    free(broker_config.log_level);
    free(broker_config.auth_file);
    free(broker_config.disconnect_handler_config);
    
    broker_config.persistence_dir = NULL;
    broker_config.log_level = NULL;
    broker_config.auth_file = NULL;
    broker_config.disconnect_handler_config = NULL;
}

int config_init(const char *config_file) {
    FILE *fp;
    long file_size;
    char *file_content;
    cJSON *json, *broker_json;
    cJSON *port_json, *max_connections_json, *max_message_size_json;
    cJSON *persistence_dir_json, *log_level_json, *auth_file_json;
    cJSON *disconnect_handler_config_json;
    
    if (initialized) {
        // Already initialized
        return 0;
    }
    
    if (!config_file) {
        log_error("No configuration file specified");
        return -1;
    }
    
    // Initialize with default values
    broker_config = default_config;
    
    // Open configuration file
    fp = fopen(config_file, "r");
    if (!fp) {
        log_error("Failed to open configuration file: %s", config_file);
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(fp);
        log_error("Empty configuration file: %s", config_file);
        return -1;
    }
    
    // Allocate buffer for file content
    file_content = (char *)malloc(file_size + 1);
    if (!file_content) {
        fclose(fp);
        log_error("Failed to allocate memory for configuration file");
        return -1;
    }
    
    // Read file content
    if (fread(file_content, 1, file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(file_content);
        log_error("Failed to read configuration file");
        return -1;
    }
    
    file_content[file_size] = '\0';
    fclose(fp);
    
    // Parse JSON
    json = cJSON_Parse(file_content);
    free(file_content);
    
    if (!json) {
        log_error("Failed to parse configuration file as JSON");
        return -1;
    }
    
    // Get broker object
    broker_json = cJSON_GetObjectItem(json, "broker");
    if (!broker_json || !cJSON_IsObject(broker_json)) {
        cJSON_Delete(json);
        log_error("Invalid broker object in configuration file");
        return -1;
    }
    
    // Parse broker configuration
    port_json = cJSON_GetObjectItem(broker_json, "port");
    if (port_json && cJSON_IsNumber(port_json)) {
        broker_config.port = port_json->valueint;
    }
    
    max_connections_json = cJSON_GetObjectItem(broker_json, "max_connections");
    if (max_connections_json && cJSON_IsNumber(max_connections_json)) {
        broker_config.max_connections = max_connections_json->valueint;
    }
    
    max_message_size_json = cJSON_GetObjectItem(broker_json, "max_message_size");
    if (max_message_size_json && cJSON_IsNumber(max_message_size_json)) {
        broker_config.max_message_size = max_message_size_json->valueint;
    }
    
    persistence_dir_json = cJSON_GetObjectItem(broker_json, "persistence_dir");
    if (persistence_dir_json && cJSON_IsString(persistence_dir_json)) {
        broker_config.persistence_dir = utils_strdup(persistence_dir_json->valuestring);
    }
    
    log_level_json = cJSON_GetObjectItem(broker_json, "log_level");
    if (log_level_json && cJSON_IsString(log_level_json)) {
        broker_config.log_level = utils_strdup(log_level_json->valuestring);
    }
    
    auth_file_json = cJSON_GetObjectItem(broker_json, "auth_file");
    if (auth_file_json && cJSON_IsString(auth_file_json)) {
        broker_config.auth_file = utils_strdup(auth_file_json->valuestring);
    }
    
    disconnect_handler_config_json = cJSON_GetObjectItem(broker_json, "disconnect_handler_config");
    if (disconnect_handler_config_json && cJSON_IsString(disconnect_handler_config_json)) {
        broker_config.disconnect_handler_config = utils_strdup(disconnect_handler_config_json->valuestring);
    }
    
    cJSON_Delete(json);
    initialized = 1;
    
    log_info("Configuration initialized");
    log_debug("Broker port: %d", broker_config.port);
    log_debug("Broker max connections: %d", broker_config.max_connections);
    log_debug("Broker max message size: %d", broker_config.max_message_size);
    log_debug("Broker persistence directory: %s", broker_config.persistence_dir ? broker_config.persistence_dir : "None");
    log_debug("Broker log level: %s", broker_config.log_level ? broker_config.log_level : "None");
    log_debug("Broker auth file: %s", broker_config.auth_file ? broker_config.auth_file : "None");
    log_debug("Broker disconnect handler config: %s", broker_config.disconnect_handler_config ? broker_config.disconnect_handler_config : "None");
    
    return 0;
}

void config_cleanup(void) {
    if (!initialized) {
        return;
    }
    
    free_config();
    initialized = 0;
}

const broker_config_t *config_get_broker(void) {
    if (!initialized) {
        return NULL;
    }
    
    return &broker_config;
}