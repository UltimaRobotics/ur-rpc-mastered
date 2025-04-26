/**
 * @file disconnect_handler.c
 * @brief Handler for client disconnections
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disconnect_handler.h"
#include "logger.h"
#include "utils.h"
#include "json/cJSON.h"

// Configuration structure
typedef struct {
    char *client_id;
    char *action;
    char *topic;
    char *message;
} disconnect_handler_config_t;

// Global state
static disconnect_handler_config_t *configs = NULL;
static int config_count = 0;
static int initialized = 0;

// Free a config structure
static void free_config(disconnect_handler_config_t *config) {
    if (!config) {
        return;
    }
    
    free(config->client_id);
    free(config->action);
    free(config->topic);
    free(config->message);
}

int disconnect_handler_init(const char *config_file) {
    FILE *fp;
    long file_size;
    char *file_content;
    cJSON *json, *handlers_json;
    int i, count;
    
    if (initialized) {
        // Already initialized
        return 0;
    }
    
    if (!config_file) {
        log_error("No disconnect handler configuration file specified");
        return -1;
    }
    
    // Open configuration file
    fp = fopen(config_file, "r");
    if (!fp) {
        log_error("Failed to open disconnect handler configuration file: %s", config_file);
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(fp);
        log_error("Empty disconnect handler configuration file: %s", config_file);
        return -1;
    }
    
    // Allocate buffer for file content
    file_content = (char *)malloc(file_size + 1);
    if (!file_content) {
        fclose(fp);
        log_error("Failed to allocate memory for disconnect handler configuration file");
        return -1;
    }
    
    // Read file content
    if (fread(file_content, 1, file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(file_content);
        log_error("Failed to read disconnect handler configuration file");
        return -1;
    }
    
    file_content[file_size] = '\0';
    fclose(fp);
    
    // Parse JSON
    json = cJSON_Parse(file_content);
    free(file_content);
    
    if (!json) {
        log_error("Failed to parse disconnect handler configuration file as JSON");
        return -1;
    }
    
    // Get handlers array
    handlers_json = cJSON_GetObjectItem(json, "handlers");
    if (!handlers_json || !cJSON_IsArray(handlers_json)) {
        cJSON_Delete(json);
        log_error("Invalid handlers array in disconnect handler configuration file");
        return -1;
    }
    
    // Count handlers
    count = cJSON_GetArraySize(handlers_json);
    if (count <= 0) {
        cJSON_Delete(json);
        log_info("No disconnect handlers defined in configuration file");
        return 0;
    }
    
    // Allocate handlers array
    configs = (disconnect_handler_config_t *)calloc(count, sizeof(disconnect_handler_config_t));
    if (!configs) {
        cJSON_Delete(json);
        log_error("Failed to allocate memory for disconnect handlers");
        return -1;
    }
    
    // Parse handlers
    for (i = 0; i < count; i++) {
        cJSON *handler_json = cJSON_GetArrayItem(handlers_json, i);
        cJSON *client_id_json, *action_json, *topic_json, *message_json;
        
        if (!handler_json || !cJSON_IsObject(handler_json)) {
            // Skip invalid handlers
            continue;
        }
        
        // Parse client ID
        client_id_json = cJSON_GetObjectItem(handler_json, "client_id");
        if (client_id_json && cJSON_IsString(client_id_json)) {
            configs[i].client_id = utils_strdup(client_id_json->valuestring);
            if (!configs[i].client_id) {
                // Failed to allocate memory
                continue;
            }
        } else {
            // Wildcard - match any client ID
            configs[i].client_id = NULL;
        }
        
        // Parse action
        action_json = cJSON_GetObjectItem(handler_json, "action");
        if (!action_json || !cJSON_IsString(action_json)) {
            // Skip handlers without action
            free(configs[i].client_id);
            configs[i].client_id = NULL;
            continue;
        }
        
        configs[i].action = utils_strdup(action_json->valuestring);
        if (!configs[i].action) {
            // Failed to allocate memory
            free(configs[i].client_id);
            configs[i].client_id = NULL;
            continue;
        }
        
        // Parse topic (if applicable)
        topic_json = cJSON_GetObjectItem(handler_json, "topic");
        if (topic_json && cJSON_IsString(topic_json)) {
            configs[i].topic = utils_strdup(topic_json->valuestring);
            if (!configs[i].topic) {
                // Failed to allocate memory
                free(configs[i].client_id);
                free(configs[i].action);
                configs[i].client_id = NULL;
                configs[i].action = NULL;
                continue;
            }
        } else {
            configs[i].topic = NULL;
        }
        
        // Parse message (if applicable)
        message_json = cJSON_GetObjectItem(handler_json, "message");
        if (message_json && cJSON_IsString(message_json)) {
            configs[i].message = utils_strdup(message_json->valuestring);
            if (!configs[i].message) {
                // Failed to allocate memory
                free(configs[i].client_id);
                free(configs[i].action);
                free(configs[i].topic);
                configs[i].client_id = NULL;
                configs[i].action = NULL;
                configs[i].topic = NULL;
                continue;
            }
        } else {
            configs[i].message = NULL;
        }
        
        config_count++;
    }
    
    cJSON_Delete(json);
    initialized = 1;
    
    log_info("Disconnect handler initialized with %d handlers", config_count);
    return 0;
}

void disconnect_handler_cleanup(void) {
    int i;
    
    if (!initialized) {
        return;
    }
    
    for (i = 0; i < config_count; i++) {
        free_config(&configs[i]);
    }
    
    free(configs);
    configs = NULL;
    config_count = 0;
    initialized = 0;
}

int disconnect_handler_handle(const char *client_id) {
    int i;
    
    if (!initialized) {
        // Not initialized, do nothing
        return 0;
    }
    
    if (!client_id) {
        return -1;
    }
    
    log_debug("Handling disconnect for client %s", client_id);
    
    // Find matching handlers
    for (i = 0; i < config_count; i++) {
        // Check if the client ID matches
        if (configs[i].client_id && strcmp(configs[i].client_id, client_id) != 0) {
            // Not a match
            continue;
        }
        
        // Client ID matches or is wildcard
        log_debug("Found matching disconnect handler for client %s", client_id);
        
        // Handle the action
        if (strcmp(configs[i].action, "publish") == 0) {
            // Publish action
            if (!configs[i].topic || !configs[i].message) {
                log_warn("Disconnect handler publish action missing topic or message");
                continue;
            }
            
            log_info("Disconnect handler publishing to topic %s", configs[i].topic);
            // In a full implementation, we would publish the message here
            // For now, we just log it
            log_debug("Would publish message: %s", configs[i].message);
        } else if (strcmp(configs[i].action, "log") == 0) {
            // Log action
            log_info("Disconnect handler log: %s", 
                configs[i].message ? configs[i].message : "Client disconnected");
        } else {
            log_warn("Unknown disconnect handler action: %s", configs[i].action);
        }
    }
    
    return 0;
}