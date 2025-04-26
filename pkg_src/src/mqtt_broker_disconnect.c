#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mqtt_broker.h"
#include "disconnect_handler.h"
#include "json/cJSON.h"
#include <stdbool.h>

/* Extracts process_id from a heartbeat message */
static bool extract_process_id_from_heartbeat(const uint8_t *payload, 
                                             size_t payload_len, 
                                             char *process_id, 
                                             size_t process_id_size) {
    if (!payload || payload_len == 0 || !process_id || process_id_size == 0) {
        return false;
    }
    
    /* Ensure the payload is null-terminated for JSON parsing */
    char *json_str = (char *)malloc(payload_len + 1);
    if (!json_str) {
        return false;
    }
    
    memcpy(json_str, payload, payload_len);
    json_str[payload_len] = '\0';
    
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    
    if (!root) {
        return false;
    }
    
    cJSON *process_id_json = cJSON_GetObjectItem(root, "process_id");
    if (!cJSON_IsString(process_id_json) || !process_id_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(process_id_json->valuestring) >= process_id_size) {
        cJSON_Delete(root);
        return false;
    }
    
    strcpy(process_id, process_id_json->valuestring);
    cJSON_Delete(root);
    
    return true;
}

int mqtt_broker_init_disconnect_handler(mqtt_broker_t *broker, const char *config_file) {
    if (!broker || !config_file) {
        return MQTT_RC_INVALID_ARGS;
    }
    
    /* Initialize the disconnect handler */
    if (!disconnect_handler_init(&broker->disconnect_handler)) {
        fprintf(stderr, "Failed to initialize disconnect handler\n");
        return MQTT_RC_FAILURE;
    }
    
    /* Load configuration */
    if (!disconnect_handler_load_config(&broker->disconnect_handler, config_file)) {
        fprintf(stderr, "Failed to load disconnect handler configuration from %s\n", config_file);
        return MQTT_RC_FAILURE;
    }
    
    broker->disconnect_handler_enabled = true;
    
    printf("Disconnect handler initialized with config from %s\n", config_file);
    return MQTT_RC_SUCCESS;
}

int mqtt_broker_handle_disconnect(mqtt_broker_t *broker, mqtt_session_t *session) {
    if (!broker || !session) {
        return MQTT_RC_INVALID_ARGS;
    }
    
    /* If disconnect handler is not enabled, just return success */
    if (!broker->disconnect_handler_enabled) {
        return MQTT_RC_SUCCESS;
    }
    
    /* Get client ID */
    const char *client_id = session->client_id;
    if (!client_id || client_id[0] == '\0') {
        fprintf(stderr, "Cannot handle disconnect for empty client ID\n");
        return MQTT_RC_FAILURE;
    }
    
    /* Try to get process ID from session if available */
    char process_id[64] = "*";  /* Default wildcard */
    
    /* Look for a stored heartbeat message in the session context */
    if (session->last_heartbeat_payload && session->last_heartbeat_len > 0) {
        if (extract_process_id_from_heartbeat(session->last_heartbeat_payload, 
                                             session->last_heartbeat_len,
                                             process_id, sizeof(process_id))) {
            printf("Found process_id in heartbeat: %s\n", process_id);
        }
    }
    
    /* Process the disconnect event */
    int actions_executed = disconnect_handler_process_disconnect(
        &broker->disconnect_handler, 
        process_id, 
        client_id
    );
    
    printf("Processed disconnect for client '%s' (process '%s'): %d actions executed\n",
           client_id, process_id, actions_executed);
    
    return MQTT_RC_SUCCESS;
}
