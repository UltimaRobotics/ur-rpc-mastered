#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "serialization.h"
#include "json/cJSON.h"

/* For Base64 encoding/decoding of binary payloads */
static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const uint8_t *data, size_t len) {
    char *out;
    size_t i, j;
    size_t out_len = 4 * ((len + 2) / 3);
    
    out = (char *)malloc(out_len + 1);
    if (!out) {
        return NULL;
    }
    
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = base64_chars[(triple >> 6) & 0x3F];
        out[j++] = base64_chars[triple & 0x3F];
    }
    
    /* Padding */
    switch (len % 3) {
        case 1:
            out[out_len - 2] = '=';
        case 2:
            out[out_len - 1] = '=';
    }
    
    out[out_len] = '\0';
    return out;
}

static uint8_t *base64_decode(const char *data, size_t *len) {
    uint8_t *out;
    size_t i, j, k;
    size_t input_len = strlen(data);
    size_t out_len = input_len / 4 * 3;
    
    if (data[input_len - 1] == '=') out_len--;
    if (data[input_len - 2] == '=') out_len--;
    
    out = (uint8_t *)malloc(out_len + 1);
    if (!out) {
        return NULL;
    }
    
    for (i = 0, j = 0; i < input_len;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
        
        if (j < out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) out[j++] = triple & 0xFF;
    }
    
    out[out_len] = '\0';
    *len = out_len;
    return out;
}

int serialize_mqtt_message(const char *client_id, const char *topic, 
                         const uint8_t *payload, size_t payload_len,
                         int qos, bool retain,
                         char *output, size_t output_size) {
    if (!client_id || !topic || !payload || !output || output_size == 0) {
        return -1;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return -1;
    }
    
    /* Convert binary payload to base64 */
    char *payload_b64 = base64_encode(payload, payload_len);
    if (!payload_b64) {
        cJSON_Delete(root);
        return -1;
    }
    
    cJSON_AddStringToObject(root, "client_id", client_id);
    cJSON_AddStringToObject(root, "topic", topic);
    cJSON_AddStringToObject(root, "payload", payload_b64);
    cJSON_AddNumberToObject(root, "qos", qos);
    cJSON_AddBoolToObject(root, "retain", retain);
    cJSON_AddNumberToObject(root, "timestamp", (double)time(NULL));
    
    char *json_str = cJSON_PrintUnformatted(root);
    free(payload_b64);
    cJSON_Delete(root);
    
    if (!json_str) {
        return -1;
    }
    
    size_t json_len = strlen(json_str);
    if (json_len >= output_size) {
        free(json_str);
        return -1;
    }
    
    strcpy(output, json_str);
    free(json_str);
    
    return json_len;
}

bool deserialize_mqtt_message(const char *json_str,
                            char *client_id, size_t client_id_size,
                            char *topic, size_t topic_size,
                            uint8_t *payload, size_t payload_size, size_t *payload_len,
                            int *qos, bool *retain) {
    if (!json_str || !client_id || !topic || !payload || !payload_len || !qos || !retain) {
        return false;
    }
    
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return false;
    }
    
    /* Get client_id */
    cJSON *client_id_json = cJSON_GetObjectItem(root, "client_id");
    if (!cJSON_IsString(client_id_json) || !client_id_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(client_id_json->valuestring) >= client_id_size) {
        cJSON_Delete(root);
        return false;
    }
    strcpy(client_id, client_id_json->valuestring);
    
    /* Get topic */
    cJSON *topic_json = cJSON_GetObjectItem(root, "topic");
    if (!cJSON_IsString(topic_json) || !topic_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(topic_json->valuestring) >= topic_size) {
        cJSON_Delete(root);
        return false;
    }
    strcpy(topic, topic_json->valuestring);
    
    /* Get payload (base64 encoded) */
    cJSON *payload_json = cJSON_GetObjectItem(root, "payload");
    if (!cJSON_IsString(payload_json) || !payload_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    size_t decoded_len = 0;
    uint8_t *decoded_payload = base64_decode(payload_json->valuestring, &decoded_len);
    if (!decoded_payload) {
        cJSON_Delete(root);
        return false;
    }
    
    if (decoded_len > payload_size) {
        free(decoded_payload);
        cJSON_Delete(root);
        return false;
    }
    
    memcpy(payload, decoded_payload, decoded_len);
    *payload_len = decoded_len;
    free(decoded_payload);
    
    /* Get QoS */
    cJSON *qos_json = cJSON_GetObjectItem(root, "qos");
    if (!cJSON_IsNumber(qos_json)) {
        cJSON_Delete(root);
        return false;
    }
    *qos = qos_json->valueint;
    
    /* Get retain flag */
    cJSON *retain_json = cJSON_GetObjectItem(root, "retain");
    if (!cJSON_IsBool(retain_json)) {
        cJSON_Delete(root);
        return false;
    }
    *retain = cJSON_IsTrue(retain_json);
    
    cJSON_Delete(root);
    return true;
}

int serialize_client_config(const client_config_t *config,
                          char *output, size_t output_size) {
    if (!config || !output || output_size == 0) {
        return -1;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return -1;
    }
    
    cJSON_AddStringToObject(root, "process_id", config->process_id);
    cJSON_AddStringToObject(root, "broker_url", config->broker_url);
    cJSON_AddNumberToObject(root, "broker_port", config->broker_port);
    cJSON_AddStringToObject(root, "heartbeat_topic", config->heartbeat_topic);
    cJSON_AddStringToObject(root, "response_topic", config->response_topic);
    cJSON_AddStringToObject(root, "query_topic", config->query_topic);
    cJSON_AddNumberToObject(root, "heartbeat_interval", config->heartbeat_interval);
    cJSON_AddNumberToObject(root, "heartbeat_timeout", config->heartbeat_timeout);
    
    /* Add publication topics */
    cJSON *pub_topics = cJSON_CreateArray();
    if (!pub_topics) {
        cJSON_Delete(root);
        return -1;
    }
    
    for (int i = 0; i < config->pub_topic_count; i++) {
        cJSON_AddItemToArray(pub_topics, cJSON_CreateString(config->pub_topics[i]));
    }
    cJSON_AddItemToObject(root, "pub_topics", pub_topics);
    
    /* Add subscription topics */
    cJSON *sub_topics = cJSON_CreateArray();
    if (!sub_topics) {
        cJSON_Delete(root);
        return -1;
    }
    
    for (int i = 0; i < config->sub_topic_count; i++) {
        cJSON_AddItemToArray(sub_topics, cJSON_CreateString(config->sub_topics[i]));
    }
    cJSON_AddItemToObject(root, "sub_topics", sub_topics);
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        return -1;
    }
    
    size_t json_len = strlen(json_str);
    if (json_len >= output_size) {
        free(json_str);
        return -1;
    }
    
    strcpy(output, json_str);
    free(json_str);
    
    return json_len;
}

bool deserialize_client_config(const char *json_str, client_config_t *config) {
    if (!json_str || !config) {
        return false;
    }
    
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return false;
    }
    
    /* Initialize config with default values */
    memset(config, 0, sizeof(client_config_t));
    strcpy(config->process_id, "unknown");
    strcpy(config->broker_url, "localhost");
    config->broker_port = 1883;
    strcpy(config->heartbeat_topic, "heartbeat");
    strcpy(config->response_topic, "response");
    strcpy(config->query_topic, "query");
    config->heartbeat_interval = 5000;  /* 5 seconds */
    config->heartbeat_timeout = 15000;  /* 15 seconds */
    
    /* Get process_id */
    cJSON *process_id = cJSON_GetObjectItem(root, "process_id");
    if (cJSON_IsString(process_id) && process_id->valuestring) {
        strncpy(config->process_id, process_id->valuestring, MAX_PROCESS_ID_LENGTH - 1);
    }
    
    /* Get broker_url */
    cJSON *broker_url = cJSON_GetObjectItem(root, "broker_url");
    if (cJSON_IsString(broker_url) && broker_url->valuestring) {
        strncpy(config->broker_url, broker_url->valuestring, MAX_URL_LENGTH - 1);
    }
    
    /* Get broker_port */
    cJSON *broker_port = cJSON_GetObjectItem(root, "broker_port");
    if (cJSON_IsNumber(broker_port)) {
        config->broker_port = (uint16_t)broker_port->valueint;
    }
    
    /* Get heartbeat_topic */
    cJSON *heartbeat_topic = cJSON_GetObjectItem(root, "heartbeat_topic");
    if (cJSON_IsString(heartbeat_topic) && heartbeat_topic->valuestring) {
        strncpy(config->heartbeat_topic, heartbeat_topic->valuestring, MAX_TOPIC_LENGTH - 1);
    }
    
    /* Get response_topic */
    cJSON *response_topic = cJSON_GetObjectItem(root, "response_topic");
    if (cJSON_IsString(response_topic) && response_topic->valuestring) {
        strncpy(config->response_topic, response_topic->valuestring, MAX_TOPIC_LENGTH - 1);
    }
    
    /* Get query_topic */
    cJSON *query_topic = cJSON_GetObjectItem(root, "query_topic");
    if (cJSON_IsString(query_topic) && query_topic->valuestring) {
        strncpy(config->query_topic, query_topic->valuestring, MAX_TOPIC_LENGTH - 1);
    }
    
    /* Get heartbeat_interval */
    cJSON *heartbeat_interval = cJSON_GetObjectItem(root, "heartbeat_interval");
    if (cJSON_IsNumber(heartbeat_interval)) {
        config->heartbeat_interval = (uint32_t)heartbeat_interval->valueint;
    }
    
    /* Get heartbeat_timeout */
    cJSON *heartbeat_timeout = cJSON_GetObjectItem(root, "heartbeat_timeout");
    if (cJSON_IsNumber(heartbeat_timeout)) {
        config->heartbeat_timeout = (uint32_t)heartbeat_timeout->valueint;
    }
    
    /* Get publication topics */
    cJSON *pub_topics = cJSON_GetObjectItem(root, "pub_topics");
    if (cJSON_IsArray(pub_topics)) {
        int count = 0;
        cJSON *topic = NULL;
        
        cJSON_ArrayForEach(topic, pub_topics) {
            if (cJSON_IsString(topic) && topic->valuestring && count < MAX_TOPICS) {
                strncpy(config->pub_topics[count], topic->valuestring, MAX_TOPIC_LENGTH - 1);
                count++;
            }
        }
        
        config->pub_topic_count = count;
    }
    
    /* Get subscription topics */
    cJSON *sub_topics = cJSON_GetObjectItem(root, "sub_topics");
    if (cJSON_IsArray(sub_topics)) {
        int count = 0;
        cJSON *topic = NULL;
        
        cJSON_ArrayForEach(topic, sub_topics) {
            if (cJSON_IsString(topic) && topic->valuestring && count < MAX_TOPICS) {
                strncpy(config->sub_topics[count], topic->valuestring, MAX_TOPIC_LENGTH - 1);
                count++;
            }
        }
        
        config->sub_topic_count = count;
    }
    
    cJSON_Delete(root);
    return true;
}

int serialize_heartbeat(const char *client_id, const char *process_id,
                      const char *status,
                      char *output, size_t output_size) {
    if (!client_id || !process_id || !status || !output || output_size == 0) {
        return -1;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return -1;
    }
    
    cJSON_AddStringToObject(root, "client_id", client_id);
    cJSON_AddStringToObject(root, "process_id", process_id);
    cJSON_AddStringToObject(root, "status", status);
    cJSON_AddNumberToObject(root, "timestamp", (double)time(NULL));
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        return -1;
    }
    
    size_t json_len = strlen(json_str);
    if (json_len >= output_size) {
        free(json_str);
        return -1;
    }
    
    strcpy(output, json_str);
    free(json_str);
    
    return json_len;
}

bool deserialize_heartbeat(const char *json_str,
                         char *client_id, size_t client_id_size,
                         char *process_id, size_t process_id_size,
                         char *status, size_t status_size,
                         int64_t *timestamp) {
    if (!json_str || !client_id || !process_id || !status || !timestamp) {
        return false;
    }
    
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return false;
    }
    
    /* Get client_id */
    cJSON *client_id_json = cJSON_GetObjectItem(root, "client_id");
    if (!cJSON_IsString(client_id_json) || !client_id_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(client_id_json->valuestring) >= client_id_size) {
        cJSON_Delete(root);
        return false;
    }
    strcpy(client_id, client_id_json->valuestring);
    
    /* Get process_id */
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
    
    /* Get status */
    cJSON *status_json = cJSON_GetObjectItem(root, "status");
    if (!cJSON_IsString(status_json) || !status_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(status_json->valuestring) >= status_size) {
        cJSON_Delete(root);
        return false;
    }
    strcpy(status, status_json->valuestring);
    
    /* Get timestamp */
    cJSON *timestamp_json = cJSON_GetObjectItem(root, "timestamp");
    if (!cJSON_IsNumber(timestamp_json)) {
        cJSON_Delete(root);
        return false;
    }
    *timestamp = (int64_t)timestamp_json->valuedouble;
    
    cJSON_Delete(root);
    return true;
}

int serialize_client_action(const char *client_id, const char *process_id,
                          int action, const char *command,
                          char *output, size_t output_size) {
    if (!client_id || !process_id || !output || output_size == 0) {
        return -1;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return -1;
    }
    
    cJSON_AddStringToObject(root, "client_id", client_id);
    cJSON_AddStringToObject(root, "process_id", process_id);
    cJSON_AddNumberToObject(root, "action", action);
    
    if (command) {
        cJSON_AddStringToObject(root, "command", command);
    } else {
        cJSON_AddStringToObject(root, "command", "");
    }
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        return -1;
    }
    
    size_t json_len = strlen(json_str);
    if (json_len >= output_size) {
        free(json_str);
        return -1;
    }
    
    strcpy(output, json_str);
    free(json_str);
    
    return json_len;
}

bool deserialize_client_action(const char *json_str,
                             char *client_id, size_t client_id_size,
                             char *process_id, size_t process_id_size,
                             int *action,
                             char *command, size_t command_size) {
    if (!json_str || !client_id || !process_id || !action || !command) {
        return false;
    }
    
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return false;
    }
    
    /* Get client_id */
    cJSON *client_id_json = cJSON_GetObjectItem(root, "client_id");
    if (!cJSON_IsString(client_id_json) || !client_id_json->valuestring) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(client_id_json->valuestring) >= client_id_size) {
        cJSON_Delete(root);
        return false;
    }
    strcpy(client_id, client_id_json->valuestring);
    
    /* Get process_id */
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
    
    /* Get action */
    cJSON *action_json = cJSON_GetObjectItem(root, "action");
    if (!cJSON_IsNumber(action_json)) {
        cJSON_Delete(root);
        return false;
    }
    *action = action_json->valueint;
    
    /* Get command */
    cJSON *command_json = cJSON_GetObjectItem(root, "command");
    if (cJSON_IsString(command_json) && command_json->valuestring) {
        if (strlen(command_json->valuestring) >= command_size) {
            cJSON_Delete(root);
            return false;
        }
        strcpy(command, command_json->valuestring);
    } else {
        command[0] = '\0';
    }
    
    cJSON_Delete(root);
    return true;
}