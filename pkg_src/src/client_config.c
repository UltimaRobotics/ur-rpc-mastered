#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "client_config.h"
#include "json/cJSON.h"

bool client_config_load(const char* filepath, client_config_t* config) {
    FILE* file = fopen(filepath, "r");
    if (!file) {
        fprintf(stderr, "Error: Unable to open config file %s\n", filepath);
        return false;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate memory for the file content
    char* json_data = (char*)malloc(file_size + 1);
    if (!json_data) {
        fprintf(stderr, "Error: Memory allocation failed for config file content\n");
        fclose(file);
        return false;
    }
    
    // Read file content
    size_t read_size = fread(json_data, 1, file_size, file);
    fclose(file);
    
    json_data[read_size] = '\0';
    
    // Parse JSON
    cJSON* root = cJSON_Parse(json_data);
    free(json_data);
    
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON in config file: %s\n", cJSON_GetErrorPtr());
        return false;
    }
    
    // Initialize config with defaults
    memset(config, 0, sizeof(client_config_t));
    
    // Set default values
    strcpy(config->process_id, "unknown");
    strcpy(config->broker_url, "localhost");
    config->broker_port = 1883;
    strcpy(config->heartbeat_topic, "heartbeat");
    strcpy(config->response_topic, "response");
    strcpy(config->query_topic, "query");
    config->heartbeat_interval = 5000;  // 5 seconds
    config->heartbeat_timeout = 15000;  // 15 seconds
    
    // Process id
    cJSON* process_id = cJSON_GetObjectItem(root, "process_id");
    if (cJSON_IsString(process_id) && process_id->valuestring) {
        strncpy(config->process_id, process_id->valuestring, MAX_PROCESS_ID_LENGTH - 1);
    }
    
    // Broker URL
    cJSON* broker_url = cJSON_GetObjectItem(root, "broker_url");
    if (cJSON_IsString(broker_url) && broker_url->valuestring) {
        strncpy(config->broker_url, broker_url->valuestring, MAX_URL_LENGTH - 1);
    }
    
    // Broker port
    cJSON* broker_port = cJSON_GetObjectItem(root, "broker_port");
    if (cJSON_IsNumber(broker_port)) {
        config->broker_port = (uint16_t)broker_port->valueint;
    }
    
    // Heartbeat topic
    cJSON* heartbeat_topic = cJSON_GetObjectItem(root, "heartbeat_topic");
    if (cJSON_IsString(heartbeat_topic) && heartbeat_topic->valuestring) {
        strncpy(config->heartbeat_topic, heartbeat_topic->valuestring, MAX_TOPIC_LENGTH - 1);
    }
    
    // Response topic
    cJSON* response_topic = cJSON_GetObjectItem(root, "response_topic");
    if (cJSON_IsString(response_topic) && response_topic->valuestring) {
        strncpy(config->response_topic, response_topic->valuestring, MAX_TOPIC_LENGTH - 1);
    }
    
    // Query topic
    cJSON* query_topic = cJSON_GetObjectItem(root, "query_topic");
    if (cJSON_IsString(query_topic) && query_topic->valuestring) {
        strncpy(config->query_topic, query_topic->valuestring, MAX_TOPIC_LENGTH - 1);
    }
    
    // Heartbeat interval
    cJSON* heartbeat_interval = cJSON_GetObjectItem(root, "heartbeat_interval");
    if (cJSON_IsNumber(heartbeat_interval)) {
        config->heartbeat_interval = (uint32_t)heartbeat_interval->valueint;
    }
    
    // Heartbeat timeout
    cJSON* heartbeat_timeout = cJSON_GetObjectItem(root, "heartbeat_timeout");
    if (cJSON_IsNumber(heartbeat_timeout)) {
        config->heartbeat_timeout = (uint32_t)heartbeat_timeout->valueint;
    }
    
    // Publication topics
    cJSON* pub_topics_obj = cJSON_GetObjectItem(root, "json_added_pubs");
    if (pub_topics_obj) {
        cJSON* topics_array = cJSON_GetObjectItem(pub_topics_obj, "topics");
        if (cJSON_IsArray(topics_array)) {
            int topic_count = 0;
            cJSON* topic_item = NULL;
            
            cJSON_ArrayForEach(topic_item, topics_array) {
                if (cJSON_IsString(topic_item) && topic_item->valuestring && topic_count < MAX_TOPICS) {
                    strncpy(config->pub_topics[topic_count], topic_item->valuestring, MAX_TOPIC_LENGTH - 1);
                    topic_count++;
                }
            }
            
            config->pub_topic_count = topic_count;
        }
    }
    
    // Subscription topics
    cJSON* sub_topics_obj = cJSON_GetObjectItem(root, "json_added_subs");
    if (sub_topics_obj) {
        cJSON* topics_array = cJSON_GetObjectItem(sub_topics_obj, "topics");
        if (cJSON_IsArray(topics_array)) {
            int topic_count = 0;
            cJSON* topic_item = NULL;
            
            cJSON_ArrayForEach(topic_item, topics_array) {
                if (cJSON_IsString(topic_item) && topic_item->valuestring && topic_count < MAX_TOPICS) {
                    strncpy(config->sub_topics[topic_count], topic_item->valuestring, MAX_TOPIC_LENGTH - 1);
                    topic_count++;
                }
            }
            
            config->sub_topic_count = topic_count;
        }
    }
    
    cJSON_Delete(root);
    return true;
}

bool client_config_merge_topics(const char* filepath, client_config_t* config) {
    FILE* file = fopen(filepath, "r");
    if (!file) {
        fprintf(stderr, "Error: Unable to open additional topics file %s\n", filepath);
        return false;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate memory for the file content
    char* json_data = (char*)malloc(file_size + 1);
    if (!json_data) {
        fprintf(stderr, "Error: Memory allocation failed for topics file content\n");
        fclose(file);
        return false;
    }
    
    // Read file content
    size_t read_size = fread(json_data, 1, file_size, file);
    fclose(file);
    
    json_data[read_size] = '\0';
    
    // Parse JSON
    cJSON* root = cJSON_Parse(json_data);
    free(json_data);
    
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON in topics file: %s\n", cJSON_GetErrorPtr());
        return false;
    }
    
    // Publication topics
    cJSON* pub_topics_obj = cJSON_GetObjectItem(root, "json_added_pubs");
    if (pub_topics_obj) {
        cJSON* topics_array = cJSON_GetObjectItem(pub_topics_obj, "topics");
        if (cJSON_IsArray(topics_array)) {
            cJSON* topic_item = NULL;
            
            cJSON_ArrayForEach(topic_item, topics_array) {
                if (cJSON_IsString(topic_item) && topic_item->valuestring && 
                    config->pub_topic_count < MAX_TOPICS) {
                    
                    // Check for duplicates
                    bool is_duplicate = false;
                    for (int i = 0; i < config->pub_topic_count; i++) {
                        if (strcmp(config->pub_topics[i], topic_item->valuestring) == 0) {
                            is_duplicate = true;
                            break;
                        }
                    }
                    
                    if (!is_duplicate) {
                        strncpy(config->pub_topics[config->pub_topic_count], 
                                topic_item->valuestring, 
                                MAX_TOPIC_LENGTH - 1);
                        config->pub_topic_count++;
                    }
                }
            }
        }
    }
    
    // Subscription topics
    cJSON* sub_topics_obj = cJSON_GetObjectItem(root, "json_added_subs");
    if (sub_topics_obj) {
        cJSON* topics_array = cJSON_GetObjectItem(sub_topics_obj, "topics");
        if (cJSON_IsArray(topics_array)) {
            cJSON* topic_item = NULL;
            
            cJSON_ArrayForEach(topic_item, topics_array) {
                if (cJSON_IsString(topic_item) && topic_item->valuestring && 
                    config->sub_topic_count < MAX_TOPICS) {
                    
                    // Check for duplicates
                    bool is_duplicate = false;
                    for (int i = 0; i < config->sub_topic_count; i++) {
                        if (strcmp(config->sub_topics[i], topic_item->valuestring) == 0) {
                            is_duplicate = true;
                            break;
                        }
                    }
                    
                    if (!is_duplicate) {
                        strncpy(config->sub_topics[config->sub_topic_count], 
                                topic_item->valuestring, 
                                MAX_TOPIC_LENGTH - 1);
                        config->sub_topic_count++;
                    }
                }
            }
        }
    }
    
    cJSON_Delete(root);
    return true;
}

bool client_config_save(const char* filepath, const client_config_t* config) {
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return false;
    }
    
    cJSON_AddStringToObject(root, "process_id", config->process_id);
    cJSON_AddStringToObject(root, "broker_url", config->broker_url);
    cJSON_AddNumberToObject(root, "broker_port", config->broker_port);
    cJSON_AddStringToObject(root, "heartbeat_topic", config->heartbeat_topic);
    cJSON_AddStringToObject(root, "response_topic", config->response_topic);
    cJSON_AddStringToObject(root, "query_topic", config->query_topic);
    cJSON_AddNumberToObject(root, "heartbeat_interval", config->heartbeat_interval);
    cJSON_AddNumberToObject(root, "heartbeat_timeout", config->heartbeat_timeout);
    
    // Publication topics
    cJSON* pub_topics_obj = cJSON_CreateObject();
    cJSON* pub_topics_array = cJSON_CreateArray();
    
    for (int i = 0; i < config->pub_topic_count; i++) {
        cJSON_AddItemToArray(pub_topics_array, cJSON_CreateString(config->pub_topics[i]));
    }
    
    cJSON_AddItemToObject(pub_topics_obj, "topics", pub_topics_array);
    cJSON_AddItemToObject(root, "json_added_pubs", pub_topics_obj);
    
    // Subscription topics
    cJSON* sub_topics_obj = cJSON_CreateObject();
    cJSON* sub_topics_array = cJSON_CreateArray();
    
    for (int i = 0; i < config->sub_topic_count; i++) {
        cJSON_AddItemToArray(sub_topics_array, cJSON_CreateString(config->sub_topics[i]));
    }
    
    cJSON_AddItemToObject(sub_topics_obj, "topics", sub_topics_array);
    cJSON_AddItemToObject(root, "json_added_subs", sub_topics_obj);
    
    // Convert to formatted string
    char* json_str = cJSON_Print(root);
    if (!json_str) {
        fprintf(stderr, "Error: Failed to generate JSON string\n");
        cJSON_Delete(root);
        return false;
    }
    
    // Write to file
    FILE* file = fopen(filepath, "w");
    if (!file) {
        fprintf(stderr, "Error: Unable to open file %s for writing\n", filepath);
        free(json_str);
        cJSON_Delete(root);
        return false;
    }
    
    fprintf(file, "%s\n", json_str);
    fclose(file);
    
    free(json_str);
    cJSON_Delete(root);
    return true;
}

bool client_generate_heartbeat(const client_config_t* config, 
                              const char* client_id, 
                              const char* status,
                              char* heartbeat_output,
                              size_t output_size) {
    if (!config || !client_id || !status || !heartbeat_output || output_size == 0) {
        return false;
    }
    
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return false;
    }
    
    cJSON_AddStringToObject(root, "client_id", client_id);
    cJSON_AddStringToObject(root, "process_id", config->process_id);
    cJSON_AddNumberToObject(root, "timestamp", (double)time(NULL));
    cJSON_AddStringToObject(root, "status", status);
    
    char* json_str = cJSON_PrintUnformatted(root);
    if (!json_str) {
        cJSON_Delete(root);
        return false;
    }
    
    if (strlen(json_str) >= output_size) {
        free(json_str);
        cJSON_Delete(root);
        return false;
    }
    
    strcpy(heartbeat_output, json_str);
    
    free(json_str);
    cJSON_Delete(root);
    return true;
}

void client_config_print(const client_config_t* config) {
    printf("Client Configuration:\n");
    printf("  Process ID: %s\n", config->process_id);
    printf("  Broker URL: %s\n", config->broker_url);
    printf("  Broker Port: %u\n", config->broker_port);
    printf("  Heartbeat Topic: %s\n", config->heartbeat_topic);
    printf("  Response Topic: %s\n", config->response_topic);
    printf("  Query Topic: %s\n", config->query_topic);
    printf("  Heartbeat Interval: %u ms\n", config->heartbeat_interval);
    printf("  Heartbeat Timeout: %u ms\n", config->heartbeat_timeout);
    
    printf("  Publication Topics (%d):\n", config->pub_topic_count);
    for (int i = 0; i < config->pub_topic_count; i++) {
        printf("    %d. %s\n", i + 1, config->pub_topics[i]);
    }
    
    printf("  Subscription Topics (%d):\n", config->sub_topic_count);
    for (int i = 0; i < config->sub_topic_count; i++) {
        printf("    %d. %s\n", i + 1, config->sub_topics[i]);
    }
}