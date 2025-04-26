#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_TOPICS 32
#define MAX_TOPIC_LENGTH 128
#define MAX_PROCESS_ID_LENGTH 64
#define MAX_URL_LENGTH 128

typedef struct {
    char process_id[MAX_PROCESS_ID_LENGTH];   /* Process identifier */
    char broker_url[MAX_URL_LENGTH];          /* MQTT broker URL */
    uint16_t broker_port;                     /* MQTT broker port */
    char heartbeat_topic[MAX_TOPIC_LENGTH];   /* Topic for sending heartbeats */
    char response_topic[MAX_TOPIC_LENGTH];    /* Topic for sending responses */
    char query_topic[MAX_TOPIC_LENGTH];       /* Topic for receiving queries */
    char pub_topics[MAX_TOPICS][MAX_TOPIC_LENGTH];  /* Topics to publish to */
    int pub_topic_count;                      /* Number of publication topics */
    char sub_topics[MAX_TOPICS][MAX_TOPIC_LENGTH];  /* Topics to subscribe to */
    int sub_topic_count;                      /* Number of subscription topics */
    uint32_t heartbeat_interval;              /* Time between heartbeats in milliseconds */
    uint32_t heartbeat_timeout;               /* Time before considering a client disconnected */
} client_config_t;

/**
 * Load client configuration from JSON file.
 * 
 * @param filepath Path to the JSON configuration file
 * @param config Pointer to config structure to be filled
 * @return bool True on success, false on failure
 */
bool client_config_load(const char* filepath, client_config_t* config);

/**
 * Merge additional pub/sub topics from a separate JSON file.
 * 
 * @param filepath Path to the JSON file with additional topics
 * @param config Pointer to config structure to update
 * @return bool True on success, false on failure
 */
bool client_config_merge_topics(const char* filepath, client_config_t* config);

/**
 * Save client configuration to JSON file.
 * 
 * @param filepath Path to save the JSON configuration file
 * @param config Pointer to config structure to save
 * @return bool True on success, false on failure
 */
bool client_config_save(const char* filepath, const client_config_t* config);

/**
 * Generate a heartbeat message in JSON format.
 * 
 * @param config Client configuration
 * @param client_id MQTT client ID
 * @param status Client status string
 * @param heartbeat_output Buffer to store generated heartbeat message
 * @param output_size Size of the output buffer
 * @return bool True on success, false on failure
 */
bool client_generate_heartbeat(const client_config_t* config, 
                              const char* client_id, 
                              const char* status,
                              char* heartbeat_output,
                              size_t output_size);

/**
 * Print configuration to stdout. Useful for debugging.
 * 
 * @param config Pointer to the config to print
 */
void client_config_print(const client_config_t* config);

#endif /* CLIENT_CONFIG_H */