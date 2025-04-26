#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "client_config.h"

/* Message types for serialization */
typedef enum {
    MESSAGE_TYPE_UNKNOWN = 0,
    MESSAGE_TYPE_MQTT_MESSAGE = 1,
    MESSAGE_TYPE_CLIENT_CONFIG = 2,
    MESSAGE_TYPE_HEARTBEAT = 3,
    MESSAGE_TYPE_CLIENT_ACTION = 4,
    MESSAGE_TYPE_BROKER_CONFIG = 5
} message_type_t;

/**
 * Serialize MQTT message to JSON format
 *
 * @param client_id Client ID associated with the message
 * @param topic Topic of the message
 * @param payload Message payload
 * @param payload_len Length of payload
 * @param qos QoS level
 * @param retain Retain flag
 * @param output Buffer to write serialized message to
 * @param output_size Size of output buffer
 * @return int Number of bytes written, or -1 on error
 */
int serialize_mqtt_message(const char *client_id, const char *topic, 
                         const uint8_t *payload, size_t payload_len,
                         int qos, bool retain,
                         char *output, size_t output_size);

/**
 * Deserialize MQTT message from JSON format
 * 
 * @param json_str JSON string to deserialize
 * @param client_id Buffer to write client ID
 * @param client_id_size Size of client ID buffer
 * @param topic Buffer to write topic
 * @param topic_size Size of topic buffer
 * @param payload Buffer to write payload
 * @param payload_size Size of payload buffer
 * @param payload_len Pointer to variable to store actual payload length
 * @param qos Pointer to variable to store QoS level
 * @param retain Pointer to variable to store retain flag
 * @return bool True on success, false on failure
 */
bool deserialize_mqtt_message(const char *json_str,
                            char *client_id, size_t client_id_size,
                            char *topic, size_t topic_size,
                            uint8_t *payload, size_t payload_size, size_t *payload_len,
                            int *qos, bool *retain);

/**
 * Serialize client config to JSON format
 *
 * @param config Pointer to client config
 * @param output Buffer to write serialized config to
 * @param output_size Size of output buffer
 * @return int Number of bytes written, or -1 on error
 */
int serialize_client_config(const client_config_t *config,
                          char *output, size_t output_size);

/**
 * Deserialize client config from JSON format
 *
 * @param json_str JSON string to deserialize
 * @param config Pointer to client config to fill
 * @return bool True on success, false on failure
 */
bool deserialize_client_config(const char *json_str, client_config_t *config);

/**
 * Serialize heartbeat message to JSON format
 *
 * @param client_id Client ID
 * @param process_id Process ID
 * @param status Status message
 * @param output Buffer to write serialized heartbeat to
 * @param output_size Size of output buffer
 * @return int Number of bytes written, or -1 on error
 */
int serialize_heartbeat(const char *client_id, const char *process_id,
                      const char *status,
                      char *output, size_t output_size);

/**
 * Deserialize heartbeat message from JSON format
 *
 * @param json_str JSON string to deserialize
 * @param client_id Buffer to write client ID
 * @param client_id_size Size of client ID buffer
 * @param process_id Buffer to write process ID
 * @param process_id_size Size of process ID buffer
 * @param status Buffer to write status
 * @param status_size Size of status buffer
 * @param timestamp Pointer to variable to store timestamp
 * @return bool True on success, false on failure
 */
bool deserialize_heartbeat(const char *json_str,
                         char *client_id, size_t client_id_size,
                         char *process_id, size_t process_id_size,
                         char *status, size_t status_size,
                         int64_t *timestamp);

/**
 * Serialize client action to JSON format
 *
 * @param client_id Client ID
 * @param process_id Process ID
 * @param action Action type
 * @param command Command to execute
 * @param output Buffer to write serialized action to
 * @param output_size Size of output buffer
 * @return int Number of bytes written, or -1 on error
 */
int serialize_client_action(const char *client_id, const char *process_id,
                          int action, const char *command,
                          char *output, size_t output_size);

/**
 * Deserialize client action from JSON format
 *
 * @param json_str JSON string to deserialize
 * @param client_id Buffer to write client ID
 * @param client_id_size Size of client ID buffer
 * @param process_id Buffer to write process ID
 * @param process_id_size Size of process ID buffer
 * @param action Pointer to variable to store action type
 * @param command Buffer to write command
 * @param command_size Size of command buffer
 * @return bool True on success, false on failure
 */
bool deserialize_client_action(const char *json_str,
                             char *client_id, size_t client_id_size,
                             char *process_id, size_t process_id_size,
                             int *action,
                             char *command, size_t command_size);

#endif /* SERIALIZATION_H */