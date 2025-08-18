#ifndef MQTT_PROTOCOL_H
#define MQTT_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

// MQTT Protocol Version 3.1.1
#define MQTT_PROTOCOL_VERSION 4
#define MQTT_PROTOCOL_NAME "MQTT"
#define MQTT_PROTOCOL_NAME_LEN 4

/**
 * Check if a topic matches a subscription filter
 * @param filter Topic filter (may contain wildcards)
 * @param topic Topic name
 * @return true if the topic matches the filter, false otherwise
 */
bool mqtt_topic_matches_filter(const char *filter, const char *topic);

// MQTT Message Types
typedef enum {
    MQTT_CONNECT     = 1,
    MQTT_CONNACK     = 2,
    MQTT_PUBLISH     = 3,
    MQTT_PUBACK      = 4,
    MQTT_PUBREC      = 5,
    MQTT_PUBREL      = 6,
    MQTT_PUBCOMP     = 7,
    MQTT_SUBSCRIBE   = 8,
    MQTT_SUBACK      = 9,
    MQTT_UNSUBSCRIBE = 10,
    MQTT_UNSUBACK    = 11,
    MQTT_PINGREQ     = 12,
    MQTT_PINGRESP    = 13,
    MQTT_DISCONNECT  = 14
} mqtt_msg_type_t;

// MQTT QoS Levels
typedef enum {
    MQTT_QOS_0 = 0,  // At most once
    MQTT_QOS_1 = 1,  // At least once
    MQTT_QOS_2 = 2   // Exactly once
} mqtt_qos_t;

// MQTT Connection Return Codes
typedef enum {
    MQTT_CONNACK_ACCEPTED = 0,
    MQTT_CONNACK_REFUSED_PROTOCOL_VERSION = 1,
    MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED = 2,
    MQTT_CONNACK_REFUSED_SERVER_UNAVAILABLE = 3,
    MQTT_CONNACK_REFUSED_BAD_USERNAME_PASSWORD = 4,
    MQTT_CONNACK_REFUSED_NOT_AUTHORIZED = 5
} mqtt_connack_code_t;

// MQTT Fixed Header
typedef struct {
    uint8_t msg_type:4;
    uint8_t dup:1;
    uint8_t qos:2;
    uint8_t retain:1;
    uint32_t remaining_length;
} mqtt_fixed_header_t;

// MQTT Connect Packet
typedef struct {
    char *protocol_name;
    uint8_t protocol_version;
    uint8_t flags;
    uint16_t keep_alive;
    char *client_id;
    char *will_topic;
    char *will_message;
    char *username;
    char *password;
} mqtt_connect_t;

// MQTT Publish Packet
typedef struct {
    char *topic;
    uint16_t packet_id;
    uint8_t *payload;
    uint32_t payload_len;
    mqtt_qos_t qos;
    bool retain;
    bool dup;
} mqtt_publish_t;

// MQTT Subscribe Packet
typedef struct {
    uint16_t packet_id;
    char **topics;
    mqtt_qos_t *qos_levels;
    uint16_t topic_count;
} mqtt_subscribe_t;

// MQTT Unsubscribe Packet
typedef struct {
    uint16_t packet_id;
    char **topics;
    uint16_t topic_count;
} mqtt_unsubscribe_t;

/**
 * Parse MQTT fixed header from buffer
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param header Output header structure
 * @param consumed_bytes Number of bytes consumed
 * @return 0 on success, -1 on error, 1 if more data needed
 */
int mqtt_parse_fixed_header(const uint8_t *buffer, uint32_t buffer_len, 
                           mqtt_fixed_header_t *header, uint32_t *consumed_bytes);

/**
 * Parse MQTT connect packet
 * @param buffer Input buffer (after fixed header)
 * @param buffer_len Buffer length
 * @param connect Output connect structure
 * @return 0 on success, -1 on error
 */
int mqtt_parse_connect(const uint8_t *buffer, uint32_t buffer_len, mqtt_connect_t *connect);

/**
 * Parse MQTT publish packet
 * @param buffer Input buffer (after fixed header)
 * @param buffer_len Buffer length
 * @param header Fixed header (for QoS and flags)
 * @param publish Output publish structure
 * @return 0 on success, -1 on error
 */
int mqtt_parse_publish(const uint8_t *buffer, uint32_t buffer_len, 
                      const mqtt_fixed_header_t *header, mqtt_publish_t *publish);

/**
 * Parse MQTT subscribe packet
 * @param buffer Input buffer (after fixed header)
 * @param buffer_len Buffer length
 * @param subscribe Output subscribe structure
 * @return 0 on success, -1 on error
 */
int mqtt_parse_subscribe(const uint8_t *buffer, uint32_t buffer_len, mqtt_subscribe_t *subscribe);

/**
 * Parse MQTT unsubscribe packet
 * @param buffer Input buffer (after fixed header)
 * @param buffer_len Buffer length
 * @param unsubscribe Output unsubscribe structure
 * @return 0 on success, -1 on error
 */
int mqtt_parse_unsubscribe(const uint8_t *buffer, uint32_t buffer_len, mqtt_unsubscribe_t *unsubscribe);

/**
 * Serialize MQTT CONNACK packet
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param session_present Session present flag
 * @param return_code Connection return code
 * @return Number of bytes written, -1 on error
 */
int mqtt_serialize_connack(uint8_t *buffer, uint32_t buffer_size, 
                          bool session_present, mqtt_connack_code_t return_code);

/**
 * Serialize MQTT PUBLISH packet
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param publish Publish packet data
 * @return Number of bytes written, -1 on error
 */
int mqtt_serialize_publish(uint8_t *buffer, uint32_t buffer_size, const mqtt_publish_t *publish);

/**
 * Serialize MQTT PUBACK packet
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param packet_id Packet identifier
 * @return Number of bytes written, -1 on error
 */
int mqtt_serialize_puback(uint8_t *buffer, uint32_t buffer_size, uint16_t packet_id);

/**
 * Serialize MQTT SUBACK packet
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param packet_id Packet identifier
 * @param return_codes Array of return codes
 * @param count Number of return codes
 * @return Number of bytes written, -1 on error
 */
int mqtt_serialize_suback(uint8_t *buffer, uint32_t buffer_size, uint16_t packet_id, 
                         const uint8_t *return_codes, uint16_t count);

/**
 * Serialize MQTT UNSUBACK packet
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param packet_id Packet identifier
 * @return Number of bytes written, -1 on error
 */
int mqtt_serialize_unsuback(uint8_t *buffer, uint32_t buffer_size, uint16_t packet_id);

/**
 * Serialize MQTT PINGRESP packet
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Number of bytes written, -1 on error
 */
int mqtt_serialize_pingresp(uint8_t *buffer, uint32_t buffer_size);

/**
 * Free MQTT connect packet data
 * @param connect Connect packet to free
 */
void mqtt_free_connect(mqtt_connect_t *connect);

/**
 * Free MQTT publish packet data
 * @param publish Publish packet to free
 */
void mqtt_free_publish(mqtt_publish_t *publish);

/**
 * Free MQTT subscribe packet data
 * @param subscribe Subscribe packet to free
 */
void mqtt_free_subscribe(mqtt_subscribe_t *subscribe);

/**
 * Free MQTT unsubscribe packet data
 * @param unsubscribe Unsubscribe packet to free
 */
void mqtt_free_unsubscribe(mqtt_unsubscribe_t *unsubscribe);

/**
 * Validate topic name according to MQTT specification
 * @param topic Topic name to validate
 * @return true if valid, false otherwise
 */
bool mqtt_validate_topic(const char *topic);

/**
 * Check if topic matches topic filter (with wildcards)
 * @param filter Topic filter (may contain wildcards)
 * @param topic Topic name
 * @return true if matches, false otherwise
 */
bool mqtt_topic_matches_filter(const char *filter, const char *topic);

/**
 * Encode remaining length for MQTT fixed header
 * @param buffer Output buffer
 * @param length Length to encode
 * @return Number of bytes written
 */
int mqtt_encode_remaining_length(uint8_t *buffer, uint32_t length);

/**
 * Decode remaining length from MQTT fixed header
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param length Output length
 * @param consumed_bytes Number of bytes consumed
 * @return 0 on success, -1 on error, 1 if more data needed
 */
int mqtt_decode_remaining_length(const uint8_t *buffer, uint32_t buffer_len, 
                                uint32_t *length, uint32_t *consumed_bytes);

#endif /* MQTT_PROTOCOL_H */
