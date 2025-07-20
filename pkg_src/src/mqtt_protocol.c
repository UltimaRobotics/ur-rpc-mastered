#include "mqtt_protocol.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// Helper function to read string from buffer
static int read_string(const uint8_t *buffer, uint32_t buffer_len, uint32_t *offset, char **str) {
    if (*offset + 2 > buffer_len) return -1;
    
    uint16_t len = ntohs(*(uint16_t*)(buffer + *offset));
    *offset += 2;
    
    if (*offset + len > buffer_len) return -1;
    
    *str = malloc(len + 1);
    if (!*str) return -1;
    
    memcpy(*str, buffer + *offset, len);
    (*str)[len] = '\0';
    *offset += len;
    
    return 0;
}

// Helper function to write string to buffer
static int write_string(uint8_t *buffer, uint32_t buffer_size, uint32_t *offset, const char *str) {
    uint16_t len = str ? strlen(str) : 0;
    
    if (*offset + 2 + len > buffer_size) return -1;
    
    *(uint16_t*)(buffer + *offset) = htons(len);
    *offset += 2;
    
    if (len > 0) {
        memcpy(buffer + *offset, str, len);
        *offset += len;
    }
    
    return 0;
}

int mqtt_decode_remaining_length(const uint8_t *buffer, uint32_t buffer_len, 
                                uint32_t *length, uint32_t *consumed_bytes) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint32_t offset = 0;
    uint8_t byte;
    
    do {
        if (offset >= buffer_len) return 1; // Need more data
        if (offset >= 4) return -1; // Invalid encoding
        
        byte = buffer[offset++];
        value += (byte & 0x7F) * multiplier;
        
        if (multiplier > 128 * 128 * 128) return -1; // Invalid encoding
        multiplier *= 128;
    } while ((byte & 0x80) != 0);
    
    *length = value;
    *consumed_bytes = offset;
    return 0;
}

int mqtt_encode_remaining_length(uint8_t *buffer, uint32_t length) {
    int bytes = 0;
    
    do {
        uint8_t byte = length % 128;
        length /= 128;
        if (length > 0) {
            byte |= 0x80;
        }
        buffer[bytes++] = byte;
    } while (length > 0 && bytes < 4);
    
    return bytes;
}

int mqtt_parse_fixed_header(const uint8_t *buffer, uint32_t buffer_len, 
                           mqtt_fixed_header_t *header, uint32_t *consumed_bytes) {
    if (buffer_len < 2) return 1; // Need at least 2 bytes
    
    uint8_t first_byte = buffer[0];
    header->msg_type = (first_byte >> 4) & 0x0F;
    header->dup = (first_byte >> 3) & 0x01;
    header->qos = (first_byte >> 1) & 0x03;
    header->retain = first_byte & 0x01;
    
    uint32_t remaining_len_bytes;
    int result = mqtt_decode_remaining_length(buffer + 1, buffer_len - 1, 
                                            &header->remaining_length, &remaining_len_bytes);
    if (result != 0) return result;
    
    *consumed_bytes = 1 + remaining_len_bytes;
    return 0;
}

int mqtt_parse_connect(const uint8_t *buffer, uint32_t buffer_len, mqtt_connect_t *connect) {
    memset(connect, 0, sizeof(mqtt_connect_t));
    uint32_t offset = 0;
    
    // Protocol name
    if (read_string(buffer, buffer_len, &offset, &connect->protocol_name) != 0) {
        return -1;
    }
    
    // Check protocol name
    if (strcmp(connect->protocol_name, MQTT_PROTOCOL_NAME) != 0) {
        mqtt_free_connect(connect);
        return -1;
    }
    
    // Protocol version
    if (offset >= buffer_len) {
        mqtt_free_connect(connect);
        return -1;
    }
    connect->protocol_version = buffer[offset++];
    
    // Connect flags
    if (offset >= buffer_len) {
        mqtt_free_connect(connect);
        return -1;
    }
    connect->flags = buffer[offset++];
    
    // Keep alive
    if (offset + 2 > buffer_len) {
        mqtt_free_connect(connect);
        return -1;
    }
    connect->keep_alive = ntohs(*(uint16_t*)(buffer + offset));
    offset += 2;
    
    // Client ID
    if (read_string(buffer, buffer_len, &offset, &connect->client_id) != 0) {
        mqtt_free_connect(connect);
        return -1;
    }
    
    // Will topic and message
    if (connect->flags & 0x04) { // Will flag
        if (read_string(buffer, buffer_len, &offset, &connect->will_topic) != 0) {
            mqtt_free_connect(connect);
            return -1;
        }
        if (read_string(buffer, buffer_len, &offset, &connect->will_message) != 0) {
            mqtt_free_connect(connect);
            return -1;
        }
    }
    
    // Username
    if (connect->flags & 0x80) { // Username flag
        if (read_string(buffer, buffer_len, &offset, &connect->username) != 0) {
            mqtt_free_connect(connect);
            return -1;
        }
    }
    
    // Password
    if (connect->flags & 0x40) { // Password flag
        if (read_string(buffer, buffer_len, &offset, &connect->password) != 0) {
            mqtt_free_connect(connect);
            return -1;
        }
    }
    
    return 0;
}

int mqtt_parse_publish(const uint8_t *buffer, uint32_t buffer_len, 
                      const mqtt_fixed_header_t *header, mqtt_publish_t *publish) {
    memset(publish, 0, sizeof(mqtt_publish_t));
    uint32_t offset = 0;
    
    publish->qos = header->qos;
    publish->retain = header->retain;
    publish->dup = header->dup;
    
    // Topic name
    if (read_string(buffer, buffer_len, &offset, &publish->topic) != 0) {
        return -1;
    }
    
    // Packet identifier (for QoS > 0)
    if (publish->qos > 0) {
        if (offset + 2 > buffer_len) {
            mqtt_free_publish(publish);
            return -1;
        }
        publish->packet_id = ntohs(*(uint16_t*)(buffer + offset));
        offset += 2;
    }
    
    // Payload
    publish->payload_len = buffer_len - offset;
    if (publish->payload_len > 0) {
        publish->payload = malloc(publish->payload_len);
        if (!publish->payload) {
            mqtt_free_publish(publish);
            return -1;
        }
        memcpy(publish->payload, buffer + offset, publish->payload_len);
    }
    
    return 0;
}

int mqtt_parse_subscribe(const uint8_t *buffer, uint32_t buffer_len, mqtt_subscribe_t *subscribe) {
    memset(subscribe, 0, sizeof(mqtt_subscribe_t));
    uint32_t offset = 0;
    
    // Packet identifier
    if (offset + 2 > buffer_len) return -1;
    subscribe->packet_id = ntohs(*(uint16_t*)(buffer + offset));
    offset += 2;
    
    // Count topics first
    uint32_t temp_offset = offset;
    uint16_t count = 0;
    while (temp_offset < buffer_len) {
        uint16_t len;
        if (temp_offset + 2 > buffer_len) break;
        len = ntohs(*(uint16_t*)(buffer + temp_offset));
        temp_offset += 2 + len + 1; // +1 for QoS byte
        count++;
    }
    
    if (count == 0) return -1;
    
    // Allocate arrays
    subscribe->topics = malloc(count * sizeof(char*));
    subscribe->qos_levels = malloc(count * sizeof(mqtt_qos_t));
    if (!subscribe->topics || !subscribe->qos_levels) {
        mqtt_free_subscribe(subscribe);
        return -1;
    }
    memset(subscribe->topics, 0, count * sizeof(char*));
    
    // Parse topics and QoS levels
    for (uint16_t i = 0; i < count && offset < buffer_len; i++) {
        if (read_string(buffer, buffer_len, &offset, &subscribe->topics[i]) != 0) {
            subscribe->topic_count = i;
            mqtt_free_subscribe(subscribe);
            return -1;
        }
        
        if (offset >= buffer_len) {
            subscribe->topic_count = i + 1;
            mqtt_free_subscribe(subscribe);
            return -1;
        }
        
        subscribe->qos_levels[i] = buffer[offset++];
        if (subscribe->qos_levels[i] > 2) {
            subscribe->topic_count = i + 1;
            mqtt_free_subscribe(subscribe);
            return -1;
        }
    }
    
    subscribe->topic_count = count;
    return 0;
}

int mqtt_parse_unsubscribe(const uint8_t *buffer, uint32_t buffer_len, mqtt_unsubscribe_t *unsubscribe) {
    memset(unsubscribe, 0, sizeof(mqtt_unsubscribe_t));
    uint32_t offset = 0;
    
    // Packet identifier
    if (offset + 2 > buffer_len) return -1;
    unsubscribe->packet_id = ntohs(*(uint16_t*)(buffer + offset));
    offset += 2;
    
    // Count topics first
    uint32_t temp_offset = offset;
    uint16_t count = 0;
    while (temp_offset < buffer_len) {
        uint16_t len;
        if (temp_offset + 2 > buffer_len) break;
        len = ntohs(*(uint16_t*)(buffer + temp_offset));
        temp_offset += 2 + len;
        count++;
    }
    
    if (count == 0) return -1;
    
    // Allocate array
    unsubscribe->topics = malloc(count * sizeof(char*));
    if (!unsubscribe->topics) return -1;
    memset(unsubscribe->topics, 0, count * sizeof(char*));
    
    // Parse topics
    for (uint16_t i = 0; i < count && offset < buffer_len; i++) {
        if (read_string(buffer, buffer_len, &offset, &unsubscribe->topics[i]) != 0) {
            unsubscribe->topic_count = i;
            mqtt_free_unsubscribe(unsubscribe);
            return -1;
        }
    }
    
    unsubscribe->topic_count = count;
    return 0;
}

int mqtt_serialize_connack(uint8_t *buffer, uint32_t buffer_size, 
                          bool session_present, mqtt_connack_code_t return_code) {
    if (buffer_size < 4) return -1;
    
    buffer[0] = (MQTT_CONNACK << 4); // Fixed header
    buffer[1] = 2; // Remaining length
    buffer[2] = session_present ? 1 : 0; // Connect acknowledge flags
    buffer[3] = return_code; // Connect return code
    
    return 4;
}

int mqtt_serialize_publish(uint8_t *buffer, uint32_t buffer_size, const mqtt_publish_t *publish) {
    uint32_t offset = 0;
    
    // Calculate remaining length
    uint32_t topic_len = strlen(publish->topic);
    uint32_t remaining_len = 2 + topic_len + publish->payload_len;
    if (publish->qos > 0) remaining_len += 2; // Packet ID
    
    // Fixed header
    if (offset >= buffer_size) return -1;
    uint8_t first_byte = (MQTT_PUBLISH << 4);
    if (publish->dup) first_byte |= 0x08;
    first_byte |= (publish->qos << 1);
    if (publish->retain) first_byte |= 0x01;
    buffer[offset++] = first_byte;
    
    // Remaining length
    int remaining_len_bytes = mqtt_encode_remaining_length(buffer + offset, remaining_len);
    offset += remaining_len_bytes;
    
    if (offset + remaining_len > buffer_size) return -1;
    
    // Topic name
    if (write_string(buffer, buffer_size, &offset, publish->topic) != 0) return -1;
    
    // Packet identifier (for QoS > 0)
    if (publish->qos > 0) {
        *(uint16_t*)(buffer + offset) = htons(publish->packet_id);
        offset += 2;
    }
    
    // Payload
    if (publish->payload_len > 0) {
        memcpy(buffer + offset, publish->payload, publish->payload_len);
        offset += publish->payload_len;
    }
    
    return offset;
}

int mqtt_serialize_puback(uint8_t *buffer, uint32_t buffer_size, uint16_t packet_id) {
    if (buffer_size < 4) return -1;
    
    buffer[0] = (MQTT_PUBACK << 4); // Fixed header
    buffer[1] = 2; // Remaining length
    *(uint16_t*)(buffer + 2) = htons(packet_id);
    
    return 4;
}

int mqtt_serialize_suback(uint8_t *buffer, uint32_t buffer_size, uint16_t packet_id, 
                         const uint8_t *return_codes, uint16_t count) {
    uint32_t remaining_len = 2 + count;
    if (buffer_size < 2 + remaining_len) return -1;
    
    uint32_t offset = 0;
    
    // Fixed header
    buffer[offset++] = (MQTT_SUBACK << 4);
    offset += mqtt_encode_remaining_length(buffer + offset, remaining_len);
    
    // Packet identifier
    *(uint16_t*)(buffer + offset) = htons(packet_id);
    offset += 2;
    
    // Return codes
    memcpy(buffer + offset, return_codes, count);
    offset += count;
    
    return offset;
}

int mqtt_serialize_unsuback(uint8_t *buffer, uint32_t buffer_size, uint16_t packet_id) {
    if (buffer_size < 4) return -1;
    
    buffer[0] = (MQTT_UNSUBACK << 4); // Fixed header
    buffer[1] = 2; // Remaining length
    *(uint16_t*)(buffer + 2) = htons(packet_id);
    
    return 4;
}

int mqtt_serialize_pingresp(uint8_t *buffer, uint32_t buffer_size) {
    if (buffer_size < 2) return -1;
    
    buffer[0] = (MQTT_PINGRESP << 4); // Fixed header
    buffer[1] = 0; // Remaining length
    
    return 2;
}

void mqtt_free_connect(mqtt_connect_t *connect) {
    if (!connect) return;
    
    free(connect->protocol_name);
    free(connect->client_id);
    free(connect->will_topic);
    free(connect->will_message);
    free(connect->username);
    free(connect->password);
    
    memset(connect, 0, sizeof(mqtt_connect_t));
}

void mqtt_free_publish(mqtt_publish_t *publish) {
    if (!publish) return;
    
    free(publish->topic);
    free(publish->payload);
    
    memset(publish, 0, sizeof(mqtt_publish_t));
}

void mqtt_free_subscribe(mqtt_subscribe_t *subscribe) {
    if (!subscribe) return;
    
    if (subscribe->topics) {
        for (uint16_t i = 0; i < subscribe->topic_count; i++) {
            free(subscribe->topics[i]);
        }
        free(subscribe->topics);
    }
    free(subscribe->qos_levels);
    
    memset(subscribe, 0, sizeof(mqtt_subscribe_t));
}

void mqtt_free_unsubscribe(mqtt_unsubscribe_t *unsubscribe) {
    if (!unsubscribe) return;
    
    if (unsubscribe->topics) {
        for (uint16_t i = 0; i < unsubscribe->topic_count; i++) {
            free(unsubscribe->topics[i]);
        }
        free(unsubscribe->topics);
    }
    
    memset(unsubscribe, 0, sizeof(mqtt_unsubscribe_t));
}

bool mqtt_validate_topic(const char *topic) {
    if (!topic || strlen(topic) == 0 || strlen(topic) > 65535) return false;
    
    // Check for invalid characters
    for (const char *p = topic; *p; p++) {
        if (*p == '+' || *p == '#') return false; // Wildcards not allowed in topic names
        if (*p < 0x20 && *p != 0x09) return false; // Control characters except tab
        if (*p == 0x7F) return false; // DEL character
    }
    
    return true;
}

bool mqtt_topic_matches_filter(const char *filter, const char *topic) {
    if (!filter || !topic) return false;
    
    const char *f = filter;
    const char *t = topic;
    
    while (*f && *t) {
        if (*f == '#') {
            return true; // Multi-level wildcard matches everything from this point
        } else if (*f == '+') {
            // Single-level wildcard
            while (*t && *t != '/') t++;
            while (*f && *f != '/') f++;
        } else if (*f == *t) {
            f++;
            t++;
        } else {
            return false;
        }
    }
    
    // Handle end cases
    if (*f == '#') return true;
    if (*f == '\0' && *t == '\0') return true;
    
    return false;
}
