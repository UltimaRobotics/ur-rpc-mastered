#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include "client_manager.h"
#include "mqtt_protocol.h"

// Forward declaration
struct mqtt_broker;

/**
 * Process incoming data from client
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @return 0 on success, -1 on error
 */
int message_handler_process_client(mqtt_client_t *client, mqtt_broker_t *broker);

/**
 * Handle MQTT CONNECT packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param connect Parsed connect packet
 * @return 0 on success, -1 on error
 */
int message_handler_connect(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_connect_t *connect);

/**
 * Handle MQTT PUBLISH packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param publish Parsed publish packet
 * @return 0 on success, -1 on error
 */
int message_handler_publish(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_publish_t *publish);

/**
 * Handle MQTT SUBSCRIBE packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param subscribe Parsed subscribe packet
 * @return 0 on success, -1 on error
 */
int message_handler_subscribe(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_subscribe_t *subscribe);

/**
 * Handle MQTT UNSUBSCRIBE packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param unsubscribe Parsed unsubscribe packet
 * @return 0 on success, -1 on error
 */
int message_handler_unsubscribe(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_unsubscribe_t *unsubscribe);

/**
 * Handle MQTT PUBACK packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param packet_id Packet identifier
 * @return 0 on success, -1 on error
 */
int message_handler_puback(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id);

/**
 * Handle MQTT PUBREC packet (QoS 2)
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param packet_id Packet identifier
 * @return 0 on success, -1 on error
 */
int message_handler_pubrec(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id);

/**
 * Handle certificate generation request
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param topic Certificate request topic
 * @param payload Request payload
 * @param payload_len Payload length
 * @return 0 on success, -1 on error
 */
int message_handler_cert_request(mqtt_client_t *client, mqtt_broker_t *broker, 
                                const char *topic, const char *payload, size_t payload_len);

/**
 * Handle certificate list request
 * @param client Pointer to client structure  
 * @param broker Pointer to broker structure
 * @return 0 on success, -1 on error
 */
int message_handler_cert_list(mqtt_client_t *client, mqtt_broker_t *broker);

/**
 * Handle certificate revoke request
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param payload Revoke request payload
 * @return 0 on success, -1 on error
 */
int message_handler_cert_revoke(mqtt_client_t *client, mqtt_broker_t *broker, const char *payload);

/**
 * Handle MQTT PUBREL packet (QoS 2)
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param packet_id Packet identifier
 * @return 0 on success, -1 on error
 */
int message_handler_pubrel(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id);

/**
 * Handle MQTT PUBCOMP packet (QoS 2)
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param packet_id Packet identifier
 * @return 0 on success, -1 on error
 */
int message_handler_pubcomp(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id);

/**
 * Handle MQTT PINGREQ packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @return 0 on success, -1 on error
 */
int message_handler_pingreq(mqtt_client_t *client, mqtt_broker_t *broker);

/**
 * Handle certificate generation request
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param topic Request topic
 * @param payload JSON request payload
 * @param payload_len Payload length
 * @return 0 on success, -1 on error
 */
int message_handler_cert_request(mqtt_client_t *client, mqtt_broker_t *broker, 
                                const char *topic, const char *payload, size_t payload_len);

/**
 * Send certificate response to client
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param response_json JSON response payload
 * @return 0 on success, -1 on error
 */
int message_handler_send_cert_response(mqtt_client_t *client, mqtt_broker_t *broker, 
                                      const char *response_json);

/**
 * Handle certificate list request
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @return 0 on success, -1 on error
 */
int message_handler_cert_list(mqtt_client_t *client, mqtt_broker_t *broker);

/**
 * Handle certificate revocation request
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @param payload JSON revocation request payload
 * @return 0 on success, -1 on error
 */
int message_handler_cert_revoke(mqtt_client_t *client, mqtt_broker_t *broker, const char *payload);

/**
 * Handle MQTT DISCONNECT packet
 * @param client Pointer to client structure
 * @param broker Pointer to broker structure
 * @return 0 on success, -1 on error
 */
int message_handler_disconnect(mqtt_client_t *client, mqtt_broker_t *broker);

/**
 * Send message to all subscribed clients
 * @param broker Pointer to broker structure
 * @param topic Topic name
 * @param payload Message payload
 * @param payload_len Payload length
 * @param qos Quality of Service level
 * @param retain Retain flag
 * @param sender_client Sending client (NULL for broker messages)
 * @return Number of clients message was sent to
 */
int message_handler_broadcast(mqtt_broker_t *broker, const char *topic, 
                             const uint8_t *payload, uint32_t payload_len,
                             uint8_t qos, bool retain, mqtt_client_t *sender_client);

/**
 * Send will message for disconnected client
 * @param broker Pointer to broker structure
 * @param client Pointer to client structure
 * @return 0 on success, -1 on error
 */
int message_handler_publish_will(mqtt_broker_t *broker, mqtt_client_t *client);

/**
 * Send MQTT packet to client
 * @param client Pointer to client structure
 * @param data Packet data
 * @param length Data length
 * @return 0 on success, -1 on error
 */
int message_handler_send_packet(mqtt_client_t *client, const uint8_t *data, uint32_t length);

/**
 * Validate client credentials
 * @param broker Pointer to broker structure
 * @param username Username (may be NULL)
 * @param password Password (may be NULL)
 * @return true if valid, false otherwise
 */
bool message_handler_authenticate(mqtt_broker_t *broker, const char *username, const char *password);

/**
 * Check if topic is authorized for client
 * @param broker Pointer to broker structure
 * @param client Pointer to client structure
 * @param topic Topic name
 * @param action Action type (0=read, 1=write)
 * @return true if authorized, false otherwise
 */
bool message_handler_authorize_topic(mqtt_broker_t *broker, mqtt_client_t *client, const char *topic, int action);

/**
 * Handle retained messages for new subscription
 * @param broker Pointer to broker structure
 * @param client Pointer to client structure
 * @param topic_filter Topic filter
 * @param qos Quality of Service level
 * @return Number of retained messages sent
 */
int message_handler_send_retained(mqtt_broker_t *broker, mqtt_client_t *client, const char *topic_filter, uint8_t qos);

#endif /* MESSAGE_HANDLER_H */
