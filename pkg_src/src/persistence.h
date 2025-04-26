/**
 * @file persistence.h
 * @brief Persistence utilities for MQTT broker
 */

#ifndef PERSISTENCE_H
#define PERSISTENCE_H

/**
 * Initialize the persistence system
 * @param persistence_dir The persistence directory
 * @return 0 on success, non-zero on error
 */
int persistence_init(const char *persistence_dir);

/**
 * Clean up the persistence system
 */
void persistence_cleanup(void);

/**
 * Save a message to persistent storage
 * @param client_id The client ID
 * @param topic The topic
 * @param payload The payload
 * @param payload_len The payload length
 * @param qos The QoS level
 * @param retain Whether the message is retained
 * @return 0 on success, non-zero on error
 */
int persistence_save_message(const char *client_id, const char *topic, const void *payload, size_t payload_len, int qos, int retain);

/**
 * Load retained messages from persistent storage
 * @return 0 on success, non-zero on error
 */
int persistence_load_retained(void);

/**
 * Load client sessions from persistent storage
 * @return 0 on success, non-zero on error
 */
int persistence_load_sessions(void);

/**
 * Save client session to persistent storage
 * @param client_id The client ID
 * @param clean_session Whether the session is clean
 * @param subscriptions The subscriptions
 * @param subscription_count The number of subscriptions
 * @return 0 on success, non-zero on error
 */
int persistence_save_session(const char *client_id, int clean_session, const char **subscriptions, int subscription_count);

/**
 * Delete client session from persistent storage
 * @param client_id The client ID
 * @return 0 on success, non-zero on error
 */
int persistence_delete_session(const char *client_id);

#endif /* PERSISTENCE_H */