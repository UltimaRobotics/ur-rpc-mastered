/**
 * @file topic_tree.h
 * @brief Topic tree for MQTT broker
 */

#ifndef TOPIC_TREE_H
#define TOPIC_TREE_H

#include "session.h"

/**
 * Topic node structure
 */
typedef struct topic_node topic_node_t;

/**
 * Initialize the topic tree
 * @return 0 on success, non-zero on error
 */
int topic_tree_init(void);

/**
 * Clean up the topic tree
 */
void topic_tree_cleanup(void);

/**
 * Subscribe a session to a topic
 * @param topic The topic to subscribe to
 * @param session The session
 * @param qos The QoS level
 * @return 0 on success, non-zero on error
 */
int topic_tree_subscribe(const char *topic, session_t *session, int qos);

/**
 * Unsubscribe a session from a topic
 * @param topic The topic to unsubscribe from
 * @param session The session
 * @return 0 on success, non-zero on error
 */
int topic_tree_unsubscribe(const char *topic, session_t *session);

/**
 * Unsubscribe a session from all topics
 * @param session The session
 * @return 0 on success, non-zero on error
 */
int topic_tree_unsubscribe_all(session_t *session);

/**
 * Publish a message to a topic
 * @param topic The topic to publish to
 * @param payload The payload
 * @param payload_len The payload length
 * @param qos The QoS level
 * @param retain Whether to retain the message
 * @return 0 on success, non-zero on error
 */
int topic_tree_publish(const char *topic, const void *payload, size_t payload_len, int qos, int retain);

/**
 * Dump subscribers information for a topic for debugging
 * @param topic The topic to dump subscribers for
 */
void topic_tree_dump_subscribers(const char *topic);

#endif /* TOPIC_TREE_H */