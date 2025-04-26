/**
 * @file session.h
 * @brief Client session management for MQTT broker
 */

#ifndef SESSION_H
#define SESSION_H

#include <stddef.h>

/**
 * Client session structure
 */
typedef struct session session_t;

/**
 * Initialize the session manager
 * @param max_sessions The maximum number of sessions
 * @return 0 on success, non-zero on error
 */
int session_manager_init(int max_sessions);

/**
 * Clean up the session manager
 */
void session_manager_cleanup(void);

/**
 * Create a new session
 * @param client_id The client ID
 * @param clean_session Whether this is a clean session
 * @return A pointer to the session, or NULL on error
 */
session_t *session_create(const char *client_id, int clean_session);

/**
 * Find a session by client ID
 * @param client_id The client ID
 * @return A pointer to the session, or NULL if not found
 */
session_t *session_find(const char *client_id);

/**
 * Find a session by index
 * @param index The index of the session (0-based)
 * @return A pointer to the session, or NULL if not found
 */
session_t *session_find_by_index(int index);

/**
 * Destroy a session
 * @param session The session to destroy
 */
void session_destroy(session_t *session);

/**
 * Add a subscription to a session
 * @param session The session
 * @param topic The topic filter to subscribe to
 * @param qos The QoS level
 * @return 0 on success, non-zero on error
 */
int session_add_subscription(session_t *session, const char *topic, int qos);

/**
 * Remove a subscription from a session
 * @param session The session
 * @param topic The topic filter to unsubscribe from
 * @return 0 on success, non-zero on error
 */
int session_remove_subscription(session_t *session, const char *topic);

/**
 * Check if a session has a subscription matching a topic
 * @param session The session
 * @param topic The topic to check
 * @param qos Pointer to store the QoS level, or NULL
 * @return 1 if the session has a matching subscription, 0 otherwise
 */
int session_has_subscription(const session_t *session, const char *topic, int *qos);

/**
 * Get the client ID for a session
 * @param session The session
 * @return The client ID, or NULL on error
 */
const char *session_get_client_id(const session_t *session);

/**
 * Get the clean session flag for a session
 * @param session The session
 * @return The clean session flag, or -1 on error
 */
int session_get_clean_session(const session_t *session);

/**
 * Get the number of subscriptions for a session
 * @param session The session
 * @return The number of subscriptions, or -1 on error
 */
int session_get_subscription_count(const session_t *session);

/**
 * Get a subscription for a session by index
 * @param session The session
 * @param index The index of the subscription
 * @param topic Pointer to store the topic filter, or NULL
 * @param qos Pointer to store the QoS level, or NULL
 * @return 0 on success, non-zero on error
 */
int session_get_subscription(const session_t *session, int index, const char **topic, int *qos);

/**
 * Set the socket for a session
 * @param session The session
 * @param socket The socket
 * @return 0 on success, non-zero on error
 */
int session_set_socket(session_t *session, int socket);

/**
 * Get the socket for a session
 * @param session The session
 * @return The socket, or -1 on error
 */
int session_get_socket(const session_t *session);

/**
 * Forward a message to a session
 * @param session The session
 * @param topic The topic
 * @param payload The payload
 * @param payload_len The payload length
 * @param qos The QoS level to use (lower of subscription and message)
 * @return 0 on success, non-zero on error
 */
int session_forward_message(session_t *session, const char *topic, const void *payload, size_t payload_len, int qos);

#endif /* SESSION_H */