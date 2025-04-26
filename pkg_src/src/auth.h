/**
 * @file auth.h
 * @brief Authentication utilities for MQTT broker
 */

#ifndef AUTH_H
#define AUTH_H

/**
 * Initialize the authentication system
 * @param auth_file The path to the authentication file
 * @return 0 on success, non-zero on error
 */
int auth_init(const char *auth_file);

/**
 * Clean up the authentication system
 */
void auth_cleanup(void);

/**
 * Authenticate a client
 * @param username The username to authenticate
 * @param password The password to authenticate
 * @return 1 if authenticated, 0 if not authenticated
 */
int auth_authenticate(const char *username, const char *password);

/**
 * Check if a client is authorized to publish to a topic
 * @param username The username to check
 * @param topic The topic to check
 * @return 1 if authorized, 0 if not authorized
 */
int auth_check_publish(const char *username, const char *topic);

/**
 * Check if a client is authorized to subscribe to a topic
 * @param username The username to check
 * @param topic The topic to check
 * @return 1 if authorized, 0 if not authorized
 */
int auth_check_subscribe(const char *username, const char *topic);

#endif /* AUTH_H */