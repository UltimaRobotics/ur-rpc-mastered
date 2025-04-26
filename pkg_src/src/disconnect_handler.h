/**
 * @file disconnect_handler.h
 * @brief Handler for client disconnections
 */

#ifndef DISCONNECT_HANDLER_H
#define DISCONNECT_HANDLER_H

/**
 * Initialize the disconnect handler
 * @param config_file Path to the disconnect handler configuration file
 * @return 0 on success, non-zero on error
 */
int disconnect_handler_init(const char *config_file);

/**
 * Clean up the disconnect handler
 */
void disconnect_handler_cleanup(void);

/**
 * Handle a client disconnection
 * @param client_id The ID of the disconnected client
 * @return 0 on success, non-zero on error
 */
int disconnect_handler_handle(const char *client_id);

#endif /* DISCONNECT_HANDLER_H */