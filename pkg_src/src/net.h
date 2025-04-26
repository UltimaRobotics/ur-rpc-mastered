/**
 * @file net.h
 * @brief Network utilities for MQTT broker
 */

#ifndef NET_H
#define NET_H

#include <stddef.h>

/**
 * Set a socket to non-blocking mode
 * @param sock The socket to modify
 * @return 0 on success, -1 on error
 */
int net_set_nonblocking(int sock);

/**
 * Read data from a socket with timeout
 * @param sock The socket to read from
 * @param buffer The buffer to read into
 * @param size The size of the buffer
 * @param timeout_ms The timeout in milliseconds
 * @return Number of bytes read, 0 on connection closed, -1 on error, -2 on timeout
 */
int net_read(int sock, void *buffer, size_t size, int timeout_ms);

/**
 * Write data to a socket with timeout
 * @param sock The socket to write to
 * @param buffer The buffer to write
 * @param size The size of the buffer
 * @param timeout_ms The timeout in milliseconds
 * @return Number of bytes written, 0 on connection closed, -1 on error, -2 on timeout
 */
int net_write(int sock, const void *buffer, size_t size, int timeout_ms);

/**
 * Check if a socket is readable
 * @param sock The socket to check
 * @param timeout_ms The timeout in milliseconds
 * @return 1 if readable, 0 if not, -1 on error
 */
int net_is_readable(int sock, int timeout_ms);

/**
 * Check if a socket is writable
 * @param sock The socket to check
 * @param timeout_ms The timeout in milliseconds
 * @return 1 if writable, 0 if not, -1 on error
 */
int net_is_writable(int sock, int timeout_ms);

#endif /* NET_H */