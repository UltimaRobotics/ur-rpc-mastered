#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * Create a TCP listener socket
 * @param port Port to listen on
 * @param bind_addr Address to bind to (NULL for any address)
 * @return Socket file descriptor on success, -1 on error
 */
int network_create_listener(uint16_t port, const char *bind_addr);

/**
 * Set socket to non-blocking mode
 * @param sockfd Socket file descriptor
 * @return 0 on success, -1 on error
 */
int network_set_nonblocking(int sockfd);

/**
 * Set socket options for optimal performance
 * @param sockfd Socket file descriptor
 * @return 0 on success, -1 on error
 */
int network_set_socket_options(int sockfd);

/**
 * Get peer address as string
 * @param sockfd Socket file descriptor
 * @param addr_str Buffer to store address string
 * @param addr_str_len Buffer length
 * @return 0 on success, -1 on error
 */
int network_get_peer_address(int sockfd, char *addr_str, size_t addr_str_len);

/**
 * Get local address and port
 * @param sockfd Socket file descriptor
 * @param addr_str Buffer to store address string
 * @param addr_str_len Buffer length
 * @param port Pointer to store port number
 * @return 0 on success, -1 on error
 */
int network_get_local_address(int sockfd, char *addr_str, size_t addr_str_len, uint16_t *port);

/**
 * Safe send function that handles partial sends
 * @param sockfd Socket file descriptor
 * @param buffer Data buffer
 * @param length Data length
 * @return Number of bytes sent, -1 on error
 */
ssize_t network_send(int sockfd, const void *buffer, size_t length);

/**
 * Safe receive function that handles partial receives
 * @param sockfd Socket file descriptor
 * @param buffer Data buffer
 * @param length Maximum data length
 * @return Number of bytes received, -1 on error, 0 on connection closed
 */
ssize_t network_recv(int sockfd, void *buffer, size_t length);

/**
 * Check if socket is still connected
 * @param sockfd Socket file descriptor
 * @return 1 if connected, 0 if disconnected, -1 on error
 */
int network_is_connected(int sockfd);

/**
 * Set TCP keep-alive options
 * @param sockfd Socket file descriptor
 * @param keepalive_time Time before first keep-alive probe (seconds)
 * @param keepalive_interval Interval between keep-alive probes (seconds)
 * @param keepalive_probes Number of keep-alive probes
 * @return 0 on success, -1 on error
 */
int network_set_keepalive(int sockfd, int keepalive_time, int keepalive_interval, int keepalive_probes);

/**
 * Parse IP address and port from string
 * @param addr_str Address string (e.g., "192.168.1.1:1883" or "[::1]:1883")
 * @param ip_str Buffer to store IP address
 * @param ip_str_len IP buffer length
 * @param port Pointer to store port number
 * @return 0 on success, -1 on error
 */
int network_parse_address(const char *addr_str, char *ip_str, size_t ip_str_len, uint16_t *port);

/**
 * Create socket address structure from string
 * @param addr_str Address string
 * @param port Port number
 * @param addr Pointer to sockaddr structure
 * @param addr_len Pointer to store address length
 * @return 0 on success, -1 on error
 */
int network_create_sockaddr(const char *addr_str, uint16_t port, 
                           struct sockaddr_storage *addr, socklen_t *addr_len);

#endif /* NETWORK_H */
