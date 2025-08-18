#include "network.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int network_create_listener(uint16_t port, const char *bind_addr) {
    int sockfd;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int opt = 1;
    
    // Create socket address
    if (network_create_sockaddr(bind_addr, port, &addr, &addr_len) != 0) {
        LOG_ERROR("Failed to create socket address");
        return -1;
    }
    
    // Create socket
    sockfd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_WARNING("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        LOG_WARNING("Failed to set SO_REUSEPORT: %s", strerror(errno));
    }
    
    // Bind socket
    if (bind(sockfd, (struct sockaddr*)&addr, addr_len) == -1) {
        LOG_ERROR("Failed to bind socket to port %d: %s", port, strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // Listen for connections
    if (listen(sockfd, SOMAXCONN) == -1) {
        LOG_ERROR("Failed to listen on socket: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // Set socket options for performance
    network_set_socket_options(sockfd);
    
    LOG_INFO("Created listener on %s:%d (fd=%d)", 
             bind_addr ? bind_addr : "0.0.0.0", port, sockfd);
    
    return sockfd;
}

int network_set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERROR("Failed to get socket flags: %s", strerror(errno));
        return -1;
    }
    
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR("Failed to set socket non-blocking: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int network_set_socket_options(int sockfd) {
    int opt = 1;
    
    // Disable Nagle's algorithm for low latency
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
        LOG_WARNING("Failed to set TCP_NODELAY: %s", strerror(errno));
    }
    
    // Set keep-alive
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
        LOG_WARNING("Failed to set SO_KEEPALIVE: %s", strerror(errno));
    }
    
    // Set send/receive buffer sizes
    int buffer_size = 64 * 1024; // 64KB
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) == -1) {
        LOG_WARNING("Failed to set send buffer size: %s", strerror(errno));
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) == -1) {
        LOG_WARNING("Failed to set receive buffer size: %s", strerror(errno));
    }
    
    return 0;
}

int network_get_peer_address(int sockfd, char *addr_str, size_t addr_str_len) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    
    if (getpeername(sockfd, (struct sockaddr*)&addr, &addr_len) == -1) {
        LOG_WARNING("Failed to get peer name: %s", strerror(errno));
        strncpy(addr_str, "unknown", addr_str_len - 1);
        addr_str[addr_str_len - 1] = '\0';
        return -1;
    }
    
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)&addr;
        if (inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, addr_str_len) == NULL) {
            strncpy(addr_str, "unknown", addr_str_len - 1);
            return -1;
        }
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&addr;
        if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, addr_str_len) == NULL) {
            strncpy(addr_str, "unknown", addr_str_len - 1);
            return -1;
        }
    } else {
        strncpy(addr_str, "unknown", addr_str_len - 1);
        return -1;
    }
    
    addr_str[addr_str_len - 1] = '\0';
    return 0;
}

int network_get_local_address(int sockfd, char *addr_str, size_t addr_str_len, uint16_t *port) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    
    if (getsockname(sockfd, (struct sockaddr*)&addr, &addr_len) == -1) {
        LOG_WARNING("Failed to get socket name: %s", strerror(errno));
        return -1;
    }
    
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)&addr;
        if (inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, addr_str_len) == NULL) {
            return -1;
        }
        if (port) *port = ntohs(addr_in->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&addr;
        if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, addr_str_len) == NULL) {
            return -1;
        }
        if (port) *port = ntohs(addr_in6->sin6_port);
    } else {
        return -1;
    }
    
    return 0;
}

ssize_t network_send(int sockfd, const void *buffer, size_t length) {
    size_t total_sent = 0;
    const uint8_t *data = (const uint8_t*)buffer;
    
    while (total_sent < length) {
        ssize_t sent = send(sockfd, data + total_sent, length - total_sent, MSG_NOSIGNAL);
        
        if (sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Would block, return bytes sent so far
                break;
            }
            LOG_WARNING("Send failed: %s", strerror(errno));
            return -1;
        }
        
        if (sent == 0) {
            // Connection closed
            break;
        }
        
        total_sent += sent;
    }
    
    return total_sent;
}

ssize_t network_recv(int sockfd, void *buffer, size_t length) {
    ssize_t received = recv(sockfd, buffer, length, 0);
    
    if (received == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Would block
            return 0;
        }
        LOG_WARNING("Receive failed: %s", strerror(errno));
        return -1;
    }
    
    return received;
}

int network_is_connected(int sockfd) {
    int error = 0;
    socklen_t len = sizeof(error);
    
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        return -1;
    }
    
    return error == 0 ? 1 : 0;
}

int network_set_keepalive(int sockfd, int keepalive_time, int keepalive_interval, int keepalive_probes) {
    int opt = 1;
    
    // Enable keep-alive
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
        LOG_WARNING("Failed to enable keep-alive: %s", strerror(errno));
        return -1;
    }
    
    // Set keep-alive parameters
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) == -1) {
        LOG_WARNING("Failed to set TCP_KEEPIDLE: %s", strerror(errno));
    }
    
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval, sizeof(keepalive_interval)) == -1) {
        LOG_WARNING("Failed to set TCP_KEEPINTVL: %s", strerror(errno));
    }
    
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) == -1) {
        LOG_WARNING("Failed to set TCP_KEEPCNT: %s", strerror(errno));
    }
    
    return 0;
}

int network_parse_address(const char *addr_str, char *ip_str, size_t ip_str_len, uint16_t *port) {
    if (!addr_str || !ip_str || !port) return -1;
    
    // Handle IPv6 addresses [::1]:1883
    if (addr_str[0] == '[') {
        const char *bracket_end = strchr(addr_str, ']');
        if (!bracket_end) return -1;
        
        size_t ip_len = bracket_end - addr_str - 1;
        if (ip_len >= ip_str_len) return -1;
        
        strncpy(ip_str, addr_str + 1, ip_len);
        ip_str[ip_len] = '\0';
        
        const char *colon = strchr(bracket_end, ':');
        if (colon) {
            *port = atoi(colon + 1);
        } else {
            *port = 0;
        }
        
        return 0;
    }
    
    // Handle IPv4 addresses 192.168.1.1:1883
    const char *colon = strrchr(addr_str, ':');
    if (colon) {
        size_t ip_len = colon - addr_str;
        if (ip_len >= ip_str_len) return -1;
        
        strncpy(ip_str, addr_str, ip_len);
        ip_str[ip_len] = '\0';
        *port = atoi(colon + 1);
    } else {
        strncpy(ip_str, addr_str, ip_str_len - 1);
        ip_str[ip_str_len - 1] = '\0';
        *port = 0;
    }
    
    return 0;
}

int network_create_sockaddr(const char *addr_str, uint16_t port, 
                           struct sockaddr_storage *addr, socklen_t *addr_len) {
    memset(addr, 0, sizeof(*addr));
    
    if (!addr_str || strcmp(addr_str, "0.0.0.0") == 0 || strlen(addr_str) == 0) {
        // IPv4 any address
        struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
        addr_in->sin_family = AF_INET;
        addr_in->sin_addr.s_addr = INADDR_ANY;
        addr_in->sin_port = htons(port);
        *addr_len = sizeof(*addr_in);
        return 0;
    }
    
    if (strcmp(addr_str, "::") == 0) {
        // IPv6 any address
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)addr;
        addr_in6->sin6_family = AF_INET6;
        addr_in6->sin6_addr = in6addr_any;
        addr_in6->sin6_port = htons(port);
        *addr_len = sizeof(*addr_in6);
        return 0;
    }
    
    // Try IPv4 first
    struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
    if (inet_pton(AF_INET, addr_str, &addr_in->sin_addr) == 1) {
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = htons(port);
        *addr_len = sizeof(*addr_in);
        return 0;
    }
    
    // Try IPv6
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)addr;
    if (inet_pton(AF_INET6, addr_str, &addr_in6->sin6_addr) == 1) {
        addr_in6->sin6_family = AF_INET6;
        addr_in6->sin6_port = htons(port);
        *addr_len = sizeof(*addr_in6);
        return 0;
    }
    
    LOG_ERROR("Invalid address: %s", addr_str);
    return -1;
}
