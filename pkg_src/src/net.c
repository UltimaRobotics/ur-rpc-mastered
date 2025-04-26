/**
 * @file net.c
 * @brief Network utilities for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include "net.h"
#include "logger.h"

int net_set_nonblocking(int sock) {
    int flags;
    
    // Get current flags
    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        log_error("Failed to get socket flags: %s", strerror(errno));
        return -1;
    }
    
    // Set non-blocking flag
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0) {
        log_error("Failed to set socket to non-blocking: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int net_is_readable(int sock, int timeout_ms) {
    fd_set readfds;
    struct timeval tv;
    int result;
    
    if (sock < 0) {
        return -1;
    }
    
    // Set up the descriptor set
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    
    // Set up the timeout
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    // Wait for socket to be readable
    result = select(sock + 1, &readfds, NULL, NULL, &tv);
    
    if (result < 0) {
        log_error("Select failed: %s", strerror(errno));
        return -1;
    }
    
    if (result == 0) {
        // Timeout
        return 0;
    }
    
    return FD_ISSET(sock, &readfds) ? 1 : 0;
}

int net_is_writable(int sock, int timeout_ms) {
    fd_set writefds;
    struct timeval tv;
    int result;
    
    if (sock < 0) {
        return -1;
    }
    
    // Set up the descriptor set
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    
    // Set up the timeout
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    // Wait for socket to be writable
    result = select(sock + 1, NULL, &writefds, NULL, &tv);
    
    if (result < 0) {
        log_error("Select failed: %s", strerror(errno));
        return -1;
    }
    
    if (result == 0) {
        // Timeout
        return 0;
    }
    
    return FD_ISSET(sock, &writefds) ? 1 : 0;
}

int net_read(int sock, void *buffer, size_t size, int timeout_ms) {
    int readable;
    int bytes_read;
    
    if (sock < 0 || !buffer || size == 0) {
        return -1;
    }
    
    // Check if socket is readable
    readable = net_is_readable(sock, timeout_ms);
    if (readable <= 0) {
        return readable == 0 ? -2 : -1;
    }
    
    // Read from socket
    bytes_read = recv(sock, buffer, size, 0);
    
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Should not happen since we checked with select()
            return -2;
        }
        
        log_error("Read failed: %s", strerror(errno));
        return -1;
    }
    
    return bytes_read;
}

int net_write(int sock, const void *buffer, size_t size, int timeout_ms) {
    int writable;
    int bytes_written;
    
    if (sock < 0 || !buffer || size == 0) {
        return -1;
    }
    
    // Check if socket is writable
    writable = net_is_writable(sock, timeout_ms);
    if (writable <= 0) {
        return writable == 0 ? -2 : -1;
    }
    
    // Write to socket
    bytes_written = send(sock, buffer, size, 0);
    
    if (bytes_written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Should not happen since we checked with select()
            return -2;
        }
        
        log_error("Write failed: %s", strerror(errno));
        return -1;
    }
    
    return bytes_written;
}