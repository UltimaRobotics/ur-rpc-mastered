#ifndef SSL_WRAPPER_H
#define SSL_WRAPPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "config.h"

// Forward declaration to avoid including mbedtls headers in this header
typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;
typedef struct mbedtls_entropy_context mbedtls_entropy_context;
typedef struct mbedtls_ctr_drbg_context mbedtls_ctr_drbg_context;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_pk_context mbedtls_pk_context;

// Forward declaration for mqtt_client_t
typedef struct mqtt_client mqtt_client_t;

// SSL context for a client connection
typedef struct {
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_config *conf;
    int socket_fd;
    bool handshake_completed;
    bool is_server;
} ssl_client_context_t;

// Global SSL configuration
typedef struct {
    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_x509_crt *ca_cert;
    mbedtls_x509_crt *server_cert;
    mbedtls_pk_context *server_key;
    mbedtls_ssl_config *server_conf;
    bool initialized;
} ssl_global_context_t;

/**
 * Initialize SSL/TLS subsystem
 * @param config Broker configuration containing SSL settings
 * @return 0 on success, -1 on error
 */
int ssl_init(const broker_config_t *config);

/**
 * Cleanup SSL/TLS subsystem
 */
void ssl_cleanup(void);

/**
 * Accept and initialize SSL connection for a client
 * @param client Pointer to mqtt_client_t structure containing socket_fd
 * @return 0 on success, -1 on error
 */
int ssl_accept_client(mqtt_client_t *client);

/**
 * Perform SSL handshake for a client
 * @param client_ssl SSL client context
 * @return 0 on success, 1 if more data needed, -1 on error
 */
int ssl_handshake(ssl_client_context_t *client_ssl);

/**
 * Send data over SSL connection
 * @param client_ssl SSL client context
 * @param buffer Data buffer
 * @param length Data length
 * @return Number of bytes sent, -1 on error, 0 if would block
 */
ssize_t ssl_send(ssl_client_context_t *client_ssl, const void *buffer, size_t length);

/**
 * Receive data over SSL connection
 * @param client_ssl SSL client context
 * @param buffer Data buffer
 * @param length Buffer size
 * @return Number of bytes received, -1 on error, 0 if would block or connection closed
 */
ssize_t ssl_recv(ssl_client_context_t *client_ssl, void *buffer, size_t length);

/**
 * Create SSL client context
 * @param socket_fd Socket file descriptor
 * @return SSL client context on success, NULL on error
 */
ssl_client_context_t* ssl_create_client_context(int socket_fd);

/**
 * Free SSL client context
 * @param client_ssl SSL client context
 */
void ssl_free_client_context(ssl_client_context_t *client_ssl);

/**
 * Check if SSL handshake is completed
 * @param client_ssl SSL client context
 * @return true if completed, false otherwise
 */
bool ssl_handshake_completed(const ssl_client_context_t *client_ssl);

/**
 * Get SSL connection information
 * @param client_ssl SSL client context
 * @param cipher_suite Buffer to store cipher suite name
 * @param cipher_suite_len Buffer length
 * @param protocol_version Buffer to store protocol version
 * @param protocol_version_len Buffer length
 * @return 0 on success, -1 on error
 */
int ssl_get_connection_info(const ssl_client_context_t *client_ssl, 
                           char *cipher_suite, size_t cipher_suite_len,
                           char *protocol_version, size_t protocol_version_len);

/**
 * Verify client certificate (if client authentication is enabled)
 * @param client_ssl SSL client context
 * @return 0 if valid, -1 if invalid
 */
int ssl_verify_client_certificate(const ssl_client_context_t *client_ssl);

/**
 * Force immediate disconnection of SSL client with invalid certificates
 * @param client_ssl SSL client context
 * @return 0 on success, -1 on error
 */
int ssl_force_disconnect_invalid_client(ssl_client_context_t *client_ssl);

/**
 * Get detailed SSL security information about the connection
 * @param client_ssl SSL client context
 * @param security_info Buffer to store security information
 * @param info_len Buffer length
 * @return 0 on success, -1 on error
 */
int ssl_get_security_info(const ssl_client_context_t *client_ssl, char *security_info, size_t info_len);

/**
 * Check if the current SSL connection meets security requirements
 * @param client_ssl SSL client context
 * @return 1 if secure, 0 if insecure, -1 on error
 */
int ssl_validate_connection_security(const ssl_client_context_t *client_ssl);

#endif /* SSL_WRAPPER_H */
