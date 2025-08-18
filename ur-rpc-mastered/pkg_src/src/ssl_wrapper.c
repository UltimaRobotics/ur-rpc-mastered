#include "ssl_wrapper.h"
#include "client_manager.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/net_sockets.h>

static ssl_global_context_t g_ssl_ctx = {0};

// Debug callback for mbedTLS
static void ssl_debug_callback(void *ctx, int level, const char *file, int line, const char *str) {
    (void)ctx;
    if (level <= 3) { // Only show important messages
        LOG_DEBUG("SSL Debug [%d] %s:%d: %s", level, file, line, str);
    }
}

// Enhanced certificate verification callback for strict security
static int ssl_enhanced_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    (void)data;
    
    LOG_DEBUG("Certificate verification: depth=%d, flags=0x%08x", depth, *flags);
    
    if (*flags != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", *flags);
        LOG_WARNING("Certificate verification failed at depth %d: %s", depth, vrfy_buf);
        
        // Log certificate details for debugging
        if (crt) {
            char subject_buf[256];
            char issuer_buf[256];
            
            mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &crt->subject);
            mbedtls_x509_dn_gets(issuer_buf, sizeof(issuer_buf), &crt->issuer);
            
            LOG_INFO("Certificate details - Subject: %s, Issuer: %s", subject_buf, issuer_buf);
        }
        
        // In strict mode, reject any certificate validation failures
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    }
    
    // Additional security checks
    if (crt) {
        // Check if certificate is expired
        time_t now = time(NULL);
        if (mbedtls_x509_time_is_past(&crt->valid_to)) {
            LOG_ERROR("Certificate has expired");
            *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }
        
        // Check if certificate is not yet valid
        if (mbedtls_x509_time_is_future(&crt->valid_from)) {
            LOG_ERROR("Certificate is not yet valid");
            *flags |= MBEDTLS_X509_BADCERT_FUTURE;
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }
        
        // Check key usage for TLS client authentication
        if (depth == 0) { // Only check end-entity certificate
            uint32_t key_usage = crt->key_usage;
            if (!(key_usage & MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) {
                LOG_ERROR("Certificate lacks required key usage for TLS client authentication");
                *flags |= MBEDTLS_X509_BADCERT_KEY_USAGE;
                return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }
        }
    }
    
    LOG_DEBUG("Certificate verification passed at depth %d", depth);
    return 0;
}

// Custom send function for mbedTLS
static int ssl_send_callback(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int*)ctx;
    ssize_t sent = send(fd, buf, len, 0);
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    
    return sent;
}

// Custom receive function for mbedTLS
static int ssl_recv_callback(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int*)ctx;
    ssize_t received = recv(fd, buf, len, 0);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    
    if (received == 0) {
        return MBEDTLS_ERR_NET_CONN_RESET;
    }
    
    return received;
}

int ssl_init(const broker_config_t *config) {
    if (!config || g_ssl_ctx.initialized) {
        return g_ssl_ctx.initialized ? 0 : -1;
    }

    memset(&g_ssl_ctx, 0, sizeof(g_ssl_ctx));
    int ret;
    char error_buf[100];

    // Allocate contexts
    g_ssl_ctx.entropy = malloc(sizeof(mbedtls_entropy_context));
    g_ssl_ctx.ctr_drbg = malloc(sizeof(mbedtls_ctr_drbg_context));
    g_ssl_ctx.ca_cert = malloc(sizeof(mbedtls_x509_crt));
    g_ssl_ctx.server_cert = malloc(sizeof(mbedtls_x509_crt));
    g_ssl_ctx.server_key = malloc(sizeof(mbedtls_pk_context));
    g_ssl_ctx.server_conf = malloc(sizeof(mbedtls_ssl_config));

    if (!g_ssl_ctx.entropy || !g_ssl_ctx.ctr_drbg || !g_ssl_ctx.ca_cert || 
        !g_ssl_ctx.server_cert || !g_ssl_ctx.server_key || !g_ssl_ctx.server_conf) {
        LOG_ERROR("Failed to allocate SSL contexts");
        ssl_cleanup();
        return -1;
    }

    // Initialize contexts
    mbedtls_entropy_init(g_ssl_ctx.entropy);
    mbedtls_ctr_drbg_init(g_ssl_ctx.ctr_drbg);
    mbedtls_x509_crt_init(g_ssl_ctx.ca_cert);
    mbedtls_x509_crt_init(g_ssl_ctx.server_cert);
    mbedtls_pk_init(g_ssl_ctx.server_key);
    mbedtls_ssl_config_init(g_ssl_ctx.server_conf);

    // Seed random number generator
    const char *pers = "mqtt_broker_ssl";
    ret = mbedtls_ctr_drbg_seed(g_ssl_ctx.ctr_drbg, mbedtls_entropy_func, 
                               g_ssl_ctx.entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_ERROR("Failed to seed random number generator: %s", error_buf);
        ssl_cleanup();
        return -1;
    }

    // Load server certificate
    ret = mbedtls_x509_crt_parse_file(g_ssl_ctx.server_cert, config->server_cert_file);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_ERROR("Failed to load server certificate from %s: %s", config->server_cert_file, error_buf);
        ssl_cleanup();
        return -1;
    }

    // Load server private key
    ret = mbedtls_pk_parse_keyfile(g_ssl_ctx.server_key, config->server_key_file, NULL);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_ERROR("Failed to load server private key from %s: %s", config->server_key_file, error_buf);
        ssl_cleanup();
        return -1;
    }

    // Load CA certificate if specified
    if (strlen(config->ca_cert_file) > 0) {
        ret = mbedtls_x509_crt_parse_file(g_ssl_ctx.ca_cert, config->ca_cert_file);
        if (ret != 0) {
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            LOG_WARNING("Failed to load CA certificate from %s: %s", config->ca_cert_file, error_buf);
        }
    }

    // Configure SSL context
    ret = mbedtls_ssl_config_defaults(g_ssl_ctx.server_conf, MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_ERROR("Failed to set SSL config defaults: %s", error_buf);
        ssl_cleanup();
        return -1;
    }

    // Set RNG
    mbedtls_ssl_conf_rng(g_ssl_ctx.server_conf, mbedtls_ctr_drbg_random, g_ssl_ctx.ctr_drbg);

    // Set debug callback
    mbedtls_ssl_conf_dbg(g_ssl_ctx.server_conf, ssl_debug_callback, NULL);

    // Set certificate and key
    ret = mbedtls_ssl_conf_own_cert(g_ssl_ctx.server_conf, g_ssl_ctx.server_cert, g_ssl_ctx.server_key);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_ERROR("Failed to configure server certificate: %s", error_buf);
        ssl_cleanup();
        return -1;
    }

    // Configure client authentication - Enhanced Security
    if (config->require_client_cert) {
        // STRICT: Require client certificate validation
        mbedtls_ssl_conf_authmode(g_ssl_ctx.server_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        if (strlen(config->ca_cert_file) > 0) {
            mbedtls_ssl_conf_ca_chain(g_ssl_ctx.server_conf, g_ssl_ctx.ca_cert, NULL);
            LOG_INFO("Client certificate authentication enabled with CA: %s", config->ca_cert_file);
        } else {
            LOG_ERROR("Client certificate required but no CA certificate specified");
            ssl_cleanup();
            return -1;
        }
    } else {
        // Even without client certs, verify server identity properly
        mbedtls_ssl_conf_authmode(g_ssl_ctx.server_conf, MBEDTLS_SSL_VERIFY_NONE);
        LOG_WARNING("Client certificate verification disabled - consider enabling for production");
    }

    // Set minimum protocol version to TLS 1.2 for enhanced security
    mbedtls_ssl_conf_min_version(g_ssl_ctx.server_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    
    // Configure cipher suites - use broader compatibility while maintaining security
    // Allow more cipher suites for better client compatibility
    static const int secure_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
        0 // Terminator
    };
    mbedtls_ssl_conf_ciphersuites(g_ssl_ctx.server_conf, secure_ciphersuites);
    
    // Enable session tickets for better performance
    mbedtls_ssl_conf_session_tickets(g_ssl_ctx.server_conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
    
    // Configure certificate verification callback for enhanced validation
    mbedtls_ssl_conf_verify(g_ssl_ctx.server_conf, ssl_enhanced_verify_callback, NULL);

    g_ssl_ctx.initialized = true;
    LOG_INFO("SSL/TLS initialized successfully");
    return 0;
}

void ssl_cleanup(void) {
    if (g_ssl_ctx.server_conf) {
        mbedtls_ssl_config_free(g_ssl_ctx.server_conf);
        free(g_ssl_ctx.server_conf);
    }
    
    if (g_ssl_ctx.server_key) {
        mbedtls_pk_free(g_ssl_ctx.server_key);
        free(g_ssl_ctx.server_key);
    }
    
    if (g_ssl_ctx.server_cert) {
        mbedtls_x509_crt_free(g_ssl_ctx.server_cert);
        free(g_ssl_ctx.server_cert);
    }
    
    if (g_ssl_ctx.ca_cert) {
        mbedtls_x509_crt_free(g_ssl_ctx.ca_cert);
        free(g_ssl_ctx.ca_cert);
    }
    
    if (g_ssl_ctx.ctr_drbg) {
        mbedtls_ctr_drbg_free(g_ssl_ctx.ctr_drbg);
        free(g_ssl_ctx.ctr_drbg);
    }
    
    if (g_ssl_ctx.entropy) {
        mbedtls_entropy_free(g_ssl_ctx.entropy);
        free(g_ssl_ctx.entropy);
    }
    
    memset(&g_ssl_ctx, 0, sizeof(g_ssl_ctx));
    LOG_INFO("SSL/TLS cleanup completed");
}

ssl_client_context_t* ssl_create_client_context(int socket_fd) {
    if (!g_ssl_ctx.initialized) {
        LOG_ERROR("SSL not initialized");
        return NULL;
    }

    ssl_client_context_t *client_ssl = malloc(sizeof(ssl_client_context_t));
    if (!client_ssl) {
        LOG_ERROR("Failed to allocate SSL client context");
        return NULL;
    }

    memset(client_ssl, 0, sizeof(ssl_client_context_t));
    client_ssl->socket_fd = socket_fd;

    // Allocate SSL context only (config is shared)
    client_ssl->ssl = malloc(sizeof(mbedtls_ssl_context));
    
    if (!client_ssl->ssl) {
        LOG_ERROR("Failed to allocate SSL context");
        ssl_free_client_context(client_ssl);
        return NULL;
    }

    // Initialize SSL context
    mbedtls_ssl_init(client_ssl->ssl);
    
    // Use the shared server configuration instead of copying it
    // This avoids double-free issues with dynamically allocated members
    client_ssl->conf = g_ssl_ctx.server_conf;

    // Setup SSL context
    int ret = mbedtls_ssl_setup(client_ssl->ssl, client_ssl->conf);
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_ERROR("Failed to setup SSL context: %s", error_buf);
        ssl_free_client_context(client_ssl);
        return NULL;
    }

    // Set BIO callbacks
    mbedtls_ssl_set_bio(client_ssl->ssl, &client_ssl->socket_fd, 
                       ssl_send_callback, ssl_recv_callback, NULL);

    return client_ssl;
}

void ssl_free_client_context(ssl_client_context_t *client_ssl) {
    if (!client_ssl) return;

    if (client_ssl->ssl) {
        mbedtls_ssl_free(client_ssl->ssl);
        free(client_ssl->ssl);
    }

    // Don't free client_ssl->conf as it points to the shared server configuration
    
    free(client_ssl);
}

int ssl_accept_client(struct mqtt_client *client) {
    if (!client || !g_ssl_ctx.initialized) {
        LOG_ERROR("Invalid parameters or SSL not initialized");
        return -1;
    }

    // Create SSL context for this client
    client->ssl_ctx = ssl_create_client_context(client->socket_fd);
    if (!client->ssl_ctx) {
        LOG_ERROR("Failed to create SSL context for client");
        return -1;
    }

    client->use_ssl = true;
    LOG_DEBUG("SSL context created for client fd=%d", client->socket_fd);
    return 0;
}

int ssl_handshake(ssl_client_context_t *client_ssl) {
    if (!client_ssl) return -1;

    int ret = mbedtls_ssl_handshake(client_ssl->ssl);
    
    if (ret == 0) {
        // Handshake successful - now perform enhanced validation
        client_ssl->handshake_completed = true;
        
        // Log connection details for security monitoring
        char cipher_suite[64] = {0};
        char protocol_version[32] = {0};
        ssl_get_connection_info(client_ssl, cipher_suite, sizeof(cipher_suite), 
                               protocol_version, sizeof(protocol_version));
        
        LOG_INFO("SSL handshake completed for fd=%d - Protocol: %s, Cipher: %s", 
                client_ssl->socket_fd, protocol_version, cipher_suite);
        
        // Verify client certificate if provided or required
        const mbedtls_x509_crt *client_cert = mbedtls_ssl_get_peer_cert(client_ssl->ssl);
        if (client_cert) {
            // Client provided a certificate - verify it
            if (ssl_verify_client_certificate(client_ssl) != 0) {
                LOG_ERROR("Client certificate verification failed for fd=%d", client_ssl->socket_fd);
                client_ssl->handshake_completed = false;
                return -1;
            }
            
            // Log successful certificate verification
            char subject_buf[256];
            mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &client_cert->subject);
            LOG_INFO("Client certificate verified for fd=%d - Subject: %s", 
                    client_ssl->socket_fd, subject_buf);
        } else {
            // No client certificate provided - check if it's required
            // This is already handled by the verification callback, but log it
            LOG_DEBUG("No client certificate provided for fd=%d", client_ssl->socket_fd);
        }
        
        return 0;
    }
    
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // Need more data
        return 1;
    }
    
    // Enhanced error reporting for SSL handshake failures
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    
    // Specific handling for certificate-related failures
    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        LOG_ERROR("SSL handshake failed for fd=%d: Client certificate verification failed", 
                 client_ssl->socket_fd);
    } else if (ret == MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED) {
        LOG_ERROR("SSL handshake failed for fd=%d: Client certificate required but not provided", 
                 client_ssl->socket_fd);
    } else if (ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY) {
        LOG_ERROR("SSL handshake failed for fd=%d: Client certificate not trusted", 
                 client_ssl->socket_fd);
    } else {
        LOG_ERROR("SSL handshake failed for fd=%d: %s", client_ssl->socket_fd, error_buf);
    }
    
    return -1;
}

ssize_t ssl_send(ssl_client_context_t *client_ssl, const void *buffer, size_t length) {
    if (!client_ssl || !client_ssl->handshake_completed) return -1;

    int ret = mbedtls_ssl_write(client_ssl->ssl, (const unsigned char*)buffer, length);
    
    if (ret >= 0) {
        return ret;
    }
    
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        errno = EAGAIN;
        return 0;
    }
    
    LOG_WARNING("SSL send failed for fd=%d: %d", client_ssl->socket_fd, ret);
    return -1;
}

ssize_t ssl_recv(ssl_client_context_t *client_ssl, void *buffer, size_t length) {
    if (!client_ssl) return -1;

    // If handshake not completed, try to complete it
    if (!client_ssl->handshake_completed) {
        int hs_ret = ssl_handshake(client_ssl);
        if (hs_ret != 0) {
            if (hs_ret == 1) {
                errno = EAGAIN;
                return 0; // Need more data for handshake
            }
            return -1; // Handshake failed
        }
    }

    int ret = mbedtls_ssl_read(client_ssl->ssl, (unsigned char*)buffer, length);
    
    if (ret >= 0) {
        return ret;
    }
    
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        errno = EAGAIN;
        return 0;
    }
    
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return 0; // Clean shutdown
    }
    
    LOG_WARNING("SSL receive failed for fd=%d: %d", client_ssl->socket_fd, ret);
    return -1;
}

bool ssl_handshake_completed(const ssl_client_context_t *client_ssl) {
    return client_ssl ? client_ssl->handshake_completed : false;
}

int ssl_get_connection_info(const ssl_client_context_t *client_ssl, 
                           char *cipher_suite, size_t cipher_suite_len,
                           char *protocol_version, size_t protocol_version_len) {
    if (!client_ssl || !client_ssl->handshake_completed) return -1;

    if (cipher_suite && cipher_suite_len > 0) {
        const char *suite = mbedtls_ssl_get_ciphersuite(client_ssl->ssl);
        strncpy(cipher_suite, suite ? suite : "unknown", cipher_suite_len - 1);
        cipher_suite[cipher_suite_len - 1] = '\0';
    }

    if (protocol_version && protocol_version_len > 0) {
        const char *version = mbedtls_ssl_get_version(client_ssl->ssl);
        strncpy(protocol_version, version ? version : "unknown", protocol_version_len - 1);
        protocol_version[protocol_version_len - 1] = '\0';
    }

    return 0;
}

int ssl_verify_client_certificate(const ssl_client_context_t *client_ssl) {
    if (!client_ssl || !client_ssl->handshake_completed) return -1;

    uint32_t flags = mbedtls_ssl_get_verify_result(client_ssl->ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        LOG_WARNING("Client certificate verification failed for fd=%d: %s", 
                   client_ssl->socket_fd, vrfy_buf);
        return -1;
    }

    return 0;
}

int ssl_force_disconnect_invalid_client(ssl_client_context_t *client_ssl) {
    if (!client_ssl) return -1;
    
    LOG_WARNING("Forcing disconnection of invalid SSL client fd=%d", client_ssl->socket_fd);
    
    // Send close notify alert
    if (client_ssl->ssl && client_ssl->handshake_completed) {
        mbedtls_ssl_close_notify(client_ssl->ssl);
    }
    
    // Close the socket immediately
    if (client_ssl->socket_fd >= 0) {
        close(client_ssl->socket_fd);
        client_ssl->socket_fd = -1;
    }
    
    return 0;
}

int ssl_get_security_info(const ssl_client_context_t *client_ssl, char *security_info, size_t info_len) {
    if (!client_ssl || !client_ssl->handshake_completed || !security_info || info_len == 0) {
        return -1;
    }
    
    char cipher_suite[64] = {0};
    char protocol_version[32] = {0};
    
    // Get basic connection info
    ssl_get_connection_info(client_ssl, cipher_suite, sizeof(cipher_suite), 
                           protocol_version, sizeof(protocol_version));
    
    // Get certificate information if available
    const mbedtls_x509_crt *client_cert = mbedtls_ssl_get_peer_cert(client_ssl->ssl);
    char cert_info[256] = "No client certificate";
    
    if (client_cert) {
        char subject_buf[128];
        mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &client_cert->subject);
        snprintf(cert_info, sizeof(cert_info), "Client cert: %s", subject_buf);
    }
    
    // Compile security information
    snprintf(security_info, info_len, 
            "SSL Security Info for fd=%d:\n"
            "- Protocol: %s\n"
            "- Cipher Suite: %s\n"
            "- %s\n"
            "- Verification Status: %s",
            client_ssl->socket_fd,
            protocol_version,
            cipher_suite,
            cert_info,
            (mbedtls_ssl_get_verify_result(client_ssl->ssl) == 0) ? "VERIFIED" : "FAILED");
    
    return 0;
}

int ssl_validate_connection_security(const ssl_client_context_t *client_ssl) {
    if (!client_ssl || !client_ssl->handshake_completed) return -1;
    
    // Check protocol version (require TLS 1.2+)
    char protocol_version[32] = {0};
    ssl_get_connection_info(client_ssl, NULL, 0, protocol_version, sizeof(protocol_version));
    
    if (strstr(protocol_version, "TLSv1.2") == NULL && strstr(protocol_version, "TLSv1.3") == NULL) {
        LOG_WARNING("Insecure TLS version detected for fd=%d: %s", 
                   client_ssl->socket_fd, protocol_version);
        return 0; // Insecure
    }
    
    // Check cipher suite security
    char cipher_suite[64] = {0};
    ssl_get_connection_info(client_ssl, cipher_suite, sizeof(cipher_suite), NULL, 0);
    
    // Check for secure cipher characteristics
    bool has_forward_secrecy = (strstr(cipher_suite, "ECDHE") != NULL || 
                               strstr(cipher_suite, "DHE") != NULL);
    bool has_aead = (strstr(cipher_suite, "GCM") != NULL || 
                    strstr(cipher_suite, "CHACHA20") != NULL ||
                    strstr(cipher_suite, "POLY1305") != NULL);
    
    if (!has_forward_secrecy) {
        LOG_WARNING("Cipher suite lacks forward secrecy for fd=%d: %s", 
                   client_ssl->socket_fd, cipher_suite);
        return 0; // Insecure
    }
    
    if (!has_aead) {
        LOG_WARNING("Cipher suite lacks AEAD for fd=%d: %s", 
                   client_ssl->socket_fd, cipher_suite);
        return 0; // Insecure
    }
    
    // Check certificate verification status
    if (mbedtls_ssl_get_verify_result(client_ssl->ssl) != 0) {
        LOG_WARNING("Certificate verification failed for fd=%d", client_ssl->socket_fd);
        return 0; // Insecure
    }
    
    LOG_DEBUG("SSL connection security validated for fd=%d", client_ssl->socket_fd);
    return 1; // Secure
}
