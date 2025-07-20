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

    // Configure client authentication
    if (config->require_client_cert) {
        mbedtls_ssl_conf_authmode(g_ssl_ctx.server_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        if (strlen(config->ca_cert_file) > 0) {
            mbedtls_ssl_conf_ca_chain(g_ssl_ctx.server_conf, g_ssl_ctx.ca_cert, NULL);
        }
    } else {
        mbedtls_ssl_conf_authmode(g_ssl_ctx.server_conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    // Set minimum protocol version to TLS 1.2
    mbedtls_ssl_conf_min_version(g_ssl_ctx.server_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

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

    // Allocate SSL context and config
    client_ssl->ssl = malloc(sizeof(mbedtls_ssl_context));
    client_ssl->conf = malloc(sizeof(mbedtls_ssl_config));
    
    if (!client_ssl->ssl || !client_ssl->conf) {
        LOG_ERROR("Failed to allocate SSL structures");
        ssl_free_client_context(client_ssl);
        return NULL;
    }

    // Initialize SSL context
    mbedtls_ssl_init(client_ssl->ssl);
    mbedtls_ssl_config_init(client_ssl->conf);

    // Copy server configuration
    memcpy(client_ssl->conf, g_ssl_ctx.server_conf, sizeof(mbedtls_ssl_config));

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

    if (client_ssl->conf) {
        mbedtls_ssl_config_free(client_ssl->conf);
        free(client_ssl->conf);
    }

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
        client_ssl->handshake_completed = true;
        LOG_DEBUG("SSL handshake completed for fd=%d", client_ssl->socket_fd);
        return 0;
    }
    
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // Need more data
        return 1;
    }
    
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    LOG_ERROR("SSL handshake failed for fd=%d: %s", client_ssl->socket_fd, error_buf);
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
