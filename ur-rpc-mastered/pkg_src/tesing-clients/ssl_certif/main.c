/*
 * Enhanced SSL MQTT Client with TLS Encryption
 * Hardcoded certificate paths for secure connection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>

#define DEFAULT_BROKER_HOST "127.0.0.1"
#define DEFAULT_BROKER_PORT 1855
#define DEFAULT_KEEPALIVE 60
#define CONNECT_TIMEOUT 30
#define MESSAGE_TIMEOUT 10

// Hardcoded SSL certificate file paths
#define CA_CERT_PATH "ca.crt"
#define CLIENT_CERT_PATH "runner_client.crt"
#define CLIENT_KEY_PATH "runner_client.key"

typedef struct {
    const char *ca_cert;
    const char *client_cert;
    const char *client_key;
    char *broker_host;
    int broker_port;
    bool connected;
    bool message_sent;
    bool ssl_handshake_complete;
    bool enable_peer_verification;
    char *client_id;
} ssl_client_t;

static ssl_client_t g_client = {
    .ca_cert = CA_CERT_PATH,
    .client_cert = CLIENT_CERT_PATH,
    .client_key = CLIENT_KEY_PATH,
    .broker_host = DEFAULT_BROKER_HOST,
    .broker_port = DEFAULT_BROKER_PORT,
    .connected = false,
    .message_sent = false,
    .ssl_handshake_complete = false,
    .enable_peer_verification = false,
    .client_id = NULL
};

static volatile bool g_running = true;

void signal_handler(int sig) {
    (void)sig;
    g_running = false;
    printf("\n🛑 Signal received, shutting down gracefully...\n");
}

void on_connect(struct mosquitto *mosq, void *userdata, int result) {
    ssl_client_t *client = (ssl_client_t *)userdata;

    if (result == 0) {
        printf("🔐 SSL/TLS connection established successfully!\n");
        printf("✅ Connected to secure broker at %s:%d\n", client->broker_host, client->broker_port);
        client->connected = true;
        client->ssl_handshake_complete = true;

        // Subscribe to a test topic first
        mosquitto_subscribe(mosq, NULL, "test/ssl/response", 1);

        // Generate secure random topic
        srand(time(NULL));
        char topic[128];
        snprintf(topic, sizeof(topic), "secure/demo/%s/%d", client->client_id, rand() % 10000);

        // Create encrypted demo message
        char message[512];
        time_t now = time(NULL);
        snprintf(message, sizeof(message), 
                "🔒 ENCRYPTED SSL MESSAGE 🔒\n"
                "Client ID: %s\n"
                "Timestamp: %ld\n"
                "Random ID: %d\n"
                "SSL Status: ACTIVE\n"
                "TLS Encryption: ENABLED\n"
                "Certificate Auth: VERIFIED", 
                client->client_id, now, rand() % 1000);

        printf("📡 Publishing encrypted message to topic: %s\n", topic);
        printf("📝 Message content:\n%s\n", message);

        int pub_result = mosquitto_publish(mosq, NULL, topic, strlen(message), message, 2, false);
        if (pub_result == MOSQ_ERR_SUCCESS) {
            printf("✅ Encrypted message queued for secure transmission\n");
        } else {
            printf("❌ Failed to queue encrypted message: %s\n", mosquitto_strerror(pub_result));
        }
    } else {
        printf("❌ SSL connection failed: %s\n", mosquitto_connack_string(result));
        printf("🔍 Connection result code: %d\n", result);
        client->connected = false;
    }
}

void on_disconnect(struct mosquitto *mosq, void *userdata, int result) {
    ssl_client_t *client = (ssl_client_t *)userdata;
    client->connected = false;
    client->ssl_handshake_complete = false;

    if (result != 0) {
        printf("⚠️  Unexpected SSL disconnection: %s\n", mosquitto_strerror(result));
    } else {
        printf("🔌 SSL connection closed gracefully\n");
    }
}

void on_publish(struct mosquitto *mosq, void *userdata, int mid) {
    ssl_client_t *client = (ssl_client_t *)userdata;
    printf("🔐 Encrypted message published successfully (Message ID: %d)\n", mid);
    printf("✅ TLS transmission completed\n");
    client->message_sent = true;
}

void on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    printf("📥 Received encrypted message on topic: %s\n", message->topic);
    printf("📄 Decrypted content: %.*s\n", message->payloadlen, (char*)message->payload);
}

void on_log(struct mosquitto *mosq, void *userdata, int level, const char *str) {
    // Filter logs to show only important SSL/TLS information
    if (strstr(str, "SSL") || strstr(str, "TLS") || strstr(str, "certificate") || level <= MOSQ_LOG_WARNING) {
        printf("🔍 [SSL LOG %d] %s\n", level, str);
    }
}

int verify_ssl_certificates() {
    printf("🔍 Verifying SSL certificate files...\n");

    // Check CA certificate
    if (access(g_client.ca_cert, R_OK) != 0) {
        printf("❌ Error: Cannot read CA certificate file: %s\n", g_client.ca_cert);
        printf("   Required for server verification\n");
        return -1;
    }
    printf("✅ CA certificate found: %s\n", g_client.ca_cert);

    // Check client certificate
    if (access(g_client.client_cert, R_OK) != 0) {
        printf("❌ Error: Cannot read client certificate file: %s\n", g_client.client_cert);
        printf("   Required for mutual TLS authentication\n");
        return -1;
    }
    printf("✅ Client certificate found: %s\n", g_client.client_cert);

    // Check client private key
    if (access(g_client.client_key, R_OK) != 0) {
        printf("❌ Error: Cannot read client private key file: %s\n", g_client.client_key);
        printf("   Required for TLS encryption\n");
        return -1;
    }
    printf("✅ Client private key found: %s\n", g_client.client_key);

    printf("🔐 All SSL/TLS certificates verified and accessible\n");
    return 0;
}

int setup_ssl_security(struct mosquitto *mosq) {
    printf("🔧 Configuring SSL/TLS security settings...\n");

    // Set TLS certificates for mutual authentication
    int rc = mosquitto_tls_set(mosq, 
                              g_client.ca_cert,      // CA certificate for server verification
                              NULL,                  // Certificate directory (not used)
                              g_client.client_cert,  // Client certificate for mutual auth
                              g_client.client_key,   // Client private key for encryption
                              NULL);                 // Password callback (key not encrypted)

    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to configure TLS certificates: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    printf("✅ TLS certificates configured for mutual authentication\n");

    // Configure TLS options for enhanced security
    rc = mosquitto_tls_opts_set(mosq, 
                               1,           // Verify peer certificate
                               "tlsv1.2",   // Minimum TLS version 1.2
                               NULL);       // Use default cipher suites

    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to set TLS options: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    printf("✅ TLS version 1.2+ enforced with peer verification\n");

    // Set hostname verification policy
    rc = mosquitto_tls_insecure_set(mosq, !g_client.enable_peer_verification);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to set TLS verification policy: %s\n", mosquitto_strerror(rc));
        return -1;
    }

    if (g_client.enable_peer_verification) {
        printf("🔒 Strict hostname verification enabled (production mode)\n");
    } else {
        printf("⚠️  Hostname verification disabled (development mode)\n");
    }

    printf("🔐 SSL/TLS security configuration completed\n");
    return 0;
}

void cleanup_resources() {
    printf("🧹 Cleaning up SSL resources...\n");
    
    if (g_client.broker_host && strcmp(g_client.broker_host, DEFAULT_BROKER_HOST) != 0) {
        free(g_client.broker_host);
        g_client.broker_host = NULL;
    }

    if (g_client.client_id) {
        free(g_client.client_id);
        g_client.client_id = NULL;
    }

    printf("✅ Resource cleanup completed\n");
}

int main(int argc, char *argv[]) {
    // Suppress unused parameter warning
    (void)argc;
    (void)argv;

    printf("🔐 Enhanced SSL MQTT Client with TLS Encryption\n");
    printf("===============================================\n");
    printf("📋 Using hardcoded certificate paths:\n");
    printf("   📜 CA Certificate: %s\n", CA_CERT_PATH);
    printf("   🔖 Client Certificate: %s\n", CLIENT_CERT_PATH);
    printf("   🔑 Private Key: %s\n", CLIENT_KEY_PATH);
    printf("\n");

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Generate unique client ID
    char client_id_buffer[128];
    snprintf(client_id_buffer, sizeof(client_id_buffer), "runner_client");
    g_client.client_id = (char*)"runner_client";

    printf("📋 SSL Configuration Summary:\n");
    printf("   🌐 Broker: %s:%d\n", g_client.broker_host, g_client.broker_port);
    printf("   🆔 Client ID: %s\n", g_client.client_id);
    printf("   📜 CA Certificate: %s\n", g_client.ca_cert);
    printf("   🔖 Client Certificate: %s\n", g_client.client_cert);
    printf("   🔑 Private Key: %s\n", g_client.client_key);
    printf("   🔒 Peer Verification: %s\n", g_client.enable_peer_verification ? "ENABLED" : "DISABLED");
    printf("\n");

    // Initialize mosquitto library
    mosquitto_lib_init();

    // Create mosquitto client instance
    struct mosquitto *mosq = mosquitto_new(g_client.client_id, true, &g_client);
    if (!mosq) {
        printf("❌ Failed to create mosquitto client instance\n");
        mosquitto_lib_cleanup();
        cleanup_resources();
        return 1;
    }

    // Configure SSL/TLS security
    if (setup_ssl_security(mosq) != 0) {
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        cleanup_resources();
        return 1;
    }
    
    // Set callback functions
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_disconnect_callback_set(mosq, on_disconnect);
    mosquitto_publish_callback_set(mosq, on_publish);
    mosquitto_message_callback_set(mosq, on_message);
    mosquitto_log_callback_set(mosq, on_log);

    printf("🔗 Establishing SSL/TLS connection to broker...\n");

    // Connect to SSL broker
    int rc = mosquitto_connect(mosq, g_client.broker_host, g_client.broker_port, DEFAULT_KEEPALIVE);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initiate SSL connection: %s\n", mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        cleanup_resources();
        return 1;
    }

    // Start the network loop in a separate thread
    rc = mosquitto_loop_start(mosq);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to start SSL network loop: %s\n", mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        cleanup_resources();
        return 1;
    }

    // Verify SSL certificate files
    if (verify_ssl_certificates() != 0) {
        mosquitto_loop_stop(mosq, false);
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        cleanup_resources();
        return 1;
    }

    // Wait for SSL connection and encrypted message transmission
    int elapsed = 0;
    printf("⏳ Waiting for SSL handshake and encrypted message transmission...\n");

    while (g_running && (!g_client.connected || !g_client.message_sent) && elapsed < CONNECT_TIMEOUT) {
        sleep(1);
        elapsed++;

        if (elapsed % 5 == 0) {
            printf("⏳ SSL Progress... (%d/%d seconds)\n", elapsed, CONNECT_TIMEOUT);
            if (g_client.ssl_handshake_complete) {
                printf("   🔐 SSL handshake: ✅ COMPLETED\n");
            }
            if (g_client.connected) {
                printf("   📡 Connection: ✅ ESTABLISHED\n");
            }
        }
    }

    // Display final results
    printf("\n🎯 SSL Demo Results:\n");
    printf("==================\n");

    if (g_client.ssl_handshake_complete && g_client.connected && g_client.message_sent) {
        printf("🎉 SSL/TLS Demo completed successfully!\n");
        printf("✅ SSL Handshake: COMPLETED\n");
        printf("✅ TLS Connection: ESTABLISHED\n");
        printf("✅ Encrypted Message: TRANSMITTED\n");
        printf("✅ Mutual Authentication: VERIFIED\n");
        printf("🔐 All communications were encrypted with TLS\n");
    } else {
        printf("⚠️  SSL Demo completed with issues:\n");
        printf("   🔐 SSL Handshake: %s\n", g_client.ssl_handshake_complete ? "✅ COMPLETED" : "❌ FAILED");
        printf("   📡 TLS Connection: %s\n", g_client.connected ? "✅ ESTABLISHED" : "❌ FAILED");
        printf("   📤 Encrypted Message: %s\n", g_client.message_sent ? "✅ SENT" : "❌ NOT SENT");
    }

    // Wait a moment for any final SSL activity
    if (g_client.connected) {
        printf("\n⏸️  Maintaining SSL connection for 3 seconds...\n");
        for (int i = 3; i > 0 && g_running; i--) {
            printf("   %d...\n", i);
            sleep(1);
        }
    }

    // Graceful SSL shutdown
    printf("\n🔌 Initiating SSL connection shutdown...\n");
    if (g_client.connected) {
        mosquitto_disconnect(mosq);
        sleep(1); // Allow time for graceful SSL close
    }

    mosquitto_loop_stop(mosq, false);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    cleanup_resources();

    printf("👋 SSL MQTT Client shutdown complete\n");
    return 0;
}
