/*
 * Simple SSL/TLS MQTT Test Client
 * Basic test to verify SSL connection works before full certificate generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>

#define BROKER_HOST "0.0.0.0"
#define BROKER_PORT 1855
#define CA_CERT_FILE "../../certs/broker/ca.crt"
#define CLIENT_CERT_FILE "../../certs/generator-client/client.crt"
#define CLIENT_KEY_FILE "../../certs/generator-client/client.key"

static volatile bool connected = false;

void on_connect(struct mosquitto *mosq, void *userdata, int result) {
    (void)mosq;
    (void)userdata;
    
    if (result == 0) {
        printf("✓ Successfully connected to SSL broker!\n");
        connected = true;
    } else {
        printf("❌ Connection failed: %s\n", mosquitto_connack_string(result));
    }
}

void on_disconnect(struct mosquitto *mosq, void *userdata, int result) {
    (void)mosq;
    (void)userdata;
    
    printf("🔌 Disconnected: %s\n", result == 0 ? "Clean disconnect" : "Unexpected disconnect");
    connected = false;
}

int main() {
    printf("=== SSL/TLS MQTT Test Client ===\n");
    printf("Testing connection to %s:%d\n", BROKER_HOST, BROKER_PORT);
    
    // Initialize Mosquitto
    if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initialize mosquitto library\n");
        return 1;
    }
    
    // Create client
    struct mosquitto *mosq = mosquitto_new("ssl_test_client", true, NULL);
    if (!mosq) {
        printf("❌ Failed to create mosquitto client\n");
        mosquitto_lib_cleanup();
        return 1;
    }
    
    // Set callbacks
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_disconnect_callback_set(mosq, on_disconnect);
    
    // Setup SSL/TLS
    printf("🔐 Setting up SSL/TLS...\n");
    int result = mosquitto_tls_set(mosq, CA_CERT_FILE, NULL, CLIENT_CERT_FILE, CLIENT_KEY_FILE, NULL);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to set TLS: %s\n", mosquitto_strerror(result));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return 1;
    }
    
    // Disable certificate verification for testing
    mosquitto_tls_insecure_set(mosq, true);
    printf("✓ SSL/TLS configured\n");
    
    // Connect
    printf("🔗 Connecting...\n");
    result = mosquitto_connect(mosq, BROKER_HOST, BROKER_PORT, 60);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initiate connection: %s\n", mosquitto_strerror(result));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return 1;
    }
    
    // Start network loop
    result = mosquitto_loop_start(mosq);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to start network loop: %s\n", mosquitto_strerror(result));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return 1;
    }
    
    // Wait for connection
    int wait_count = 0;
    while (!connected && wait_count < 50) {
        usleep(100000); // 100ms
        wait_count++;
    }
    
    if (connected) {
        printf("🎉 SSL connection test successful!\n");
        printf("📡 Connected to SSL broker on port %d\n", BROKER_PORT);
        
        // Stay connected for a moment
        sleep(2);
        
        mosquitto_disconnect(mosq);
    } else {
        printf("❌ Connection timeout after 5 seconds\n");
    }
    
    // Cleanup
    mosquitto_loop_stop(mosq, true);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    
    return connected ? 0 : 1;
}
