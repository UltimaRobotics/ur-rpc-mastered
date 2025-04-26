/**
 * @file main.c
 * @brief Main entry point for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "mqtt_broker.h"
#include "config.h"
#include "logger.h"

// Signal flag
static volatile int running = 1;

// Signal handler
static void signal_handler(int sig) {
    running = 0;
}

int main(int argc, char *argv[]) {
    const char *config_file = "config/broker.json";
    const broker_config_t *broker_config;
    mqtt_broker_config_t mqtt_config;
    
    // Check for custom config file path
    if (argc > 1) {
        config_file = argv[1];
    }
    
    // Initialize configuration
    if (config_init(config_file) != 0) {
        fprintf(stderr, "Failed to initialize configuration from: %s\n", config_file);
        return 1;
    }
    
    // Get broker configuration
    broker_config = config_get_broker();
    if (!broker_config) {
        fprintf(stderr, "Failed to get broker configuration\n");
        config_cleanup();
        return 1;
    }
    
    // Initialize MQTT configuration
    mqtt_config.port = broker_config->port;
    mqtt_config.max_connections = broker_config->max_connections;
    mqtt_config.max_message_size = broker_config->max_message_size;
    mqtt_config.persistence_dir = broker_config->persistence_dir;
    mqtt_config.log_level = broker_config->log_level;
    mqtt_config.auth_file = broker_config->auth_file;
    mqtt_config.disconnect_handler_config = broker_config->disconnect_handler_config;
    
    // Initialize MQTT broker
    if (mqtt_broker_init(&mqtt_config) != 0) {
        fprintf(stderr, "Failed to initialize MQTT broker\n");
        config_cleanup();
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Start MQTT broker
    if (mqtt_broker_start() != 0) {
        fprintf(stderr, "Failed to start MQTT broker\n");
        mqtt_broker_cleanup();
        config_cleanup();
        return 1;
    }
    
    // Main loop
    while (running) {
        // Just sleep for a bit
        sleep(1);
    }
    
    // Stop the broker
    mqtt_broker_stop();
    
    // Clean up
    mqtt_broker_cleanup();
    config_cleanup();
    
    return 0;
}