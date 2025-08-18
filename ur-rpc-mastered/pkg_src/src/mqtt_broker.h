#ifndef MQTT_BROKER_H
#define MQTT_BROKER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include "config.h"
#include "client_manager.h"

// Forward declarations
typedef struct notification_manager notification_manager_t;

#define MAX_EVENTS 64
#define MQTT_BROKER_VERSION "1.0.0"

typedef struct mqtt_broker {
    int listen_fd;
    int ssl_listen_fd;
    int epoll_fd;
    struct epoll_event events[MAX_EVENTS];
    broker_config_t config;
    client_manager_t client_manager;
    notification_manager_t* notification_manager;
    bool running;
    uint64_t total_messages;
    uint64_t total_clients;
    time_t start_time;
} mqtt_broker_t;

/**
 * Initialize the MQTT broker
 * @param broker Pointer to broker structure
 * @param config_file Path to configuration file
 * @return 0 on success, -1 on error
 */
int mqtt_broker_init(mqtt_broker_t *broker, const char *config_file);

/**
 * Start the broker main loop
 * @param broker Pointer to broker structure
 * @return 0 on success, -1 on error
 */
int mqtt_broker_run(mqtt_broker_t *broker);

/**
 * Stop the broker gracefully
 * @param broker Pointer to broker structure
 */
void mqtt_broker_stop(mqtt_broker_t *broker);

/**
 * Cleanup broker resources
 * @param broker Pointer to broker structure
 */
void mqtt_broker_cleanup(mqtt_broker_t *broker);

/**
 * Handle new client connection
 * @param broker Pointer to broker structure
 * @param listen_fd Listening socket file descriptor
 * @param use_ssl Whether to use SSL for this connection
 * @return 0 on success, -1 on error
 */
int mqtt_broker_accept_client(mqtt_broker_t *broker, int listen_fd, bool use_ssl);

/**
 * Handle client data
 * @param broker Pointer to broker structure
 * @param client_fd Client socket file descriptor
 * @return 0 on success, -1 on error
 */
int mqtt_broker_handle_client_data(mqtt_broker_t *broker, int client_fd);

/**
 * Handle client disconnection
 * @param broker Pointer to broker structure
 * @param client_fd Client socket file descriptor
 */
void mqtt_broker_disconnect_client(mqtt_broker_t *broker, int client_fd);

/**
 * Get broker statistics
 * @param broker Pointer to broker structure
 * @param uptime_seconds Pointer to store uptime in seconds
 * @param active_clients Pointer to store active client count
 * @param total_messages Pointer to store total message count
 */
void mqtt_broker_get_stats(mqtt_broker_t *broker, uint64_t *uptime_seconds, 
                          uint32_t *active_clients, uint64_t *total_messages);

#endif /* MQTT_BROKER_H */
