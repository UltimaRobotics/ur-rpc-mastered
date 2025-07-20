#include "mqtt_broker.h"
#include "network.h"
#include "ssl_wrapper.h"
#include "message_handler.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>

static mqtt_broker_t *g_broker = NULL;

static void signal_handler(int sig) {
    if (g_broker) {
        mqtt_broker_stop(g_broker);
    }
}

int mqtt_broker_init(mqtt_broker_t *broker, const char *config_file) {
    if (!broker || !config_file) {
        LOG_ERROR("Invalid parameters");
        return -1;
    }

    memset(broker, 0, sizeof(mqtt_broker_t));
    broker->listen_fd = -1;
    broker->ssl_listen_fd = -1;
    broker->epoll_fd = -1;
    broker->running = false;
    broker->start_time = time(NULL);

    // Load configuration
    if (config_load(&broker->config, config_file) != 0) {
        LOG_ERROR("Failed to load configuration from %s", config_file);
        return -1;
    }

    // Initialize client manager
    if (client_manager_init(&broker->client_manager, broker->config.max_clients) != 0) {
        LOG_ERROR("Failed to initialize client manager");
        config_cleanup(&broker->config);
        return -1;
    }

    // Create epoll instance
    broker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (broker->epoll_fd == -1) {
        LOG_ERROR("Failed to create epoll instance: %s", strerror(errno));
        mqtt_broker_cleanup(broker);
        return -1;
    }

    // Initialize SSL if enabled
    if (broker->config.ssl_enabled) {
        if (ssl_init(&broker->config) != 0) {
            LOG_ERROR("Failed to initialize SSL");
            mqtt_broker_cleanup(broker);
            return -1;
        }
    }

    // Create TCP listener
    broker->listen_fd = network_create_listener(broker->config.port, broker->config.bind_address);
    if (broker->listen_fd == -1) {
        LOG_ERROR("Failed to create TCP listener on port %d", broker->config.port);
        mqtt_broker_cleanup(broker);
        return -1;
    }

    // Add TCP listener to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = broker->listen_fd;
    if (epoll_ctl(broker->epoll_fd, EPOLL_CTL_ADD, broker->listen_fd, &ev) == -1) {
        LOG_ERROR("Failed to add TCP listener to epoll: %s", strerror(errno));
        mqtt_broker_cleanup(broker);
        return -1;
    }

    // Create SSL listener if enabled
    if (broker->config.ssl_enabled && broker->config.ssl_port > 0) {
        broker->ssl_listen_fd = network_create_listener(broker->config.ssl_port, broker->config.bind_address);
        if (broker->ssl_listen_fd == -1) {
            LOG_ERROR("Failed to create SSL listener on port %d", broker->config.ssl_port);
            mqtt_broker_cleanup(broker);
            return -1;
        }

        // Add SSL listener to epoll
        ev.events = EPOLLIN;
        ev.data.fd = broker->ssl_listen_fd;
        if (epoll_ctl(broker->epoll_fd, EPOLL_CTL_ADD, broker->ssl_listen_fd, &ev) == -1) {
            LOG_ERROR("Failed to add SSL listener to epoll: %s", strerror(errno));
            mqtt_broker_cleanup(broker);
            return -1;
        }
    }

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    g_broker = broker;

    LOG_INFO("MQTT broker initialized successfully");
    LOG_INFO("TCP listener on %s:%d", broker->config.bind_address, broker->config.port);
    if (broker->config.ssl_enabled && broker->config.ssl_port > 0) {
        LOG_INFO("SSL listener on %s:%d", broker->config.bind_address, broker->config.ssl_port);
    }

    return 0;
}

int mqtt_broker_run(mqtt_broker_t *broker) {
    if (!broker) {
        LOG_ERROR("Invalid broker pointer");
        return -1;
    }

    broker->running = true;
    LOG_INFO("Starting MQTT broker main loop");

    while (broker->running) {
        int nfds = epoll_wait(broker->epoll_fd, broker->events, MAX_EVENTS, 1000);
        
        if (nfds == -1) {
            if (errno == EINTR) {
                continue; // Interrupted by signal
            }
            LOG_ERROR("epoll_wait failed: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = broker->events[i].data.fd;
            uint32_t events = broker->events[i].events;

            if (fd == broker->listen_fd) {
                // New TCP connection
                if (mqtt_broker_accept_client(broker, broker->listen_fd, false) != 0) {
                    LOG_WARNING("Failed to accept TCP client");
                }
            } else if (fd == broker->ssl_listen_fd) {
                // New SSL connection
                if (mqtt_broker_accept_client(broker, broker->ssl_listen_fd, true) != 0) {
                    LOG_WARNING("Failed to accept SSL client");
                }
            } else {
                // Client data or disconnection
                if (events & (EPOLLERR | EPOLLHUP)) {
                    mqtt_broker_disconnect_client(broker, fd);
                } else if (events & EPOLLIN) {
                    if (mqtt_broker_handle_client_data(broker, fd) != 0) {
                        mqtt_broker_disconnect_client(broker, fd);
                    }
                }
            }
        }

        // Periodic cleanup of disconnected clients
        client_manager_cleanup_disconnected(&broker->client_manager);
    }

    LOG_INFO("MQTT broker main loop stopped");
    return 0;
}

void mqtt_broker_stop(mqtt_broker_t *broker) {
    if (broker) {
        broker->running = false;
        LOG_INFO("Broker stop requested");
    }
}

void mqtt_broker_cleanup(mqtt_broker_t *broker) {
    if (!broker) return;

    broker->running = false;

    if (broker->epoll_fd != -1) {
        close(broker->epoll_fd);
        broker->epoll_fd = -1;
    }

    if (broker->listen_fd != -1) {
        close(broker->listen_fd);
        broker->listen_fd = -1;
    }

    if (broker->ssl_listen_fd != -1) {
        close(broker->ssl_listen_fd);
        broker->ssl_listen_fd = -1;
    }

    client_manager_cleanup(&broker->client_manager);
    
    if (broker->config.ssl_enabled) {
        ssl_cleanup();
    }

    config_cleanup(&broker->config);

    LOG_INFO("MQTT broker cleanup completed");
}

int mqtt_broker_accept_client(mqtt_broker_t *broker, int listen_fd, bool use_ssl) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd == -1) {
        LOG_WARNING("Failed to accept client: %s", strerror(errno));
        return -1;
    }

    // Set socket to non-blocking
    if (network_set_nonblocking(client_fd) != 0) {
        LOG_WARNING("Failed to set client socket non-blocking");
        close(client_fd);
        return -1;
    }

    // Create client structure
    mqtt_client_t *client = client_manager_create_client(&broker->client_manager, client_fd, use_ssl);
    if (!client) {
        LOG_WARNING("Failed to create client structure");
        close(client_fd);
        return -1;
    }

    // Initialize SSL for this client if needed
    if (use_ssl && ssl_accept_client(client) != 0) {
        LOG_WARNING("Failed to initialize SSL for client");
        client_manager_remove_client(&broker->client_manager, client_fd);
        close(client_fd);
        return -1;
    }

    // Add client to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; // Edge-triggered
    ev.data.fd = client_fd;
    if (epoll_ctl(broker->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
        LOG_WARNING("Failed to add client to epoll: %s", strerror(errno));
        client_manager_remove_client(&broker->client_manager, client_fd);
        close(client_fd);
        return -1;
    }

    char client_ip[INET6_ADDRSTRLEN];
    network_get_peer_address(client_fd, client_ip, sizeof(client_ip));
    LOG_INFO("New %s client connected from %s (fd=%d)", 
             use_ssl ? "SSL" : "TCP", client_ip, client_fd);

    broker->total_clients++;
    return 0;
}

int mqtt_broker_handle_client_data(mqtt_broker_t *broker, int client_fd) {
    mqtt_client_t *client = client_manager_get_client(&broker->client_manager, client_fd);
    if (!client) {
        LOG_WARNING("Received data from unknown client fd=%d", client_fd);
        return -1;
    }

    // Handle incoming data
    int result = message_handler_process_client(client, broker);
    if (result < 0) {
        LOG_DEBUG("Client fd=%d processing failed", client_fd);
        return -1;
    }

    return 0;
}

void mqtt_broker_disconnect_client(mqtt_broker_t *broker, int client_fd) {
    mqtt_client_t *client = client_manager_get_client(&broker->client_manager, client_fd);
    if (client) {
        LOG_INFO("Client disconnected (fd=%d, client_id=%s)", 
                 client_fd, client->client_id ? client->client_id : "unknown");
        
        // Send will message if needed
        if (client->will_flag && client->will_topic && client->will_message) {
            message_handler_publish_will(broker, client);
        }
    }

    // Remove from epoll
    epoll_ctl(broker->epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    
    // Remove client and close socket
    client_manager_remove_client(&broker->client_manager, client_fd);
    close(client_fd);
}

void mqtt_broker_get_stats(mqtt_broker_t *broker, uint64_t *uptime_seconds, 
                          uint32_t *active_clients, uint64_t *total_messages) {
    if (!broker) return;

    if (uptime_seconds) {
        *uptime_seconds = time(NULL) - broker->start_time;
    }
    if (active_clients) {
        *active_clients = broker->client_manager.active_count;
    }
    if (total_messages) {
        *total_messages = broker->total_messages;
    }
}
