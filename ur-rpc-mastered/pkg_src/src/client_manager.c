#include "client_manager.h"
#include "notification_manager.h"
#include "network.h"
#include "ssl_wrapper.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

int client_manager_init(client_manager_t *manager, uint32_t max_clients) {
    if (!manager) {
        LOG_ERROR("Invalid parameters");
        return -1;
    }
    
    memset(manager, 0, sizeof(client_manager_t));
    manager->max_clients = max_clients;
    manager->last_cleanup = time(NULL);
    manager->notification_manager = NULL;
    
    LOG_INFO("Client manager initialized (max_clients=%u)", max_clients);
    return 0;
}

void client_manager_cleanup(client_manager_t *manager) {
    if (!manager) return;
    
    mqtt_client_t *client = manager->clients;
    while (client) {
        mqtt_client_t *next = client->next;
        client_manager_remove_client(manager, client->socket_fd);
        client = next;
    }
    
    memset(manager, 0, sizeof(client_manager_t));
    LOG_INFO("Client manager cleanup completed");
}

static void client_free_subscriptions(mqtt_client_t *client) {
    if (!client) return;
    
    mqtt_subscription_t *sub = client->subscriptions;
    while (sub) {
        mqtt_subscription_t *next = sub->next;
        free(sub);
        sub = next;
    }
    client->subscriptions = NULL;
    client->subscription_count = 0;
}

static void client_free_pending_messages(mqtt_client_t *client) {
    if (!client) return;
    
    // Free outgoing pending messages
    pending_message_t *msg = client->pending_out;
    while (msg) {
        pending_message_t *next = msg->next;
        free(msg->data);
        free(msg);
        msg = next;
    }
    client->pending_out = NULL;
    
    // Free incoming pending messages
    msg = client->pending_in;
    while (msg) {
        pending_message_t *next = msg->next;
        free(msg->data);
        free(msg);
        msg = next;
    }
    client->pending_in = NULL;
}

mqtt_client_t* client_manager_create_client(client_manager_t *manager, int socket_fd, bool use_ssl) {
    if (!manager || socket_fd < 0) {
        LOG_ERROR("Invalid parameters");
        return NULL;
    }
    
    if (manager->active_count >= manager->max_clients) {
        LOG_WARNING("Maximum clients reached (%u)", manager->max_clients);
        return NULL;
    }
    
    mqtt_client_t *client = malloc(sizeof(mqtt_client_t));
    if (!client) {
        LOG_ERROR("Failed to allocate client structure");
        return NULL;
    }
    
    memset(client, 0, sizeof(mqtt_client_t));
    client->socket_fd = socket_fd;
    client->state = MQTT_CLIENT_CONNECTING;
    client->use_ssl = use_ssl;
    client->connect_time = time(NULL);
    client->last_activity = client->connect_time;
    client->next_packet_id = 1;
    client->clean_session = true;
    client->wants_notifications = false;
    memset(client->notification_topic, 0, sizeof(client->notification_topic));
    
    // Add to linked list
    client->next = manager->clients;
    manager->clients = client;
    manager->active_count++;
    manager->total_connections++;
    
    LOG_DEBUG("Created client for fd=%d (ssl=%s, total=%u)", 
              socket_fd, use_ssl ? "yes" : "no", manager->active_count);
    
    return client;
}

void client_manager_remove_client(client_manager_t *manager, int socket_fd) {
    if (!manager) return;
    
    mqtt_client_t **current = &manager->clients;
    while (*current) {
        mqtt_client_t *client = *current;
        if (client->socket_fd == socket_fd) {
            // Remove from linked list
            *current = client->next;
            
            // Cleanup client resources
            free(client->username);
            free(client->password);
            free(client->will_topic);
            free(client->will_message);
            
            client_free_subscriptions(client);
            client_free_pending_messages(client);
            
            if (client->ssl_ctx) {
                ssl_free_client_context(client->ssl_ctx);
            }
            
            free(client);
            manager->active_count--;
            
            LOG_DEBUG("Removed client fd=%d (active=%u)", socket_fd, manager->active_count);
            return;
        }
        current = &client->next;
    }
    
    LOG_WARNING("Client fd=%d not found for removal", socket_fd);
}

mqtt_client_t* client_manager_get_client(client_manager_t *manager, int socket_fd) {
    if (!manager) return NULL;
    
    mqtt_client_t *client = manager->clients;
    while (client) {
        if (client->socket_fd == socket_fd) {
            return client;
        }
        client = client->next;
    }
    
    return NULL;
}

mqtt_client_t* client_manager_get_client_by_id(client_manager_t *manager, const char *client_id) {
    if (!manager || !client_id) return NULL;
    
    mqtt_client_t *client = manager->clients;
    while (client) {
        if (client->client_id[0] && strcmp(client->client_id, client_id) == 0) {
            return client;
        }
        client = client->next;
    }
    
    return NULL;
}

int client_manager_add_subscription(mqtt_client_t *client, const char *topic_filter, uint8_t qos) {
    if (!client || !topic_filter || qos > 2) {
        LOG_ERROR("Invalid subscription parameters");
        return -1;
    }
    
    if (client->subscription_count >= MAX_SUBSCRIPTIONS) {
        LOG_WARNING("Maximum subscriptions reached for client %s", client->client_id);
        return -1;
    }
    
    // Check if already subscribed
    mqtt_subscription_t *sub = client->subscriptions;
    while (sub) {
        if (strcmp(sub->topic_filter, topic_filter) == 0) {
            // Update QoS
            sub->qos = qos;
            sub->active = true;
            LOG_DEBUG("Updated subscription for client %s: %s (QoS %u)", 
                     client->client_id, topic_filter, qos);
            return 0;
        }
        sub = sub->next;
    }
    
    // Create new subscription
    sub = malloc(sizeof(mqtt_subscription_t));
    if (!sub) {
        LOG_ERROR("Failed to allocate subscription");
        return -1;
    }
    
    memset(sub, 0, sizeof(mqtt_subscription_t));
    strncpy(sub->topic_filter, topic_filter, sizeof(sub->topic_filter) - 1);
    sub->qos = qos;
    sub->active = true;
    sub->next = client->subscriptions;
    
    client->subscriptions = sub;
    client->subscription_count++;
    
    LOG_DEBUG("Added subscription for client %s: %s (QoS %u)", 
             client->client_id, topic_filter, qos);
    
    return 0;
}

int client_manager_remove_subscription(mqtt_client_t *client, const char *topic_filter) {
    if (!client || !topic_filter) return -1;
    
    mqtt_subscription_t **current = &client->subscriptions;
    while (*current) {
        mqtt_subscription_t *sub = *current;
        if (strcmp(sub->topic_filter, topic_filter) == 0) {
            *current = sub->next;
            free(sub);
            client->subscription_count--;
            
            LOG_DEBUG("Removed subscription for client %s: %s", 
                     client->client_id, topic_filter);
            return 0;
        }
        current = &sub->next;
    }
    
    return -1;
}

bool client_manager_is_subscribed(mqtt_client_t *client, const char *topic, uint8_t *qos) {
    if (!client || !topic) return false;
    
    mqtt_subscription_t *sub = client->subscriptions;
    while (sub) {
        if (sub->active && mqtt_topic_matches_filter(sub->topic_filter, topic)) {
            if (qos) *qos = sub->qos;
            return true;
        }
        sub = sub->next;
    }
    
    return false;
}

uint16_t client_manager_get_next_packet_id(mqtt_client_t *client) {
    if (!client) return 0;
    
    uint16_t packet_id = client->next_packet_id++;
    if (client->next_packet_id == 0) {
        client->next_packet_id = 1; // Skip 0
    }
    
    return packet_id;
}

int client_manager_add_pending_message(mqtt_client_t *client, uint16_t packet_id, 
                                      const uint8_t *data, uint32_t data_len, uint8_t qos) {
    if (!client || !data || data_len == 0 || qos == 0) return -1;
    
    pending_message_t *msg = malloc(sizeof(pending_message_t));
    if (!msg) {
        LOG_ERROR("Failed to allocate pending message");
        return -1;
    }
    
    msg->data = malloc(data_len);
    if (!msg->data) {
        LOG_ERROR("Failed to allocate pending message data");
        free(msg);
        return -1;
    }
    
    memcpy(msg->data, data, data_len);
    msg->packet_id = packet_id;
    msg->data_len = data_len;
    msg->timestamp = time(NULL);
    msg->retry_count = 0;
    msg->qos = qos;
    
    // Add to outgoing list
    msg->next = client->pending_out;
    client->pending_out = msg;
    
    LOG_DEBUG("Added pending message for client %s: packet_id=%u, qos=%u", 
             client->client_id, packet_id, qos);
    
    return 0;
}

int client_manager_remove_pending_message(mqtt_client_t *client, uint16_t packet_id, bool outgoing) {
    if (!client) return -1;
    
    pending_message_t **list = outgoing ? &client->pending_out : &client->pending_in;
    pending_message_t **current = list;
    
    while (*current) {
        pending_message_t *msg = *current;
        if (msg->packet_id == packet_id) {
            *current = msg->next;
            free(msg->data);
            free(msg);
            
            LOG_DEBUG("Removed pending message for client %s: packet_id=%u (%s)", 
                     client->client_id, packet_id, outgoing ? "out" : "in");
            return 0;
        }
        current = &msg->next;
    }
    
    return -1;
}

pending_message_t* client_manager_get_pending_message(mqtt_client_t *client, uint16_t packet_id, bool outgoing) {
    if (!client) return NULL;
    
    pending_message_t *list = outgoing ? client->pending_out : client->pending_in;
    pending_message_t *current = list;
    
    while (current) {
        if (current->packet_id == packet_id) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

void client_manager_update_activity(mqtt_client_t *client) {
    if (client) {
        client->last_activity = time(NULL);
    }
}

bool client_manager_is_keepalive_expired(mqtt_client_t *client) {
    if (!client || client->keep_alive == 0) return false;
    
    time_t now = time(NULL);
    time_t timeout = client->keep_alive + (client->keep_alive / 2); // 1.5x keep alive
    
    return (now - client->last_activity) > timeout;
}

bool client_manager_check_rate_limit(mqtt_client_t *client, uint32_t max_rate) {
    if (!client || max_rate == 0) return true;
    
    time_t now = time(NULL);
    
    // Reset counter every minute
    if (now - client->last_publish_time >= 60) {
        client->publish_count_minute = 0;
        client->last_publish_time = now;
    }
    
    if (client->publish_count_minute >= max_rate) {
        LOG_WARNING("Rate limit exceeded for client %s: %u/%u per minute", 
                   client->client_id, client->publish_count_minute, max_rate);
        return false;
    }
    
    client->publish_count_minute++;
    return true;
}

void client_manager_cleanup_disconnected(client_manager_t *manager) {
    if (!manager) return;
    
    time_t now = time(NULL);
    
    // Only run cleanup every 30 seconds
    if (now - manager->last_cleanup < 30) return;
    
    manager->last_cleanup = now;
    
    mqtt_client_t **current = &manager->clients;
    uint32_t cleaned = 0;
    
    while (*current) {
        mqtt_client_t *client = *current;
        
        bool should_remove = false;
        
        // Check keep-alive timeout
        if (client->state == MQTT_CLIENT_CONNECTED && 
            client_manager_is_keepalive_expired(client)) {
            LOG_INFO("Client %s keep-alive expired", client->client_id);
            should_remove = true;
        }
        
        // Check connection state
        if (client->state == MQTT_CLIENT_DISCONNECTED) {
            should_remove = true;
        }
        
        // Check socket status
        if (!should_remove && network_is_connected(client->socket_fd) <= 0) {
            LOG_DEBUG("Client %s socket disconnected", client->client_id);
            should_remove = true;
        }
        
        if (should_remove) {
            *current = client->next;
            
            // Cleanup client resources
            close(client->socket_fd);
            free(client->username);
            free(client->password);
            free(client->will_topic);
            free(client->will_message);
            
            client_free_subscriptions(client);
            client_free_pending_messages(client);
            
            if (client->ssl_ctx) {
                ssl_free_client_context(client->ssl_ctx);
            }
            
            free(client);
            manager->active_count--;
            cleaned++;
        } else {
            current = &client->next;
        }
    }
    
    if (cleaned > 0) {
        LOG_DEBUG("Cleaned up %u disconnected clients (active=%u)", cleaned, manager->active_count);
    }
}

void client_manager_get_stats(mqtt_client_t *client, uint64_t *uptime_seconds,
                             uint64_t *messages_sent, uint64_t *messages_received,
                             uint64_t *bytes_sent, uint64_t *bytes_received) {
    if (!client) return;
    
    time_t now = time(NULL);
    
    if (uptime_seconds) {
        *uptime_seconds = now - client->connect_time;
    }
    if (messages_sent) {
        *messages_sent = client->messages_sent;
    }
    if (messages_received) {
        *messages_received = client->messages_received;
    }
    if (bytes_sent) {
        *bytes_sent = client->bytes_sent;
    }
    if (bytes_received) {
        *bytes_received = client->bytes_received;
    }
}

ssize_t client_manager_send(mqtt_client_t *client, const void *data, size_t length) {
    if (!client || !data || length == 0) return -1;
    
    ssize_t sent;
    
    if (client->use_ssl && client->ssl_ctx) {
        sent = ssl_send(client->ssl_ctx, data, length);
    } else {
        sent = network_send(client->socket_fd, data, length);
    }
    
    if (sent > 0) {
        client->bytes_sent += sent;
        client_manager_update_activity(client);
    }
    
    return sent;
}

ssize_t client_manager_recv(mqtt_client_t *client, void *buffer, size_t length) {
    if (!client || !buffer || length == 0) return -1;
    
    ssize_t received;
    
    if (client->use_ssl && client->ssl_ctx) {
        received = ssl_recv(client->ssl_ctx, buffer, length);
    } else {
        received = network_recv(client->socket_fd, buffer, length);
    }
    
    if (received > 0) {
        client->bytes_received += received;
        client_manager_update_activity(client);
    }
    
    return received;
}

// Notification support functions

void client_manager_set_notification_manager(client_manager_t* manager, 
                                            notification_manager_t* notification_manager) {
    if (!manager) return;
    
    manager->notification_manager = notification_manager;
    LOG_DEBUG("Set notification manager reference in client manager");
}

int client_manager_handle_connect(client_manager_t* manager, mqtt_client_t* client, 
                                 const char* client_id) {
    if (!manager || !client || !client_id) {
        return -1;
    }

    // Set client ID
    strncpy(client->client_id, client_id, MAX_CLIENT_ID_LEN - 1);
    client->client_id[MAX_CLIENT_ID_LEN - 1] = '\0';
    
    // Set client state
    client->state = MQTT_CLIENT_CONNECTED;

    // Send connection notification
    if (manager->notification_manager) {
        char client_info[512];
        snprintf(client_info, sizeof(client_info), 
                "{\"ssl_enabled\":%s,\"connect_time\":%ld,\"socket_fd\":%d}", 
                client->use_ssl ? "true" : "false",
                client->connect_time,
                client->socket_fd);

        notification_manager_send_notification(manager->notification_manager,
                                              manager,
                                              NOTIFICATION_CLIENT_CONNECTED,
                                              client_id,
                                              client_info);
    }

    LOG_INFO("Client connected: %s (SSL: %s, FD: %d)", 
           client_id, client->use_ssl ? "yes" : "no", client->socket_fd);

    return 0;
}

int client_manager_handle_disconnect(client_manager_t* manager, mqtt_client_t* client) {
    if (!manager || !client) {
        return -1;
    }

    // Send disconnection notification before removing the client
    if (manager->notification_manager && client->client_id[0]) {
        time_t now = time(NULL);
        uint64_t uptime = now - client->connect_time;
        
        char client_info[512];
        snprintf(client_info, sizeof(client_info), 
                "{\"ssl_enabled\":%s,\"connect_time\":%ld,\"disconnect_time\":%ld,\"uptime_seconds\":%llu,\"messages_sent\":%llu,\"messages_received\":%llu,\"socket_fd\":%d}", 
                client->use_ssl ? "true" : "false",
                client->connect_time,
                now,
                (unsigned long long)uptime,
                (unsigned long long)client->messages_sent,
                (unsigned long long)client->messages_received,
                client->socket_fd);

        notification_manager_send_notification(manager->notification_manager,
                                              manager,
                                              NOTIFICATION_CLIENT_DISCONNECTED,
                                              client->client_id,
                                              client_info);

        // Remove client from notification subscribers if it was one
        notification_manager_remove_subscriber(manager->notification_manager, 
                                             client->client_id);
    }

    LOG_INFO("Client disconnected: %s (FD: %d)", 
           client->client_id[0] ? client->client_id : "unknown", client->socket_fd);

    return 0;
}

int client_manager_enable_notifications(mqtt_client_t* client, const char* notification_topic) {
    if (!client) {
        return -1;
    }

    client->wants_notifications = true;
    
    if (notification_topic) {
        strncpy(client->notification_topic, notification_topic, MAX_TOPIC_LEN - 1);
        client->notification_topic[MAX_TOPIC_LEN - 1] = '\0';
    } else {
        // Use default notification topic
        strcpy(client->notification_topic, "broker/notifications");
    }

    LOG_DEBUG("Enabled notifications for client %s -> topic: %s", 
            client->client_id, client->notification_topic);

    return 0;
}

int client_manager_disable_notifications(mqtt_client_t* client) {
    if (!client) {
        return -1;
    }

    client->wants_notifications = false;
    memset(client->notification_topic, 0, sizeof(client->notification_topic));

    LOG_DEBUG("Disabled notifications for client %s", client->client_id);

    return 0;
}
