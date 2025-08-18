#include "notification_manager.h"
#include "mqtt_protocol.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <cJSON.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Default configuration values
static const notification_config_t DEFAULT_CONFIG = {
    .enabled = true,
    .default_notification_topic = "broker/notifications",
    .include_client_details = true,
    .include_ssl_info = true,
    .include_timestamp = true,
    .max_subscribers = 100,
    .notification_qos = 1
};

int notification_manager_init(notification_manager_t* manager, const char* config_file) {
    if (!manager) {
        return -1;
    }

    memset(manager, 0, sizeof(notification_manager_t));
    
    // Initialize mutex
    if (pthread_mutex_init(&manager->mutex, NULL) != 0) {
        return -1;
    }

    // Load configuration
    if (config_file) {
        if (notification_manager_load_config(&manager->config, config_file) != 0) {
            LOG_WARNING("Failed to load notification config from %s, using defaults", config_file);
            manager->config = DEFAULT_CONFIG;
        }
    } else {
        manager->config = DEFAULT_CONFIG;
    }

    LOG_INFO("Notification manager initialized (enabled: %s)", 
           manager->config.enabled ? "yes" : "no");

    return 0;
}

void notification_manager_cleanup(notification_manager_t* manager) {
    if (!manager) return;

    pthread_mutex_lock(&manager->mutex);

    // Free all subscribers
    notification_subscriber_t* current = manager->subscribers;
    while (current) {
        notification_subscriber_t* next = current->next;
        free(current);
        current = next;
    }

    manager->subscribers = NULL;
    manager->subscriber_count = 0;

    pthread_mutex_unlock(&manager->mutex);
    pthread_mutex_destroy(&manager->mutex);

    LOG_INFO("Notification manager cleaned up");
}

int notification_manager_add_subscriber(notification_manager_t* manager, 
                                      const char* client_id, 
                                      const char* notification_topic,
                                      bool ssl_enabled) {
    if (!manager || !client_id) {
        return -1;
    }

    if (!manager->config.enabled) {
        return 0; // Silently ignore if notifications disabled
    }

    pthread_mutex_lock(&manager->mutex);

    // Check if subscriber already exists
    notification_subscriber_t* existing = manager->subscribers;
    while (existing) {
        if (strcmp(existing->client_id, client_id) == 0) {
            // Update existing subscriber
            if (notification_topic) {
                strncpy(existing->notification_topic, notification_topic, 
                       MAX_NOTIFICATION_TOPIC_LEN - 1);
                existing->notification_topic[MAX_NOTIFICATION_TOPIC_LEN - 1] = '\0';
            }
            existing->ssl_enabled = ssl_enabled;
            existing->active = true;
            existing->subscribed_time = time(NULL);
            
            pthread_mutex_unlock(&manager->mutex);
            LOG_INFO("Updated notification subscriber: %s -> %s", 
                   client_id, existing->notification_topic);
            return 0;
        }
        existing = existing->next;
    }

    // Check subscriber limit
    if (manager->subscriber_count >= manager->config.max_subscribers) {
        pthread_mutex_unlock(&manager->mutex);
        LOG_ERROR("Maximum notification subscribers limit reached (%u)", 
               manager->config.max_subscribers);
        return -1;
    }

    // Create new subscriber
    notification_subscriber_t* subscriber = malloc(sizeof(notification_subscriber_t));
    if (!subscriber) {
        pthread_mutex_unlock(&manager->mutex);
        return -1;
    }

    strncpy(subscriber->client_id, client_id, MAX_NOTIFICATION_CLIENT_ID_LEN - 1);
    subscriber->client_id[MAX_NOTIFICATION_CLIENT_ID_LEN - 1] = '\0';

    if (notification_topic) {
        strncpy(subscriber->notification_topic, notification_topic, 
               MAX_NOTIFICATION_TOPIC_LEN - 1);
        subscriber->notification_topic[MAX_NOTIFICATION_TOPIC_LEN - 1] = '\0';
    } else {
        strncpy(subscriber->notification_topic, manager->config.default_notification_topic, 
               MAX_NOTIFICATION_TOPIC_LEN - 1);
        subscriber->notification_topic[MAX_NOTIFICATION_TOPIC_LEN - 1] = '\0';
    }

    subscriber->ssl_enabled = ssl_enabled;
    subscriber->active = true;
    subscriber->subscribed_time = time(NULL);
    subscriber->notifications_sent = 0;
    subscriber->next = manager->subscribers;

    manager->subscribers = subscriber;
    manager->subscriber_count++;

    pthread_mutex_unlock(&manager->mutex);

    LOG_INFO("Added notification subscriber: %s -> %s (SSL: %s)", 
           client_id, subscriber->notification_topic, ssl_enabled ? "yes" : "no");

    return 0;
}

int notification_manager_remove_subscriber(notification_manager_t* manager, 
                                         const char* client_id) {
    if (!manager || !client_id) {
        return -1;
    }

    pthread_mutex_lock(&manager->mutex);

    notification_subscriber_t* current = manager->subscribers;
    notification_subscriber_t* prev = NULL;

    while (current) {
        if (strcmp(current->client_id, client_id) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                manager->subscribers = current->next;
            }

            LOG_INFO("Removed notification subscriber: %s (sent %llu notifications)", 
                   client_id, (unsigned long long)current->notifications_sent);

            free(current);
            manager->subscriber_count--;
            
            pthread_mutex_unlock(&manager->mutex);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    pthread_mutex_unlock(&manager->mutex);
    return -1; // Not found
}

int notification_manager_create_message(notification_event_type_t event_type,
                                       const char* client_id,
                                       const char* client_info,
                                       const notification_config_t* config,
                                       char* buffer,
                                       size_t buffer_size) {
    if (!client_id || !config || !buffer || buffer_size == 0) {
        return -1;
    }

    cJSON* json = cJSON_CreateObject();
    if (!json) return -1;

    // Event type with matching IDs from notification_client.h
    const char* event_str;
    int event_id;
    switch (event_type) {
        case NOTIFICATION_CLIENT_CONNECTED:
            event_str = "client_connected";
            event_id = 1; // EVENT_CLIENT_CONNECTED
            break;
        case NOTIFICATION_CLIENT_DISCONNECTED:
            event_str = "client_disconnected";
            event_id = 2; // EVENT_CLIENT_DISCONNECTED
            break;
        case NOTIFICATION_CLIENT_SUBSCRIBE:
            event_str = "client_subscribed";
            event_id = 6; // EVENT_CLIENT_SUBSCRIBED
            break;
        case NOTIFICATION_CLIENT_UNSUBSCRIBE:
            event_str = "client_unsubscribed";
            event_id = 7; // EVENT_CLIENT_UNSUBSCRIBED
            break;
        case NOTIFICATION_CLIENT_PUBLISH:
            event_str = "client_published";
            event_id = 5; // EVENT_CLIENT_PUBLISHED
            break;
        case NOTIFICATION_TOPIC_SUBSCRIBE:
            event_str = "topic_subscribed";
            event_id = 3; // EVENT_TOPIC_SUBSCRIBED
            break;
        case NOTIFICATION_TOPIC_PUBLISH:
            event_str = "topic_published";
            event_id = 4; // EVENT_TOPIC_PUBLISHED
            break;
        default:
            event_str = "unknown";
            event_id = 0; // EVENT_UNKNOWN
            break;
    }

    // Enhanced event information matching notification_client.h structs
    cJSON_AddStringToObject(json, "event", event_str);
    cJSON_AddNumberToObject(json, "event_id", event_id);
    cJSON_AddStringToObject(json, "source_client_id", client_id);

    // Always include timestamp for proper event tracking
    time_t current_time = time(NULL);
    cJSON_AddNumberToObject(json, "timestamp", (double)current_time);

    // Enhanced client data structure matching client_info_t
    if (config->include_client_details) {
        cJSON* client_data = cJSON_CreateObject();
        if (client_data) {
            cJSON_AddStringToObject(client_data, "client_id", client_id);
            cJSON_AddStringToObject(client_data, "source_ip", "127.0.0.1"); // Default, can be enhanced
            cJSON_AddStringToObject(client_data, "topic", ""); // Will be filled for topic events
            cJSON_AddStringToObject(client_data, "username", ""); // Will be filled if available
            cJSON_AddNumberToObject(client_data, "socket_fd", 0);
            cJSON_AddBoolToObject(client_data, "ssl_enabled", false);
            cJSON_AddBoolToObject(client_data, "clean_session", true);
            cJSON_AddNumberToObject(client_data, "keepalive_interval", 60);
            cJSON_AddNumberToObject(client_data, "messages_sent", 0);
            cJSON_AddNumberToObject(client_data, "messages_received", 0);
            cJSON_AddNumberToObject(client_data, "bytes_sent", 0);
            cJSON_AddNumberToObject(client_data, "bytes_received", 0);
            cJSON_AddNumberToObject(client_data, "qos_level", 0);
            cJSON_AddNumberToObject(client_data, "connect_time", (double)current_time);
            cJSON_AddNumberToObject(client_data, "disconnect_time", 0);
            
            // Parse additional client_info if provided
            if (client_info) {
                cJSON* info_json = cJSON_Parse(client_info);
                if (info_json) {
                    // Merge additional info into client_data
                    cJSON* item = info_json->child;
                    while (item) {
                        cJSON* copy = cJSON_Duplicate(item, 1);
                        if (copy) {
                            cJSON_ReplaceItemInObject(client_data, item->string, copy);
                        }
                        item = item->next;
                    }
                    cJSON_Delete(info_json);
                } else {
                    cJSON_AddStringToObject(client_data, "additional_info", client_info);
                }
            }
            
            cJSON_AddItemToObject(json, "client_data", client_data);
        }
    }

    char* json_string = cJSON_Print(json);
    if (!json_string) {
        cJSON_Delete(json);
        return -1;
    }

    size_t json_len = strlen(json_string);
    if (json_len >= buffer_size) {
        free(json_string);
        cJSON_Delete(json);
        return -1;
    }

    strcpy(buffer, json_string);
    free(json_string);
    cJSON_Delete(json);

    return 0;
}

// Create a proper MQTT PUBLISH packet for notifications
static int notification_manager_create_publish_packet(uint8_t* buffer, size_t buffer_size,
                                                     const char* topic, const char* payload,
                                                     uint8_t qos) {
    if (!buffer || !topic || !payload || buffer_size < 64) {
        return -1;
    }

    size_t topic_len = strlen(topic);
    size_t payload_len = strlen(payload);
    size_t total_len = 2 + topic_len + payload_len;  // topic length field + topic + payload
    
    if (qos > 0) {
        total_len += 2;  // packet identifier for QoS > 0
    }
    
    if (total_len + 4 > buffer_size) {  // +4 for fixed header
        return -1;
    }

    uint8_t* ptr = buffer;
    
    // Fixed header
    *ptr++ = (MQTT_PUBLISH << 4) | (qos << 1);  // Message type and QoS flags
    
    // Remaining length (simplified - only handles single byte)
    if (total_len < 128) {
        *ptr++ = (uint8_t)total_len;
    } else {
        // Multi-byte remaining length encoding
        *ptr++ = (uint8_t)((total_len & 0x7F) | 0x80);
        *ptr++ = (uint8_t)(total_len >> 7);
    }
    
    // Topic length (big endian)
    *ptr++ = (uint8_t)(topic_len >> 8);
    *ptr++ = (uint8_t)(topic_len & 0xFF);
    
    // Topic
    memcpy(ptr, topic, topic_len);
    ptr += topic_len;
    
    // Packet identifier for QoS > 0 (simplified - using fixed ID)
    if (qos > 0) {
        *ptr++ = 0x00;
        *ptr++ = 0x01;
    }
    
    // Payload
    memcpy(ptr, payload, payload_len);
    ptr += payload_len;
    
    return (int)(ptr - buffer);
}

int notification_manager_send_notification(notification_manager_t* manager,
                                          client_manager_t* client_manager,
                                          notification_event_type_t event_type,
                                          const char* client_id,
                                          const char* client_info) {
    if (!manager || !client_manager || !client_id) {
        return -1;
    }

    if (!manager->config.enabled) {
        LOG_DEBUG("Notifications disabled, ignoring %s event for client %s", 
                event_type == NOTIFICATION_CLIENT_CONNECTED ? "connect" : "disconnect", client_id);
        return 0; // Silently ignore if notifications disabled
    }
    
    LOG_DEBUG("Processing notification: %s event for client %s", 
            event_type == NOTIFICATION_CLIENT_CONNECTED ? "connect" : "disconnect", client_id);

    char message_buffer[NOTIFICATION_MESSAGE_BUFFER_SIZE];
    
    // Create notification message
    if (notification_manager_create_message(event_type, client_id, client_info, 
                                           &manager->config, message_buffer, 
                                           sizeof(message_buffer)) != 0) {
        LOG_ERROR("Failed to create notification message");
        return -1;
    }

    int notifications_sent = 0;
    const char* notification_topic = manager->config.default_notification_topic;

    // Send notification to all clients subscribed to the notification topic
    mqtt_client_t* client = client_manager->clients;
    LOG_DEBUG("Checking connected clients for notification topic subscription");
    while (client) {
        if (client->state == MQTT_CLIENT_CONNECTED) {
            LOG_DEBUG("Checking client %s for subscription to %s", client->client_id, notification_topic);
            // Check if client is subscribed to notification topic
            uint8_t qos;
            if (client_manager_is_subscribed(client, notification_topic, &qos)) {
                LOG_DEBUG("Client %s is subscribed to %s, sending notification", client->client_id, notification_topic);
                // Create proper MQTT PUBLISH packet
                uint8_t publish_buffer[2048];
                int packet_len = notification_manager_create_publish_packet(
                    publish_buffer, sizeof(publish_buffer),
                    notification_topic, message_buffer, qos);
                
                if (packet_len > 0) {
                    if (client_manager_send(client, publish_buffer, packet_len) > 0) {
                        notifications_sent++;
                        LOG_DEBUG("Sent notification to client %s on topic %s", 
                                client->client_id, notification_topic);
                    }
                }
            }
        }
        client = client->next;
    }

    pthread_mutex_lock(&manager->mutex);
    manager->total_notifications_sent += notifications_sent;
    pthread_mutex_unlock(&manager->mutex);

    if (notifications_sent > 0) {
        LOG_INFO("Sent %d notifications for %s event (client: %s)",
               notifications_sent, 
               event_type == NOTIFICATION_CLIENT_CONNECTED ? "connect" :
               event_type == NOTIFICATION_CLIENT_DISCONNECTED ? "disconnect" :
               event_type == NOTIFICATION_CLIENT_SUBSCRIBE ? "subscribe" : "unsubscribe",
               client_id);
    }

    return notifications_sent;
}

int notification_manager_load_config(notification_config_t* config, const char* config_file) {
    if (!config || !config_file) {
        return -1;
    }

    // Start with defaults
    *config = DEFAULT_CONFIG;

    FILE* file = fopen(config_file, "r");
    if (!file) {
        return -1;
    }

    // Read file content
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* file_content = malloc(file_size + 1);
    if (!file_content) {
        fclose(file);
        return -1;
    }

    size_t read_size = fread(file_content, 1, file_size, file);
    file_content[read_size] = '\0';
    fclose(file);

    // Parse JSON
    cJSON* json = cJSON_Parse(file_content);
    free(file_content);

    if (!json) {
        return -1;
    }

    // Parse configuration fields
    cJSON* enabled = cJSON_GetObjectItem(json, "enabled");
    if (cJSON_IsBool(enabled)) {
        config->enabled = cJSON_IsTrue(enabled);
    }

    cJSON* default_topic = cJSON_GetObjectItem(json, "default_notification_topic");
    if (cJSON_IsString(default_topic)) {
        strncpy(config->default_notification_topic, cJSON_GetStringValue(default_topic), 
               MAX_NOTIFICATION_TOPIC_LEN - 1);
        config->default_notification_topic[MAX_NOTIFICATION_TOPIC_LEN - 1] = '\0';
    }

    cJSON* include_details = cJSON_GetObjectItem(json, "include_client_details");
    if (cJSON_IsBool(include_details)) {
        config->include_client_details = cJSON_IsTrue(include_details);
    }

    cJSON* include_ssl = cJSON_GetObjectItem(json, "include_ssl_info");
    if (cJSON_IsBool(include_ssl)) {
        config->include_ssl_info = cJSON_IsTrue(include_ssl);
    }

    cJSON* include_timestamp = cJSON_GetObjectItem(json, "include_timestamp");
    if (cJSON_IsBool(include_timestamp)) {
        config->include_timestamp = cJSON_IsTrue(include_timestamp);
    }

    cJSON* max_subscribers = cJSON_GetObjectItem(json, "max_subscribers");
    if (cJSON_IsNumber(max_subscribers)) {
        config->max_subscribers = (uint32_t)cJSON_GetNumberValue(max_subscribers);
    }

    cJSON* qos = cJSON_GetObjectItem(json, "notification_qos");
    if (cJSON_IsNumber(qos)) {
        int qos_val = (int)cJSON_GetNumberValue(qos);
        if (qos_val >= 0 && qos_val <= 2) {
            config->notification_qos = (uint32_t)qos_val;
        }
    }

    cJSON_Delete(json);

    LOG_INFO("Loaded notification configuration from %s", config_file);
    return 0;
}

void notification_manager_get_stats(notification_manager_t* manager,
                                   uint32_t* subscriber_count,
                                   uint64_t* total_notifications) {
    if (!manager) return;

    pthread_mutex_lock(&manager->mutex);

    if (subscriber_count) {
        *subscriber_count = manager->subscriber_count;
    }

    if (total_notifications) {
        *total_notifications = manager->total_notifications_sent;
    }

    pthread_mutex_unlock(&manager->mutex);
}

bool notification_manager_is_subscriber(notification_manager_t* manager, const char* client_id) {
    if (!manager || !client_id) {
        return false;
    }

    pthread_mutex_lock(&manager->mutex);

    notification_subscriber_t* current = manager->subscribers;
    while (current) {
        if (strcmp(current->client_id, client_id) == 0 && current->active) {
            pthread_mutex_unlock(&manager->mutex);
            return true;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&manager->mutex);
    return false;
}

// Enhanced topic notification function for publish/subscribe events
int notification_manager_send_topic_notification(notification_manager_t* manager,
                                                client_manager_t* client_manager,
                                                notification_event_type_t event_type,
                                                const char* source_client_id,
                                                const char* source_ip,
                                                const char* topic_name,
                                                const char* destination_client_id) {
    if (!manager || !client_manager || !source_client_id || !topic_name) {
        return -1;
    }

    if (!manager->config.enabled) {
        return 0; // Silently ignore if notifications disabled
    }

    // Create comprehensive JSON notification message
    cJSON* json = cJSON_CreateObject();
    if (!json) return -1;

    // Event type
    const char* event_str;
    int event_id;
    switch (event_type) {
        case NOTIFICATION_TOPIC_SUBSCRIBE:
            event_str = "topic_subscribed";
            event_id = 3; // EVENT_TOPIC_SUBSCRIBED from notification_client.h
            break;
        case NOTIFICATION_TOPIC_PUBLISH:
            event_str = "topic_published";
            event_id = 4; // EVENT_TOPIC_PUBLISHED from notification_client.h
            break;
        case NOTIFICATION_CLIENT_PUBLISH:
            event_str = "client_published";
            event_id = 5; // EVENT_CLIENT_PUBLISHED from notification_client.h
            break;
        default:
            event_str = "topic_event";
            event_id = 0;
            break;
    }

    // Enhanced event information matching notification_client.h structs
    cJSON_AddStringToObject(json, "event", event_str);
    cJSON_AddNumberToObject(json, "event_id", event_id);
    cJSON_AddStringToObject(json, "source_client_id", source_client_id);
    cJSON_AddStringToObject(json, "topic", topic_name);
    
    if (source_ip) {
        cJSON_AddStringToObject(json, "source_ip", source_ip);
    }
    
    // Always include timestamp for proper event tracking
    time_t current_time = time(NULL);
    cJSON_AddNumberToObject(json, "timestamp", (double)current_time);
    
    // Get detailed client information for enhanced notification
    mqtt_client_t* source_client = client_manager_get_client_by_id(client_manager, source_client_id);
    if (source_client) {
        // Create client_data object with detailed information
        cJSON* client_data = cJSON_CreateObject();
        if (client_data) {
            cJSON_AddStringToObject(client_data, "client_id", source_client_id);
            cJSON_AddStringToObject(client_data, "source_ip", source_ip ? source_ip : "unknown");
            cJSON_AddStringToObject(client_data, "topic", topic_name);
            cJSON_AddStringToObject(client_data, "username", source_client->username ? source_client->username : "");
            cJSON_AddNumberToObject(client_data, "socket_fd", source_client->socket_fd);
            cJSON_AddBoolToObject(client_data, "ssl_enabled", source_client->use_ssl);
            cJSON_AddBoolToObject(client_data, "clean_session", source_client->clean_session);
            cJSON_AddNumberToObject(client_data, "keepalive_interval", source_client->keep_alive);
            cJSON_AddNumberToObject(client_data, "messages_sent", 0); // Not tracked in this struct
            cJSON_AddNumberToObject(client_data, "messages_received", 0); // Not tracked in this struct
            cJSON_AddNumberToObject(client_data, "bytes_sent", 0); // Not tracked in this struct
            cJSON_AddNumberToObject(client_data, "bytes_received", 0); // Not tracked in this struct
            cJSON_AddNumberToObject(client_data, "qos_level", 0); // Default QoS for this event
            cJSON_AddNumberToObject(client_data, "connect_time", (double)source_client->connect_time);
            
            cJSON_AddItemToObject(json, "client_data", client_data);
        }
    }

    // Convert to JSON string
    char* json_string = cJSON_Print(json);
    if (!json_string) {
        cJSON_Delete(json);
        return -1;
    }

    int notifications_sent = 0;

    pthread_mutex_lock(&manager->mutex);

    // Send notification to the specific destination client if specified
    if (destination_client_id && strlen(destination_client_id) > 0) {
        mqtt_client_t* target_client = client_manager_get_client_by_id(
            client_manager, destination_client_id);
        
        if (target_client && target_client->state == MQTT_CLIENT_CONNECTED) {
            // Create a proper MQTT PUBLISH packet for the notification
            uint8_t publish_buffer[2048];
            
            // Use the broker's notification topic from config
            const char* notification_topic = manager->config.default_notification_topic;
            
            // Create MQTT publish structure
            mqtt_publish_t publish;
            memset(&publish, 0, sizeof(publish));
            publish.topic = (char*)notification_topic;
            publish.payload = (uint8_t*)json_string;
            publish.payload_len = strlen(json_string);
            publish.qos = MQTT_QOS_0;
            publish.retain = false;
            publish.dup = false;
            publish.packet_id = 0; // Not needed for QoS 0
            
            int msg_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
            
            if (msg_len > 0) {
                if (client_manager_send(target_client, publish_buffer, msg_len) > 0) {
                    notifications_sent++;
                    LOG_INFO("Sent topic notification to client %s: %s on topic %s", 
                           destination_client_id, event_str, topic_name);
                }
            }
        } else {
            LOG_WARNING("Target notification client %s not found or not connected", 
                       destination_client_id);
        }
    }

    // Also send to all registered notification subscribers (existing behavior)
    notification_subscriber_t* subscriber = manager->subscribers;
    while (subscriber) {
        if (subscriber->active && strcmp(subscriber->client_id, source_client_id) != 0) {
            mqtt_client_t* notify_client = client_manager_get_client_by_id(
                client_manager, subscriber->client_id);
            
            if (notify_client && notify_client->state == MQTT_CLIENT_CONNECTED) {
                uint8_t publish_buffer[2048];
                
                // Create MQTT publish structure
                mqtt_publish_t publish;
                memset(&publish, 0, sizeof(publish));
                publish.topic = subscriber->notification_topic;
                publish.payload = (uint8_t*)json_string;
                publish.payload_len = strlen(json_string);
                publish.qos = MQTT_QOS_0;
                publish.retain = false;
                publish.dup = false;
                publish.packet_id = 0; // Not needed for QoS 0
                
                int msg_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
                
                if (msg_len > 0) {
                    if (client_manager_send(notify_client, publish_buffer, msg_len) > 0) {
                        subscriber->notifications_sent++;
                        notifications_sent++;
                    }
                }
            }
        }
        subscriber = subscriber->next;
    }

    manager->total_notifications_sent += notifications_sent;

    pthread_mutex_unlock(&manager->mutex);

    free(json_string);
    cJSON_Delete(json);

    if (notifications_sent > 0) {
        LOG_INFO("Sent %d topic notifications for %s event (topic: %s, source: %s)",
               notifications_sent, event_str, topic_name, source_client_id);
    }

    return notifications_sent;
}