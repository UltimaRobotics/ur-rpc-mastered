#ifndef NOTIFICATION_MANAGER_H
#define NOTIFICATION_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "client_manager.h"

#define MAX_NOTIFICATION_TOPIC_LEN 256
#define MAX_NOTIFICATION_CLIENT_ID_LEN 64
#define NOTIFICATION_MESSAGE_BUFFER_SIZE 1024

// Forward declarations
typedef struct client_manager client_manager_t;
typedef struct mqtt_client mqtt_client_t;

// Notification event types
typedef enum {
    NOTIFICATION_CLIENT_CONNECTED = 0,
    NOTIFICATION_CLIENT_DISCONNECTED,
    NOTIFICATION_CLIENT_SUBSCRIBE,
    NOTIFICATION_CLIENT_UNSUBSCRIBE,
    NOTIFICATION_CLIENT_PUBLISH,
    NOTIFICATION_TOPIC_SUBSCRIBE,
    NOTIFICATION_TOPIC_PUBLISH
} notification_event_type_t;

// Notification subscriber
typedef struct notification_subscriber {
    char client_id[MAX_NOTIFICATION_CLIENT_ID_LEN];
    char notification_topic[MAX_NOTIFICATION_TOPIC_LEN];
    bool ssl_enabled;
    bool active;
    time_t subscribed_time;
    uint64_t notifications_sent;
    struct notification_subscriber* next;
} notification_subscriber_t;

// Notification configuration
typedef struct {
    bool enabled;
    char default_notification_topic[MAX_NOTIFICATION_TOPIC_LEN];
    bool include_client_details;
    bool include_ssl_info;
    bool include_timestamp;
    uint32_t max_subscribers;
    uint32_t notification_qos;
} notification_config_t;

// Notification manager
typedef struct notification_manager {
    notification_subscriber_t* subscribers;
    uint32_t subscriber_count;
    notification_config_t config;
    pthread_mutex_t mutex;
    uint64_t total_notifications_sent;
} notification_manager_t;

/**
 * Initialize notification manager
 * @param manager Pointer to notification manager
 * @param config_file Path to configuration file (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int notification_manager_init(notification_manager_t* manager, const char* config_file);

/**
 * Cleanup notification manager
 * @param manager Pointer to notification manager
 */
void notification_manager_cleanup(notification_manager_t* manager);

/**
 * Add notification subscriber
 * @param manager Pointer to notification manager
 * @param client_id Client ID that wants to receive notifications
 * @param notification_topic Topic to send notifications to
 * @param ssl_enabled Whether the subscriber uses SSL
 * @return 0 on success, -1 on error
 */
int notification_manager_add_subscriber(notification_manager_t* manager, 
                                      const char* client_id, 
                                      const char* notification_topic,
                                      bool ssl_enabled);

/**
 * Remove notification subscriber
 * @param manager Pointer to notification manager
 * @param client_id Client ID to remove
 * @return 0 on success, -1 on error
 */
int notification_manager_remove_subscriber(notification_manager_t* manager, 
                                         const char* client_id);

/**
 * Send connection notification
 * @param manager Pointer to notification manager
 * @param client_manager Pointer to client manager
 * @param event_type Type of notification event
 * @param client_id Client ID that triggered the event
 * @param client_info Additional client information
 * @return 0 on success, -1 on error
 */
int notification_manager_send_notification(notification_manager_t* manager,
                                          client_manager_t* client_manager,
                                          notification_event_type_t event_type,
                                          const char* client_id,
                                          const char* client_info);

/**
 * Send topic-specific notification (publish/subscribe)
 * @param manager Pointer to notification manager
 * @param client_manager Pointer to client manager
 * @param event_type Type of notification event
 * @param source_client_id Client ID that triggered the event
 * @param source_ip Source IP address
 * @param topic_name Topic name involved in the event
 * @param destination_client_id Target client ID for notification (from config)
 * @return 0 on success, -1 on error
 */
int notification_manager_send_topic_notification(notification_manager_t* manager,
                                                client_manager_t* client_manager,
                                                notification_event_type_t event_type,
                                                const char* source_client_id,
                                                const char* source_ip,
                                                const char* topic_name,
                                                const char* destination_client_id);

/**
 * Create JSON notification message
 * @param event_type Type of notification event
 * @param client_id Client ID
 * @param client_info Additional client information
 * @param config Notification configuration
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return 0 on success, -1 on error
 */
int notification_manager_create_message(notification_event_type_t event_type,
                                       const char* client_id,
                                       const char* client_info,
                                       const notification_config_t* config,
                                       char* buffer,
                                       size_t buffer_size);

/**
 * Load notification configuration from file
 * @param config Pointer to configuration structure
 * @param config_file Path to configuration file
 * @return 0 on success, -1 on error
 */
int notification_manager_load_config(notification_config_t* config, const char* config_file);

/**
 * Get notification statistics
 * @param manager Pointer to notification manager
 * @param subscriber_count Pointer to store subscriber count
 * @param total_notifications Pointer to store total notifications sent
 */
void notification_manager_get_stats(notification_manager_t* manager,
                                   uint32_t* subscriber_count,
                                   uint64_t* total_notifications);

/**
 * Check if client is a notification subscriber
 * @param manager Pointer to notification manager
 * @param client_id Client ID to check
 * @return true if subscriber, false otherwise
 */
bool notification_manager_is_subscriber(notification_manager_t* manager, const char* client_id);

#endif /* NOTIFICATION_MANAGER_H */