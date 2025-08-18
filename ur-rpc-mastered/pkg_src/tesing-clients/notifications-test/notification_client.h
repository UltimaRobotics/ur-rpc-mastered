
#ifndef NOTIFICATION_CLIENT_H
#define NOTIFICATION_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>

// Configuration constants
#define BROKER_HOST "127.0.0.1"
#define BROKER_PORT 1855
#define CLIENT_ID "notification_client"
#define TOPIC "broker/notifications"
#define MAX_BUFFER_SIZE 4096
#define MAX_CLIENTS 100
#define MAX_STRING_LEN 256

// MQTT packet types
#define MQTT_CONNECT     1
#define MQTT_CONNACK     2
#define MQTT_PUBLISH     3
#define MQTT_SUBSCRIBE   8
#define MQTT_SUBACK      9

// Notification event types matching broker implementation
typedef enum {
    EVENT_UNKNOWN = 0,
    EVENT_CLIENT_CONNECTED = 1,
    EVENT_CLIENT_DISCONNECTED = 2,
    EVENT_TOPIC_SUBSCRIBED = 3,
    EVENT_TOPIC_PUBLISHED = 4,
    EVENT_CLIENT_PUBLISHED = 5,
    EVENT_CLIENT_SUBSCRIBED = 6,
    EVENT_CLIENT_UNSUBSCRIBED = 7,
    EVENT_SSL_HANDSHAKE = 8,
    EVENT_AUTHENTICATION_FAILED = 9,
    EVENT_KEEPALIVE_TIMEOUT = 10
} notification_event_t;

// Client information structure
typedef struct {
    char client_id[MAX_STRING_LEN];
    char source_ip[64];
    char topic[MAX_STRING_LEN];
    char username[MAX_STRING_LEN];
    char protocol_version[16];
    int socket_fd;
    bool ssl_enabled;
    bool clean_session;
    int keepalive_interval;
    time_t connect_time;
    time_t disconnect_time;
    unsigned long messages_sent;
    unsigned long messages_received;
    unsigned long bytes_sent;
    unsigned long bytes_received;
    int qos_level;
    notification_event_t last_event;
    char last_error[MAX_STRING_LEN];
} client_info_t;

// Notification message structure
typedef struct {
    notification_event_t event_type;
    char event_name[64];
    time_t timestamp;
    client_info_t client_data;
    char raw_payload[MAX_BUFFER_SIZE];
    int payload_length;
} notification_message_t;

// Client database structure
typedef struct {
    client_info_t clients[MAX_CLIENTS];
    int client_count;
    int total_notifications;
    time_t start_time;
} client_database_t;

// Function prototypes
int create_connect_packet(unsigned char *buffer, const char *client_id);
int create_subscribe_packet(unsigned char *buffer, const char *topic);
void extract_json_value(const char *json, const char *key, char *value, int max_len);
void extract_json_number(const char *json, const char *key, long *value);
void extract_json_bool(const char *json, const char *key, bool *value);

notification_event_t identify_notification_action(const char *event_str);
const char* get_event_name(notification_event_t event);
int parse_notification_payload(const char *payload, notification_message_t *notification);
void update_client_database(client_database_t *db, const notification_message_t *notification);
client_info_t* find_client_by_id(client_database_t *db, const char *client_id);

void parse_mqtt_packet(unsigned char *buffer, int length, client_database_t *db);
void print_notification_summary(const notification_message_t *notification);
void print_client_database(const client_database_t *db);
void print_statistics(const client_database_t *db);

int connect_to_broker(void);
int subscribe_to_notifications(int sock);
int run_notification_listener(void);

#endif // NOTIFICATION_CLIENT_H
