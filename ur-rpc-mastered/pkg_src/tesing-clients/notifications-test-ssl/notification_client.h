
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
#include <pthread.h>
#include <mosquitto.h>

// Add missing declarations for usleep
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

// Configuration constants
#define BROKER_HOST "127.0.0.1"
#define BROKER_PORT_TCP 1856
#define BROKER_PORT_SSL 1855
#define CLIENT_ID "ssl_notification_client"
#define TOPIC "broker/notifications"
#define MAX_BUFFER_SIZE 4096
#define MAX_CLIENTS 100
#define MAX_STRING_LEN 256

// SSL certificate paths (relative to tesing-clients/notifications-test/)
#define CA_CERT_PATH "test-certs/ca.crt"
#define CLIENT_CERT_PATH "test-certs/client.crt"
#define CLIENT_KEY_PATH "test-certs/client.key"

// Connection types
typedef enum {
    CONNECTION_TCP = 0,
    CONNECTION_SSL = 1
} connection_type_t;

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

// SSL configuration structure
typedef struct {
    char ca_cert_path[512];
    char client_cert_path[512];
    char client_key_path[512];
    bool verify_peer;
    bool require_client_cert;
} ssl_config_t;

// Mosquitto connection structure
typedef struct {
    struct mosquitto *mosq;
    bool is_ssl;
    bool connected;
    ssl_config_t config;
    char client_id[256];
    char topic[256];  // Store the topic to subscribe to
    int message_count;
    pthread_mutex_t mutex;
} mosquitto_connection_t;

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

// Mosquitto support functions
int mosquitto_init_library(void);
void mosquitto_cleanup_library(void);
ssl_config_t* ssl_config_create(const char *ca_cert, const char *client_cert, const char *client_key);
mosquitto_connection_t* mosquitto_create_connection(connection_type_t type, ssl_config_t *ssl_config, const char *topic);
void mosquitto_cleanup_connection(mosquitto_connection_t *conn);

// Mosquitto callbacks
void on_connect_callback(struct mosquitto *mosq, void *userdata, int result);
void on_disconnect_callback(struct mosquitto *mosq, void *userdata, int result);
void on_message_callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message);
void on_log_callback(struct mosquitto *mosq, void *userdata, int level, const char *str);

// Connection functions
mosquitto_connection_t* connect_to_broker(connection_type_t type, ssl_config_t *ssl_config, const char *host, int port, const char *topic);
int subscribe_to_notifications(mosquitto_connection_t *conn, const char *topic);
int run_notification_listener(connection_type_t type, ssl_config_t *ssl_config, const char *host, int port, const char *topic);
int run_notification_listener_auto(ssl_config_t *ssl_config, const char *host, int port, const char *topic);
int run_notification_listener_with_certs(const char *ca_cert, const char *client_cert, const char *client_key);

#endif // NOTIFICATION_CLIENT_H
