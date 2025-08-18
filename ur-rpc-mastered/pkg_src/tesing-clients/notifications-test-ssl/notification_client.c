
#include "notification_client.h"

// Global client database
static client_database_t g_client_db = {0};

// Function to create MQTT CONNECT packet
int create_connect_packet(unsigned char *buffer, const char *client_id) {
    int pos = 0;
    
    // Fixed header
    buffer[pos++] = 0x10;  // CONNECT packet type
    
    // Calculate remaining length (we'll update this)
    int remaining_length_pos = pos++;
    
    // Variable header
    // Protocol name length and name
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x04;
    buffer[pos++] = 'M';
    buffer[pos++] = 'Q';
    buffer[pos++] = 'T';
    buffer[pos++] = 'T';
    
    // Protocol version
    buffer[pos++] = 0x04;  // MQTT 3.1.1
    
    // Connect flags (clean session)
    buffer[pos++] = 0x02;
    
    // Keep alive (60 seconds)
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x3C;
    
    // Payload - Client ID
    int client_id_len = strlen(client_id);
    buffer[pos++] = (client_id_len >> 8) & 0xFF;
    buffer[pos++] = client_id_len & 0xFF;
    memcpy(&buffer[pos], client_id, client_id_len);
    pos += client_id_len;
    
    // Update remaining length
    buffer[remaining_length_pos] = pos - 2;
    
    return pos;
}

// Function to create MQTT SUBSCRIBE packet
int create_subscribe_packet(unsigned char *buffer, const char *topic) {
    int pos = 0;
    
    // Fixed header
    buffer[pos++] = 0x82;  // SUBSCRIBE packet type with flags
    
    // Calculate remaining length (we'll update this)
    int remaining_length_pos = pos++;
    
    // Variable header - Packet ID
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x01;
    
    // Payload - Topic filter
    int topic_len = strlen(topic);
    buffer[pos++] = (topic_len >> 8) & 0xFF;
    buffer[pos++] = topic_len & 0xFF;
    memcpy(&buffer[pos], topic, topic_len);
    pos += topic_len;
    
    // QoS level
    buffer[pos++] = 0x00;  // QoS 0
    
    // Update remaining length
    buffer[remaining_length_pos] = pos - 2;
    
    return pos;
}

// Enhanced JSON value extraction (string)
void extract_json_value(const char *json, const char *key, char *value, int max_len) {
    if (!json || !key || !value) return;
    
    char search_key[128];
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);
    
    char *pos = strstr(json, search_key);
    if (pos) {
        pos += strlen(search_key);
        
        // Skip whitespace
        while (*pos == ' ' || *pos == '\t') pos++;
        
        if (*pos == '"') {
            // String value
            pos++;
            char *end = strchr(pos, '"');
            if (end) {
                int len = end - pos;
                if (len < max_len - 1) {
                    strncpy(value, pos, len);
                    value[len] = '\0';
                }
            }
        } else {
            // Number or other value as string
            char *end = pos;
            while (*end && *end != ',' && *end != '}' && *end != '\n' && *end != ' ') end++;
            int len = end - pos;
            if (len < max_len - 1) {
                strncpy(value, pos, len);
                value[len] = '\0';
            }
        }
    }
}

// Extract JSON number
void extract_json_number(const char *json, const char *key, long *value) {
    char str_value[32] = {0};
    extract_json_value(json, key, str_value, sizeof(str_value));
    if (strlen(str_value) > 0) {
        *value = strtol(str_value, NULL, 10);
    }
}

// Extract JSON boolean
void extract_json_bool(const char *json, const char *key, bool *value) {
    char str_value[16] = {0};
    extract_json_value(json, key, str_value, sizeof(str_value));
    if (strlen(str_value) > 0) {
        *value = (strcmp(str_value, "true") == 0);
    }
}

// Identify notification action from event string
notification_event_t identify_notification_action(const char *event_str) {
    if (!event_str) return EVENT_UNKNOWN;
    
    if (strcmp(event_str, "client_connected") == 0) {
        return EVENT_CLIENT_CONNECTED;
    } else if (strcmp(event_str, "client_disconnected") == 0) {
        return EVENT_CLIENT_DISCONNECTED;
    } else if (strcmp(event_str, "client_subscribed") == 0 || 
               strcmp(event_str, "topic_subscribed") == 0) {
        return EVENT_CLIENT_SUBSCRIBED;
    } else if (strcmp(event_str, "client_unsubscribed") == 0 ||
               strcmp(event_str, "topic_unsubscribed") == 0) {
        return EVENT_CLIENT_UNSUBSCRIBED;
    } else if (strcmp(event_str, "topic_published") == 0 ||
               strcmp(event_str, "message_published") == 0) {
        return EVENT_TOPIC_PUBLISHED;
    } else if (strcmp(event_str, "ssl_handshake") == 0) {
        return EVENT_SSL_HANDSHAKE;
    } else if (strcmp(event_str, "auth_failed") == 0) {
        return EVENT_AUTHENTICATION_FAILED;
    } else if (strcmp(event_str, "keepalive_timeout") == 0) {
        return EVENT_KEEPALIVE_TIMEOUT;
    }
    
    return EVENT_UNKNOWN;
}

// Get event name from event type
const char* get_event_name(notification_event_t event) {
    switch (event) {
        case EVENT_CLIENT_CONNECTED: return "CLIENT_CONNECTED";
        case EVENT_CLIENT_DISCONNECTED: return "CLIENT_DISCONNECTED";
        case EVENT_CLIENT_SUBSCRIBED: return "CLIENT_SUBSCRIBED";
        case EVENT_CLIENT_UNSUBSCRIBED: return "CLIENT_UNSUBSCRIBED";
        case EVENT_TOPIC_PUBLISHED: return "TOPIC_PUBLISHED";
        case EVENT_SSL_HANDSHAKE: return "SSL_HANDSHAKE";
        case EVENT_AUTHENTICATION_FAILED: return "AUTH_FAILED";
        case EVENT_KEEPALIVE_TIMEOUT: return "KEEPALIVE_TIMEOUT";
        default: return "UNKNOWN";
    }
}

// Parse notification payload and extract all client parameters
int parse_notification_payload(const char *payload, notification_message_t *notification) {
    if (!payload || !notification) return -1;
    
    // Initialize notification structure
    memset(notification, 0, sizeof(notification_message_t));
    
    // Store raw payload
    strncpy(notification->raw_payload, payload, MAX_BUFFER_SIZE - 1);
    notification->payload_length = strlen(payload);
    
    // Extract basic event information
    char event_str[64] = {0};
    extract_json_value(payload, "event", event_str, sizeof(event_str));
    notification->event_type = identify_notification_action(event_str);
    strncpy(notification->event_name, event_str, sizeof(notification->event_name) - 1);
    
    // Extract timestamp
    long timestamp = 0;
    extract_json_number(payload, "timestamp", &timestamp);
    notification->timestamp = (time_t)timestamp;
    if (notification->timestamp == 0) {
        notification->timestamp = time(NULL);
    }
    
    // Extract client parameters
    client_info_t *client = &notification->client_data;
    
    extract_json_value(payload, "client_id", client->client_id, sizeof(client->client_id));
    extract_json_value(payload, "source_client_id", client->client_id, sizeof(client->client_id));
    extract_json_value(payload, "source_ip", client->source_ip, sizeof(client->source_ip));
    extract_json_value(payload, "topic", client->topic, sizeof(client->topic));
    extract_json_value(payload, "username", client->username, sizeof(client->username));
    extract_json_value(payload, "protocol_version", client->protocol_version, sizeof(client->protocol_version));
    
    // Extract numeric values
    long socket_fd = 0, keepalive = 0, messages_sent = 0, messages_received = 0;
    long bytes_sent = 0, bytes_received = 0, qos = 0;
    
    extract_json_number(payload, "socket_fd", &socket_fd);
    extract_json_number(payload, "keepalive", &keepalive);
    extract_json_number(payload, "messages_sent", &messages_sent);
    extract_json_number(payload, "messages_received", &messages_received);
    extract_json_number(payload, "bytes_sent", &bytes_sent);
    extract_json_number(payload, "bytes_received", &bytes_received);
    extract_json_number(payload, "qos", &qos);
    
    client->socket_fd = (int)socket_fd;
    client->keepalive_interval = (int)keepalive;
    client->messages_sent = (unsigned long)messages_sent;
    client->messages_received = (unsigned long)messages_received;
    client->bytes_sent = (unsigned long)bytes_sent;
    client->bytes_received = (unsigned long)bytes_received;
    client->qos_level = (int)qos;
    
    // Extract boolean values
    extract_json_bool(payload, "ssl_enabled", &client->ssl_enabled);
    extract_json_bool(payload, "clean_session", &client->clean_session);
    
    // Set timestamps based on event type
    if (notification->event_type == EVENT_CLIENT_CONNECTED) {
        client->connect_time = notification->timestamp;
    } else if (notification->event_type == EVENT_CLIENT_DISCONNECTED) {
        client->disconnect_time = notification->timestamp;
    }
    
    client->last_event = notification->event_type;
    
    return 0;
}

// Find client by ID in database
client_info_t* find_client_by_id(client_database_t *db, const char *client_id) {
    if (!db || !client_id) return NULL;
    
    for (int i = 0; i < db->client_count; i++) {
        if (strcmp(db->clients[i].client_id, client_id) == 0) {
            return &db->clients[i];
        }
    }
    return NULL;
}

// Update client database with new notification
void update_client_database(client_database_t *db, const notification_message_t *notification) {
    if (!db || !notification) return;
    
    const char *client_id = notification->client_data.client_id;
    if (strlen(client_id) == 0) return;
    
    client_info_t *existing_client = find_client_by_id(db, client_id);
    
    if (existing_client) {
        // Update existing client
        if (strlen(notification->client_data.source_ip) > 0) {
            strncpy(existing_client->source_ip, notification->client_data.source_ip, sizeof(existing_client->source_ip) - 1);
        }
        if (strlen(notification->client_data.topic) > 0) {
            strncpy(existing_client->topic, notification->client_data.topic, sizeof(existing_client->topic) - 1);
        }
        if (strlen(notification->client_data.username) > 0) {
            strncpy(existing_client->username, notification->client_data.username, sizeof(existing_client->username) - 1);
        }
        
        // Update metrics
        existing_client->socket_fd = notification->client_data.socket_fd;
        existing_client->ssl_enabled = notification->client_data.ssl_enabled;
        existing_client->clean_session = notification->client_data.clean_session;
        existing_client->keepalive_interval = notification->client_data.keepalive_interval;
        existing_client->messages_sent = notification->client_data.messages_sent;
        existing_client->messages_received = notification->client_data.messages_received;
        existing_client->bytes_sent = notification->client_data.bytes_sent;
        existing_client->bytes_received = notification->client_data.bytes_received;
        existing_client->qos_level = notification->client_data.qos_level;
        existing_client->last_event = notification->event_type;
        
        if (notification->event_type == EVENT_CLIENT_DISCONNECTED) {
            existing_client->disconnect_time = notification->timestamp;
        }
    } else if (db->client_count < MAX_CLIENTS) {
        // Add new client
        client_info_t *new_client = &db->clients[db->client_count++];
        memcpy(new_client, &notification->client_data, sizeof(client_info_t));
    }
}

// Enhanced MQTT packet parsing
void parse_mqtt_packet(unsigned char *buffer, int length, client_database_t *db) {
    if (length < 2) {
        printf("Packet too short\n");
        return;
    }
    
    unsigned char packet_type = (buffer[0] >> 4) & 0x0F;
    unsigned char remaining_length = buffer[1];
    
    // Debug: Print raw packet info
    printf("   Raw packet: type=%d, remaining_length=%d, total_length=%d\n", packet_type, remaining_length, length);
    
    // If this looks like a PUBLISH packet with variable length encoding
    if (packet_type == 3 || (length > 10 && packet_type == 5)) {
        // Try to parse as PUBLISH directly
        printf("   Attempting PUBLISH parsing...\n");
    }
    
    switch (packet_type) {
        case MQTT_CONNACK:
            printf("📥 Received CONNACK");
            if (length > 3) {
                printf(" (return code: %d)", buffer[3]);
            }
            printf("\n");
            break;
            
        case MQTT_SUBACK:
            printf("📥 Received SUBACK");
            if (length > 4) {
                printf(" (packet ID: %d)", (buffer[2] << 8) | buffer[3]);
            }
            printf("\n");
            break;
        
        case 5:  // Special notification packet - likely PUBLISH with custom encoding
            printf("📥 Received Notification Packet (type 5)\n");
            
            // For type 5 packets, try different parsing approach
            if (length > 80) { // If packet is large enough to contain notification
                // Look for JSON data starting from different offsets
                char *json_start = NULL;
                for (int i = 2; i < length - 10; i++) {
                    if (buffer[i] == '{' && strstr((char*)&buffer[i], "event")) {
                        json_start = (char*)&buffer[i];
                        break;
                    }
                }
                
                if (json_start) {
                    printf("   Found JSON notification data\n");
                    
                    // Parse notification
                    notification_message_t notification;
                    if (parse_notification_payload(json_start, &notification) == 0) {
                        printf("   🔍 Notification Action: %s", get_event_name(notification.event_type));
                        
                        // Update client database
                        update_client_database(db, &notification);
                        db->total_notifications++;
                        
                        // Print detailed notification summary
                        print_notification_summary(&notification);
                    } else {
                        printf("   ⚠️ Failed to parse notification payload");
                    }
                } else {
                    printf("   ⚠️ No JSON data found in packet\n");
                }
            }
            break;
            
        case MQTT_PUBLISH:
            printf("📥 Received PUBLISH");
            
            // Debug: Print first 50 bytes to understand structure
            printf("\n   Debug - First 50 bytes: ");
            for (int i = 0; i < (length < 50 ? length : 50); i++) {
                if (buffer[i] >= 32 && buffer[i] <= 126) {
                    printf("%c", buffer[i]);
                } else {
                    printf("\\x%02x", buffer[i]);
                }
            }
            printf("\n");
            
            // Parse topic - MQTT PUBLISH packet structure:
            // [0] = packet type & flags, [1] = remaining length
            // [2-3] = topic length (big endian), [4...] = topic, then payload
            if (length > 4) {
                int topic_len = (buffer[2] << 8) | buffer[3];
                printf("   Topic length (raw): %d (0x%02x%02x)\n", topic_len, buffer[2], buffer[3]);
                
                // Try alternative parsing - sometimes the length is in [3-4]
                int alt_topic_len = (buffer[3] << 8) | buffer[4];
                printf("   Alt topic length: %d (0x%02x%02x)\n", alt_topic_len, buffer[3], buffer[4]);
                
                // Search for the topic pattern byte by byte
                const char* target_topic = "broker/notifications";
                int topic_start_offset = -1;
                
                for (int i = 0; i <= length - 20; i++) {
                    if (memcmp(&buffer[i], target_topic, 20) == 0) {
                        topic_start_offset = i;
                        break;
                    }
                }
                
                if (topic_start_offset >= 0) {
                    printf("   Found topic at offset: %d\n", topic_start_offset);
                    
                    // Extract topic
                    char topic[256] = {0};
                    memcpy(topic, &buffer[topic_start_offset], 20);
                    printf("   Topic: '%s'\n", topic);
                    
                    // Payload starts right after the topic
                    int payload_start = topic_start_offset + 20;
                    printf("   Payload starts at: %d\n", payload_start);
                    
                    if (length > payload_start) {
                        int payload_len = length - payload_start;
                        printf("   Payload length: %d\n", payload_len);
                        
                        char payload[MAX_BUFFER_SIZE] = {0};
                        int copy_len = payload_len < MAX_BUFFER_SIZE - 1 ? payload_len : MAX_BUFFER_SIZE - 1;
                        memcpy(payload, &buffer[payload_start], copy_len);
                        payload[copy_len] = '\0';
                        
                        printf("   JSON Payload: %.200s%s\n", payload, payload_len > 200 ? "..." : "");
                        
                        // Parse notification
                        notification_message_t notification;
                        if (parse_notification_payload(payload, &notification) == 0) {
                            printf("   🔍 Notification Action: %s\n", get_event_name(notification.event_type));
                            
                            // Update client database
                            update_client_database(db, &notification);
                            db->total_notifications++;  
                            
                            // Print detailed notification summary
                            print_notification_summary(&notification);
                        } else {
                            printf("   ⚠️ Failed to parse notification payload\n");
                        }
                    }
                } else {
                    printf("   ⚠️ Topic 'broker/notifications' not found in packet\n");
                    // Debug: show where we are looking
                    printf("   Searching in: ");
                    for (int i = 0; i < (length < 100 ? length : 100); i++) {
                        if (buffer[i] >= 32 && buffer[i] <= 126) {
                            printf("%c", buffer[i]);
                        } else {
                            printf(".");
                        }
                    }
                    printf("\n");
                }
            }
            printf("\n");
            break;
            
        default:
            printf("📥 Received packet type %d (length: %d)\n", packet_type, remaining_length);
            break;
    }
}

// Print notification summary
void print_notification_summary(const notification_message_t *notification) {
    printf("\n   ════════════════════════════════════");
    printf("\n   Event Type: %s", get_event_name(notification->event_type));
    
    char time_str[64];
    struct tm *tm_info = localtime(&notification->timestamp);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("\n   Timestamp: %s", time_str);
    
    const client_info_t *client = &notification->client_data;
    if (strlen(client->client_id) > 0) {
        printf("\n   Client ID: %s", client->client_id);
    }
    if (strlen(client->source_ip) > 0) {
        printf("\n   Source IP: %s", client->source_ip);
    }
    if (strlen(client->topic) > 0) {
        printf("\n   Topic: %s", client->topic);
    }
    if (strlen(client->username) > 0) {
        printf("\n   Username: %s", client->username);
    }
    if (client->socket_fd > 0) {
        printf("\n   Socket FD: %d", client->socket_fd);
    }
    if (client->ssl_enabled) {
        printf("\n   SSL: Enabled");
    }
    if (client->keepalive_interval > 0) {
        printf("\n   Keep-Alive: %d seconds", client->keepalive_interval);
    }
    if (client->messages_sent > 0 || client->messages_received > 0) {
        printf("\n   Messages: Sent=%lu, Received=%lu", client->messages_sent, client->messages_received);
    }
    if (client->bytes_sent > 0 || client->bytes_received > 0) {
        printf("\n   Bytes: Sent=%lu, Received=%lu", client->bytes_sent, client->bytes_received);
    }
    printf("\n   ════════════════════════════════════");
}

// Print client database
void print_client_database(const client_database_t *db) {
    printf("\n\n🗄️  CLIENT DATABASE (%d clients)\n", db->client_count);
    printf("════════════════════════════════════════════════════════════════\n");
    
    for (int i = 0; i < db->client_count; i++) {
        const client_info_t *client = &db->clients[i];
        printf("Client #%d: %s\n", i + 1, client->client_id);
        printf("  IP: %s | SSL: %s | Last Event: %s\n", 
               client->source_ip, 
               client->ssl_enabled ? "Yes" : "No",
               get_event_name(client->last_event));
        
        if (client->connect_time > 0) {
            char time_str[64];
            struct tm *tm_info = localtime(&client->connect_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            printf("  Connected: %s\n", time_str);
        }
        if (client->disconnect_time > 0) {
            char time_str[64];
            struct tm *tm_info = localtime(&client->disconnect_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            printf("  Disconnected: %s\n", time_str);
        }
        
        printf("  Stats: Msgs(S:%lu/R:%lu) Bytes(S:%lu/R:%lu)\n",
               client->messages_sent, client->messages_received,
               client->bytes_sent, client->bytes_received);
        printf("────────────────────────────────────────────────────────────────\n");
    }
}

// Print statistics
void print_statistics(const client_database_t *db) {
    printf("\n📊 STATISTICS SUMMARY\n");
    printf("══════════════════════════════════════════════════════\n");
    printf("Runtime: %ld seconds\n", time(NULL) - db->start_time);
    printf("Total notifications: %d\n", db->total_notifications);
    printf("Active clients: %d\n", db->client_count);
    printf("══════════════════════════════════════════════════════\n");
}

// Initialize Mosquitto library
int mosquitto_init_library(void) {
    int rc = mosquitto_lib_init();
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initialize mosquitto library: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    printf("✅ Mosquitto library initialized\n");
    return 0;
}

// Cleanup Mosquitto library
void mosquitto_cleanup_library(void) {
    mosquitto_lib_cleanup();
    printf("✅ Mosquitto library cleaned up\n");
}

// Create SSL configuration
ssl_config_t* ssl_config_create(const char *ca_cert, const char *client_cert, const char *client_key) {
    ssl_config_t *config = malloc(sizeof(ssl_config_t));
    if (!config) {
        printf("❌ Failed to allocate SSL configuration\n");
        return NULL;
    }
    
    memset(config, 0, sizeof(ssl_config_t));
    
    // Set certificate paths
    if (ca_cert) {
        strncpy(config->ca_cert_path, ca_cert, sizeof(config->ca_cert_path) - 1);
    }
    if (client_cert) {
        strncpy(config->client_cert_path, client_cert, sizeof(config->client_cert_path) - 1);
    }
    if (client_key) {
        strncpy(config->client_key_path, client_key, sizeof(config->client_key_path) - 1);
    }
    
    // Set default SSL options
    config->verify_peer = false;  // Relaxed verification for demo
    config->require_client_cert = false;
    
    return config;
}

// Mosquitto callback functions
void on_connect_callback(struct mosquitto *mosq, void *userdata, int result) {
    mosquitto_connection_t *conn = (mosquitto_connection_t *)userdata;
    if (result == 0) {
        pthread_mutex_lock(&conn->mutex);
        conn->connected = true;
        pthread_mutex_unlock(&conn->mutex);
        printf("✅ MQTT connection successful (result: %d)\n", result);
        
        // Subscribe to notifications topic (use stored topic)
        int rc = mosquitto_subscribe(mosq, NULL, conn->topic, 0);
        if (rc == MOSQ_ERR_SUCCESS) {
            printf("📤 SUBSCRIBE packet sent for '%s'\n", conn->topic);
        } else {
            printf("❌ Failed to subscribe: %s\n", mosquitto_strerror(rc));
        }
    } else {
        printf("❌ MQTT connection failed (result: %d): %s\n", result, mosquitto_strerror(result));
    }
}

void on_disconnect_callback(struct mosquitto *mosq, void *userdata, int result) {
    mosquitto_connection_t *conn = (mosquitto_connection_t *)userdata;
    pthread_mutex_lock(&conn->mutex);
    conn->connected = false;
    pthread_mutex_unlock(&conn->mutex);
    printf("📡 Disconnected from broker (result: %d)\n", result);
}

void on_message_callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    mosquitto_connection_t *conn = (mosquitto_connection_t *)userdata;
    
    pthread_mutex_lock(&conn->mutex);
    conn->message_count++;
    int msg_num = conn->message_count;
    pthread_mutex_unlock(&conn->mutex);
    
    printf("📨 NOTIFICATION #%d:\n", msg_num);
    printf("Topic: %s\n", message->topic);
    printf("Payload Length: %d\n", message->payloadlen);
    
    if (message->payload && message->payloadlen > 0) {
        // Parse the MQTT payload as JSON notification
        char *payload_str = malloc(message->payloadlen + 1);
        if (payload_str) {
            memcpy(payload_str, message->payload, message->payloadlen);
            payload_str[message->payloadlen] = '\0';
            
            printf("Raw Payload: %s\n", payload_str);
            
            notification_message_t notification;
            if (parse_notification_payload(payload_str, &notification) == 0) {
                print_notification_summary(&notification);
                update_client_database(&g_client_db, &notification);
            } else {
                printf("⚠️ Failed to parse notification payload\n");
            }
            
            free(payload_str);
        }
    }
    printf("\n");
}

void on_log_callback(struct mosquitto *mosq, void *userdata, int level, const char *str) {
    const char *level_str;
    switch (level) {
        case MOSQ_LOG_DEBUG: level_str = "DEBUG"; break;
        case MOSQ_LOG_INFO: level_str = "INFO"; break;
        case MOSQ_LOG_NOTICE: level_str = "NOTICE"; break;
        case MOSQ_LOG_WARNING: level_str = "WARNING"; break;
        case MOSQ_LOG_ERR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }
    printf("[MOSQ-%s] %s\n", level_str, str);
}

// Create Mosquitto connection
mosquitto_connection_t* mosquitto_create_connection(connection_type_t type, ssl_config_t *ssl_config, const char *topic) {
    mosquitto_connection_t *conn = malloc(sizeof(mosquitto_connection_t));
    if (!conn) {
        printf("❌ Failed to allocate connection structure\n");
        return NULL;
    }
    
    memset(conn, 0, sizeof(mosquitto_connection_t));
    conn->is_ssl = (type == CONNECTION_SSL);
    conn->connected = false;
    conn->message_count = 0;
    
    if (pthread_mutex_init(&conn->mutex, NULL) != 0) {
        printf("❌ Failed to initialize mutex\n");
        free(conn);
        return NULL;
    }
    
    // Copy SSL configuration if provided
    if (ssl_config && conn->is_ssl) {
        memcpy(&conn->config, ssl_config, sizeof(ssl_config_t));
    }
    
    // Store the topic
    if (topic) {
        strncpy(conn->topic, topic, sizeof(conn->topic) - 1);
        conn->topic[sizeof(conn->topic) - 1] = '\0';
    } else {
        strncpy(conn->topic, TOPIC, sizeof(conn->topic) - 1);
        conn->topic[sizeof(conn->topic) - 1] = '\0';
    }
    
    // Generate unique client ID
    snprintf(conn->client_id, sizeof(conn->client_id), "%s_%d_%ld", 
             CLIENT_ID, getpid(), time(NULL));
    
    // Create mosquitto instance
    conn->mosq = mosquitto_new(conn->client_id, true, conn);
    if (!conn->mosq) {
        printf("❌ Failed to create mosquitto instance\n");
        pthread_mutex_destroy(&conn->mutex);
        free(conn);
        return NULL;
    }
    
    // Set callbacks
    mosquitto_connect_callback_set(conn->mosq, on_connect_callback);
    mosquitto_disconnect_callback_set(conn->mosq, on_disconnect_callback);
    mosquitto_message_callback_set(conn->mosq, on_message_callback);
    mosquitto_log_callback_set(conn->mosq, on_log_callback);
    
    // Configure SSL if needed
    if (conn->is_ssl) {
        const char *ca_path = conn->config.ca_cert_path[0] ? conn->config.ca_cert_path : CA_CERT_PATH;
        const char *cert_path = conn->config.client_cert_path[0] ? conn->config.client_cert_path : CLIENT_CERT_PATH;
        const char *key_path = conn->config.client_key_path[0] ? conn->config.client_key_path : CLIENT_KEY_PATH;
        
        printf("📋 SSL Configuration:\n");
        printf("   CA Certificate: %s\n", ca_path);
        printf("   Client Certificate: %s\n", cert_path);
        printf("   Client Key: %s\n", key_path);
        printf("   Peer Verification: %s\n", conn->config.verify_peer ? "Enabled" : "Disabled");
        
        // Set TLS options
        int rc = mosquitto_tls_set(conn->mosq, ca_path, NULL, cert_path, key_path, NULL);
        if (rc != MOSQ_ERR_SUCCESS) {
            printf("❌ Failed to set TLS options: %s\n", mosquitto_strerror(rc));
            mosquitto_destroy(conn->mosq);
            pthread_mutex_destroy(&conn->mutex);
            free(conn);
            return NULL;
        }
        
        // Set TLS options for verification
        rc = mosquitto_tls_opts_set(conn->mosq, conn->config.verify_peer ? 1 : 0, "tlsv1.2", NULL);
        if (rc != MOSQ_ERR_SUCCESS) {
            printf("❌ Failed to set TLS verification options: %s\n", mosquitto_strerror(rc));
            mosquitto_destroy(conn->mosq);
            pthread_mutex_destroy(&conn->mutex);
            free(conn);
            return NULL;
        }
        
        // Disable hostname verification for localhost connections
        rc = mosquitto_tls_insecure_set(conn->mosq, true);
        if (rc != MOSQ_ERR_SUCCESS) {
            printf("❌ Failed to set TLS insecure mode: %s\n", mosquitto_strerror(rc));
            mosquitto_destroy(conn->mosq);
            pthread_mutex_destroy(&conn->mutex);
            free(conn);
            return NULL;
        }
        printf("⚠️  Hostname verification disabled for testing purposes\n");
        
        printf("✅ SSL/TLS configured successfully\n");
    }
    
    return conn;
}

// Cleanup Mosquitto connection
void mosquitto_cleanup_connection(mosquitto_connection_t *conn) {
    if (!conn) return;
    
    if (conn->mosq) {
        mosquitto_disconnect(conn->mosq);
        mosquitto_destroy(conn->mosq);
    }
    pthread_mutex_destroy(&conn->mutex);
    free(conn);
}

// Connect to broker (updated)
mosquitto_connection_t* connect_to_broker(connection_type_t type, ssl_config_t *ssl_config, const char *host, int port, const char *topic) {
    const char *type_str = (type == CONNECTION_SSL) ? "SSL" : "TCP";
    
    printf("🔗 Connecting to %s broker at %s:%d...\n", type_str, host, port);
    
    mosquitto_connection_t *conn = mosquitto_create_connection(type, ssl_config, topic);
    if (!conn) {
        printf("❌ Failed to create %s connection\n", type_str);
        return NULL;
    }
    
    printf("📡 Client ID: %s\n", conn->client_id);
    
    // Connect to broker
    int rc = mosquitto_connect(conn->mosq, host, port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to connect to broker: %s\n", mosquitto_strerror(rc));
        mosquitto_cleanup_connection(conn);
        return NULL;
    }
    
    printf("✅ %s connection initiated\n", type_str);
    return conn;
}

// Subscribe to notifications (updated for mosquitto)
int subscribe_to_notifications(mosquitto_connection_t *conn, const char *topic) {
    // With mosquitto, subscription is handled in the connect callback
    // Just wait for connection to be established
    
    printf("⏳ Waiting for MQTT connection...\n");
    
    // Wait for connection (with timeout)
    for (int i = 0; i < 50; i++) {
        pthread_mutex_lock(&conn->mutex);
        bool is_connected = conn->connected;
        pthread_mutex_unlock(&conn->mutex);
        
        if (is_connected) {
            printf("✅ Connected and subscribed to notifications\n");
            return 0;
        }
        
        // Process mosquitto network events
        int rc = mosquitto_loop(conn->mosq, 100, 1);
        if (rc != MOSQ_ERR_SUCCESS) {
            printf("❌ Mosquitto loop error: %s\n", mosquitto_strerror(rc));
            return -1;
        }
        
        usleep(100000); // 100ms
    }
    
    printf("❌ Connection timeout\n");
    return -1;
}

// Main notification listener (updated for mosquitto)
int run_notification_listener(connection_type_t type, ssl_config_t *ssl_config, const char *host, int port, const char *topic) {
    const char *type_str = (type == CONNECTION_SSL) ? "SSL" : "TCP";
    
    printf("🚀 Enhanced Mosquitto MQTT Notification Client\n");
    printf("===============================================\n");
    printf("Connection Type: %s\n", type_str);
    printf("Broker: %s:%d\n", host, port);
    printf("Topic: %s\n", topic);
    printf("===============================================\n\n");
    
    // Initialize Mosquitto library
    if (mosquitto_init_library() < 0) {
        return 1;
    }
    
    // Initialize client database
    memset(&g_client_db, 0, sizeof(g_client_db));
    g_client_db.start_time = time(NULL);
    
    // Connect to broker
    mosquitto_connection_t *conn = connect_to_broker(type, ssl_config, host, port, topic);
    if (!conn) {
        mosquitto_cleanup_library();
        return 1;
    }
    
    // Subscribe to notifications
    if (subscribe_to_notifications(conn, topic) < 0) {
        mosquitto_cleanup_connection(conn);
        mosquitto_cleanup_library();
        return 1;
    }
    
    printf("📢 Listening for notifications...\n\n");
    
    // Listen for messages using mosquitto loop
    for (int i = 0; i < 500; i++) {  // Listen for more iterations
        pthread_mutex_lock(&conn->mutex);
        bool is_connected = conn->connected;
        int msg_count = conn->message_count;
        pthread_mutex_unlock(&conn->mutex);
        
        if (!is_connected) {
            printf("📡 Connection lost, attempting to reconnect...\n");
            int rc = mosquitto_reconnect(conn->mosq);
            if (rc != MOSQ_ERR_SUCCESS) {
                printf("❌ Reconnection failed: %s\n", mosquitto_strerror(rc));
                break;
            }
        }
        
        // Process mosquitto network events
        int rc = mosquitto_loop(conn->mosq, 100, 1);
        if (rc != MOSQ_ERR_SUCCESS) {
            printf("❌ Mosquitto loop error: %s\n", mosquitto_strerror(rc));
            break;
        }
        
        // Show progress every 10 loops if no messages
        if (i > 0 && i % 10 == 0 && msg_count == 0) {
            printf(".");
            fflush(stdout);
        }
        
        usleep(100000); // 100ms
    }
    
    // Print final statistics
    print_client_database(&g_client_db);
    print_statistics(&g_client_db);
    
    mosquitto_cleanup_connection(conn);
    mosquitto_cleanup_library();
    printf("👋 Connection closed\n");
    
    return 0;
}

// Auto-detect connection type (try SSL first, fallback to TCP)
int run_notification_listener_auto(ssl_config_t *ssl_config, const char *host, int port, const char *topic) {
    printf("🔍 Auto-detecting connection type...\n");
    
    // Initialize Mosquitto library
    if (mosquitto_init_library() < 0) {
        return 1;
    }
    
    // Try SSL first
    printf("Attempting SSL connection...\n");
    mosquitto_connection_t *ssl_conn = mosquitto_create_connection(CONNECTION_SSL, ssl_config, topic);
    if (ssl_conn) {
        // Test SSL connection
        int ssl_port = (port > 0) ? port : BROKER_PORT_SSL;
        int rc = mosquitto_connect(ssl_conn->mosq, host, ssl_port, 5);
        if (rc == MOSQ_ERR_SUCCESS) {
            printf("✅ SSL connection successful, using SSL mode\n\n");
            mosquitto_cleanup_connection(ssl_conn);
            mosquitto_cleanup_library();
            return run_notification_listener(CONNECTION_SSL, ssl_config, host, ssl_port, topic);
        }
        mosquitto_cleanup_connection(ssl_conn);
    }
    
    printf("⚠️ SSL connection failed, trying TCP...\n");
    
    // Fallback to TCP
    mosquitto_connection_t *tcp_conn = mosquitto_create_connection(CONNECTION_TCP, NULL, topic);
    if (tcp_conn) {
        // Test TCP connection
        int tcp_port = (port > 0) ? port : BROKER_PORT_TCP;
        int rc = mosquitto_connect(tcp_conn->mosq, host, tcp_port, 5);
        if (rc == MOSQ_ERR_SUCCESS) {
            printf("✅ TCP connection successful, using TCP mode\n\n");
            mosquitto_cleanup_connection(tcp_conn);
            mosquitto_cleanup_library();
            return run_notification_listener(CONNECTION_TCP, NULL, host, tcp_port, topic);
        }
        mosquitto_cleanup_connection(tcp_conn);
    }
    
    mosquitto_cleanup_library();
    printf("❌ Both SSL and TCP connections failed\n");
    return 1;
}

// Convenience function to run with certificate paths
int run_notification_listener_with_certs(const char *ca_cert, const char *client_cert, const char *client_key) {
    printf("🔐 Creating SSL configuration with provided certificates\n");
    
    ssl_config_t *ssl_config = ssl_config_create(ca_cert, client_cert, client_key);
    if (!ssl_config) {
        printf("❌ Failed to create SSL configuration\n");
        return 1;
    }
    
    // Enable peer verification if we have all certificates
    if (ca_cert && client_cert && client_key) {
        ssl_config->verify_peer = true;
        ssl_config->require_client_cert = true;
        printf("✅ SSL peer verification enabled\n");
    }
    
    int result = run_notification_listener(CONNECTION_SSL, ssl_config, BROKER_HOST, BROKER_PORT_SSL, TOPIC);
    
    free(ssl_config);
    return result;
}
