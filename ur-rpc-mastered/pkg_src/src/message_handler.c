#include "message_handler.h"
#include "mqtt_broker.h"
#include "notification_manager.h"
#include "cert_manager.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cJSON.h>

static int handle_mqtt_packet(mqtt_client_t *client, mqtt_broker_t *broker, 
                              const mqtt_fixed_header_t *header, const uint8_t *payload, uint32_t payload_len);

int message_handler_process_client(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) return -1;
    
    uint8_t buffer[MQTT_BUFFER_SIZE];
    ssize_t received = client_manager_recv(client, buffer, sizeof(buffer));
    
    if (received < 0) {
        LOG_WARNING("Failed to receive data from client fd=%d", client->socket_fd);
        return -1;
    }
    
    if (received == 0) {
        // No data available
        return 0;
    }
    
    // Add received data to client's read buffer
    if (client->read_buffer_len + (size_t)received > sizeof(client->read_buffer)) {
        LOG_WARNING("Client fd=%d read buffer overflow", client->socket_fd);
        return -1;
    }
    
    memcpy(client->read_buffer + client->read_buffer_len, buffer, received);
    client->read_buffer_len += received;
    
    // Process complete MQTT packets
    while (client->read_buffer_len > 0) {
        mqtt_fixed_header_t header;
        uint32_t header_bytes;
        
        // Try to parse fixed header
        int result = mqtt_parse_fixed_header(client->read_buffer, client->read_buffer_len, 
                                           &header, &header_bytes);
        
        if (result == 1) {
            // Need more data for header
            break;
        }
        
        if (result < 0) {
            LOG_WARNING("Invalid MQTT header from client fd=%d", client->socket_fd);
            return -1;
        }
        
        uint32_t total_packet_len = header_bytes + header.remaining_length;
        
        if (client->read_buffer_len < total_packet_len) {
            // Need more data for complete packet
            break;
        }
        
        // Process the packet
        const uint8_t *payload = client->read_buffer + header_bytes;
        result = handle_mqtt_packet(client, broker, &header, payload, header.remaining_length);
        
        if (result < 0) {
            LOG_WARNING("Failed to handle MQTT packet from client fd=%d, msg_type=%d, remaining_length=%d", 
                       client->socket_fd, header.msg_type, header.remaining_length);
            return -1;
        }
        
        // Remove processed packet from buffer
        memmove(client->read_buffer, client->read_buffer + total_packet_len, 
                client->read_buffer_len - total_packet_len);
        client->read_buffer_len -= total_packet_len;
        
        client->messages_received++;
        broker->total_messages++;
    }
    
    return 0;
}

static int handle_mqtt_packet(mqtt_client_t *client, mqtt_broker_t *broker, 
                              const mqtt_fixed_header_t *header, const uint8_t *payload, uint32_t payload_len) {
    
    switch (header->msg_type) {
        case MQTT_CONNECT: {
            mqtt_connect_t connect;
            if (mqtt_parse_connect(payload, payload_len, &connect) != 0) {
                LOG_WARNING("Failed to parse CONNECT packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_connect(client, broker, &connect);
            mqtt_free_connect(&connect);
            return result;
        }
        
        case MQTT_PUBLISH: {
            mqtt_publish_t publish;
            if (mqtt_parse_publish(payload, payload_len, header, &publish) != 0) {
                LOG_WARNING("Failed to parse PUBLISH packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_publish(client, broker, &publish);
            mqtt_free_publish(&publish);
            return result;
        }
        
        case MQTT_SUBSCRIBE: {
            mqtt_subscribe_t subscribe;
            if (mqtt_parse_subscribe(payload, payload_len, &subscribe) != 0) {
                LOG_WARNING("Failed to parse SUBSCRIBE packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_subscribe(client, broker, &subscribe);
            mqtt_free_subscribe(&subscribe);
            return result;
        }
        
        case MQTT_UNSUBSCRIBE: {
            mqtt_unsubscribe_t unsubscribe;
            if (mqtt_parse_unsubscribe(payload, payload_len, &unsubscribe) != 0) {
                LOG_WARNING("Failed to parse UNSUBSCRIBE packet from client fd=%d", client->socket_fd);
                return -1;
            }
            
            int result = message_handler_unsubscribe(client, broker, &unsubscribe);
            mqtt_free_unsubscribe(&unsubscribe);
            return result;
        }
        
        case MQTT_PUBACK: {
            if (payload_len < 2) {
                LOG_WARNING("Invalid PUBACK packet length from client fd=%d", client->socket_fd);
                return -1;
            }
            
            uint16_t packet_id = ntohs(*(uint16_t*)payload);
            return message_handler_puback(client, broker, packet_id);
        }
        
        case MQTT_PUBREC: {
            if (payload_len < 2) {
                LOG_WARNING("Invalid PUBREC packet length from client fd=%d", client->socket_fd);
                return -1;
            }
            
            uint16_t packet_id = ntohs(*(uint16_t*)payload);
            return message_handler_pubrec(client, broker, packet_id);
        }
        
        case MQTT_PUBREL: {
            if (payload_len < 2) {
                LOG_WARNING("Invalid PUBREL packet length from client fd=%d", client->socket_fd);
                return -1;
            }
            
            uint16_t packet_id = ntohs(*(uint16_t*)payload);
            return message_handler_pubrel(client, broker, packet_id);
        }
        
        case MQTT_PUBCOMP: {
            if (payload_len < 2) {
                LOG_WARNING("Invalid PUBCOMP packet length from client fd=%d", client->socket_fd);
                return -1;
            }
            
            uint16_t packet_id = ntohs(*(uint16_t*)payload);
            return message_handler_pubcomp(client, broker, packet_id);
        }
        
        case MQTT_PINGREQ: {
            return message_handler_pingreq(client, broker);
        }
        
        case MQTT_DISCONNECT: {
            return message_handler_disconnect(client, broker);
        }
        
        default:
            LOG_WARNING("Unsupported MQTT message type %d from client fd=%d", 
                       header->msg_type, client->socket_fd);
            return -1;
    }
}

int message_handler_connect(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_connect_t *connect) {
    if (!client || !broker || !connect) return -1;
    
    mqtt_connack_code_t return_code = MQTT_CONNACK_ACCEPTED;
    bool session_present = false;
    
    // Validate protocol version
    if (connect->protocol_version != MQTT_PROTOCOL_VERSION) {
        return_code = MQTT_CONNACK_REFUSED_PROTOCOL_VERSION;
        LOG_WARNING("Unsupported protocol version %d from client fd=%d", 
                   connect->protocol_version, client->socket_fd);
    }
    
    // Validate client ID
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        if (!connect->client_id || strlen(connect->client_id) == 0) {
            if (!(connect->flags & 0x02)) { // Clean session not set
                return_code = MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED;
            } else {
                // Generate client ID
                snprintf(client->client_id, sizeof(client->client_id), "auto_%d_%lu", 
                        client->socket_fd, time(NULL));
            }
        } else if (strlen(connect->client_id) >= MAX_CLIENT_ID_LEN) {
            return_code = MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED;
        } else {
            strncpy(client->client_id, connect->client_id, sizeof(client->client_id) - 1);
        }
    }
    
    // Check for duplicate client ID
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        mqtt_client_t *existing = client_manager_get_client_by_id(&broker->client_manager, client->client_id);
        if (existing && existing != client) {
            LOG_INFO("Disconnecting existing client with same ID: %s", client->client_id);
            existing->state = MQTT_CLIENT_DISCONNECTED;
        }
    }
    
    // Authenticate client
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        // For SSL connections with certificate authentication, check if client cert is present
        if (broker->config.ssl_enabled && !broker->config.allow_anonymous) {
            // SSL certificate authentication - if we got here, SSL handshake succeeded
            // This means the client certificate was validated by the SSL layer
            LOG_DEBUG("SSL certificate authentication successful for client %s", client->client_id);
        } else if (!message_handler_authenticate(broker, connect->username, connect->password)) {
            return_code = broker->config.allow_anonymous ? 
                         MQTT_CONNACK_ACCEPTED : MQTT_CONNACK_REFUSED_NOT_AUTHORIZED;
        }
    }
    
    // Store connection details
    if (return_code == MQTT_CONNACK_ACCEPTED) {
        client->keep_alive = connect->keep_alive;
        client->clean_session = (connect->flags & 0x02) != 0;
        
        // Store will message
        if (connect->flags & 0x04) { // Will flag
            client->will_flag = true;
            client->will_qos = (connect->flags >> 3) & 0x03;
            client->will_retain = (connect->flags & 0x20) != 0;
            
            if (connect->will_topic) {
                client->will_topic = strdup(connect->will_topic);
            }
            if (connect->will_message) {
                client->will_message = strdup(connect->will_message);
            }
        }
        
        // Store credentials
        if (connect->username) {
            client->username = strdup(connect->username);
        }
        if (connect->password) {
            client->password = strdup(connect->password);
        }
        
        client->state = MQTT_CLIENT_CONNECTED;
        LOG_INFO("Client connected: %s (fd=%d, keepalive=%d, clean=%s)", 
                client->client_id, client->socket_fd, client->keep_alive,
                client->clean_session ? "yes" : "no");
        
        // Send connection notification
        if (broker->notification_manager) {
            notification_manager_send_notification(broker->notification_manager, &broker->client_manager, NOTIFICATION_CLIENT_CONNECTED, client->client_id, "");
        }
    }
    
    // Send CONNACK
    uint8_t connack_buffer[4];
    int connack_len = mqtt_serialize_connack(connack_buffer, sizeof(connack_buffer), 
                                           session_present, return_code);
    
    if (connack_len > 0) {
        message_handler_send_packet(client, connack_buffer, connack_len);
    }
    
    return return_code == MQTT_CONNACK_ACCEPTED ? 0 : -1;
}

int message_handler_publish(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_publish_t *publish) {
    if (!client || !broker || !publish) return -1;
    
    // Validate topic
    if (!mqtt_validate_topic(publish->topic)) {
        LOG_WARNING("Invalid topic from client %s: %s", client->client_id, publish->topic);
        return -1;
    }
    
    // Check authorization
    if (!message_handler_authorize_topic(broker, client, publish->topic, 1)) {
        LOG_WARNING("Client %s not authorized to publish to %s", client->client_id, publish->topic);
        return -1;
    }
    
    // Check rate limiting
    if (!client_manager_check_rate_limit(client, broker->config.max_publish_rate)) {
        return -1;
    }
    
    LOG_DEBUG("PUBLISH from %s: %s (QoS %d, retain=%s, len=%u)", 
             client->client_id, publish->topic, publish->qos, 
             publish->retain ? "yes" : "no", publish->payload_len);
    
    // Send PUBACK for QoS 1
    if (publish->qos == 1) {
        uint8_t puback_buffer[4];
        int puback_len = mqtt_serialize_puback(puback_buffer, sizeof(puback_buffer), publish->packet_id);
        if (puback_len > 0) {
            message_handler_send_packet(client, puback_buffer, puback_len);
        }
    }
    
    // Check if this is a certificate management topic
    if (strncmp(publish->topic, "sys/cert/request", 16) == 0) {
        // Handle certificate generation request with real certificate generation
        char payload_str[publish->payload_len + 1];
        memcpy(payload_str, publish->payload, publish->payload_len);
        payload_str[publish->payload_len] = '\0';
        
        LOG_INFO("Certificate request from client %s: %s", client->client_id, payload_str);
        
        // Parse JSON request
        cJSON *request_json = cJSON_Parse(payload_str);
        if (!request_json) {
            LOG_ERROR("Failed to parse certificate request JSON from client %s", client->client_id);
            return -1;
        }
        
        // Extract certificate type
        cJSON *cert_type = cJSON_GetObjectItem(request_json, "certificate_type");
        const char *cert_type_str = (cert_type && cJSON_IsString(cert_type)) ? cert_type->valuestring : "generic";
        
        // Generate real certificate using OpenSSL
        char cert_filename[256], key_filename[256];
        time_t now = time(NULL);
        snprintf(cert_filename, sizeof(cert_filename), "%s_%s_%ld.crt", 
                cert_type_str, client->client_id, now);
        snprintf(key_filename, sizeof(key_filename), "%s_%s_%ld.key", 
                cert_type_str, client->client_id, now);
                
        // Create certificate directory using config path
        const char* cert_dir = broker->config.cert_output_directory;
        mkdir(cert_dir, 0755);
        
        char cert_path[512], key_path[512];
        snprintf(cert_path, sizeof(cert_path), "%s/%s", cert_dir, cert_filename);
        snprintf(key_path, sizeof(key_path), "%s/%s", cert_dir, key_filename);
        
        // Generate certificate using OpenSSL command with client authentication extensions
        // Create temporary config file with client ID
        char config_template_path[] = "ur-rpc-mastered/pkg_src/certs/client_auth_cert.conf";
        char temp_config_path[512];
        snprintf(temp_config_path, sizeof(temp_config_path), "%s/client_%s.conf", cert_dir, client->client_id);
        
        // Copy template and replace placeholder
        char sed_cmd[1024];
        snprintf(sed_cmd, sizeof(sed_cmd),
                "sed 's/PLACEHOLDER_CLIENT_ID/%s/g' %s > %s",
                client->client_id, config_template_path, temp_config_path);
        system(sed_cmd);
        
        // Generate private key first
        char key_gen_cmd[512];
        snprintf(key_gen_cmd, sizeof(key_gen_cmd),
                "openssl genrsa -out '%s' 2048 2>/dev/null", key_path);
        system(key_gen_cmd);
        
        // Generate CSR
        char csr_path[512];
        snprintf(csr_path, sizeof(csr_path), "%s.csr", cert_path);
        
        char csr_cmd[1024];
        snprintf(csr_cmd, sizeof(csr_cmd),
                "openssl req -new -key '%s' -out '%s' -config '%s' 2>/dev/null",
                key_path, csr_path, temp_config_path);
        system(csr_cmd);
        
        // Sign CSR with CA certificate using config paths
        char openssl_cmd[1024];
        snprintf(openssl_cmd, sizeof(openssl_cmd),
                "openssl x509 -req -in '%s' -CA '%s' "
                "-CAkey '%s' -CAcreateserial "
                "-out '%s' -days 365 -extensions v3_req -extfile '%s' 2>/dev/null && "
                "rm -f '%s' '%s'",
                csr_path, broker->config.cert_ca_cert_file, broker->config.cert_ca_key_file,
                cert_path, temp_config_path, csr_path, temp_config_path);
        
        int result = system(openssl_cmd);
        
        // Create response
        cJSON *response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "ssl_enabled", true);
        cJSON_AddBoolToObject(response, "cert_generation_enabled", true);
        
        if (result == 0 && access(cert_path, R_OK) == 0 && access(key_path, R_OK) == 0) {
            // Read generated certificate
            FILE *cert_file = fopen(cert_path, "r");
            FILE *key_file = fopen(key_path, "r");
            
            if (cert_file && key_file) {
                char cert_buffer[4096] = {0};
                char key_buffer[4096] = {0};
                
                fread(cert_buffer, 1, sizeof(cert_buffer) - 1, cert_file);
                fread(key_buffer, 1, sizeof(key_buffer) - 1, key_file);
                
                fclose(cert_file);
                fclose(key_file);
                
                cJSON_AddStringToObject(response, "status", "success");
                cJSON_AddStringToObject(response, "client_id", client->client_id);
                cJSON_AddStringToObject(response, "certificate", cert_buffer);
                cJSON_AddStringToObject(response, "private_key", key_buffer);
                cJSON_AddStringToObject(response, "cert_filename", cert_filename);
                cJSON_AddStringToObject(response, "key_filename", key_filename);
                cJSON_AddNumberToObject(response, "issued_timestamp", (double)now);
                
                LOG_INFO("Generated real certificate for client %s: %s", client->client_id, cert_filename);
            } else {
                cJSON_AddStringToObject(response, "status", "error");
                cJSON_AddStringToObject(response, "error", "Failed to read generated certificate files");
            }
        } else {
            cJSON_AddStringToObject(response, "status", "error");
            cJSON_AddStringToObject(response, "error", "Failed to generate certificate using OpenSSL");
        }
        
        char *response_str = cJSON_Print(response);
        if (response_str) {
            // Create PUBLISH packet for response
            mqtt_publish_t cert_response = {0};
            cert_response.topic = "sys/cert/response";
            cert_response.payload = (uint8_t*)response_str;
            cert_response.payload_len = strlen(response_str);
            cert_response.qos = 0;
            cert_response.retain = false;
            cert_response.packet_id = 0;
            
            uint8_t publish_buffer[8192];
            int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &cert_response);
            
            if (publish_len > 0) {
                message_handler_send_packet(client, publish_buffer, publish_len);
                LOG_INFO("Sent real certificate response to client %s", client->client_id);
            }
            
            free(response_str);
        }
        
        cJSON_Delete(response);
        cJSON_Delete(request_json);
        return 0;
    } else if (strncmp(publish->topic, "sys/cert/list", 13) == 0) {
        // Handle certificate listing request  
        LOG_INFO("Certificate list request from client %s", client->client_id);
        
        cJSON *response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "ssl_enabled", broker->config.ssl_enabled);
        cJSON_AddStringToObject(response, "status", "success");
        
        cJSON *certificates = cJSON_CreateArray();
        cJSON_AddItemToObject(response, "certificates", certificates);
        
        char *response_str = cJSON_Print(response);
        if (response_str) {
            mqtt_publish_t list_response = {0};
            list_response.topic = "sys/cert/list_response";
            list_response.payload = (uint8_t*)response_str;
            list_response.payload_len = strlen(response_str);
            list_response.qos = 0;
            list_response.retain = false;
            list_response.packet_id = 0;
            
            uint8_t publish_buffer[2048];
            int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &list_response);
            
            if (publish_len > 0) {
                message_handler_send_packet(client, publish_buffer, publish_len);
            }
            
            free(response_str);
        }
        
        cJSON_Delete(response);
        return 0;
    } else if (strncmp(publish->topic, "sys/cert/environment/", 21) == 0) {
        // Handle environment-based certificate request
        LOG_INFO("Environment certificate request from client %s", client->client_id);
        
        char payload_str[publish->payload_len + 1];
        memcpy(payload_str, publish->payload, publish->payload_len);
        payload_str[publish->payload_len] = '\0';
        
        cert_request_t request;
        if (!cert_manager_parse_request(payload_str, &request)) {
            LOG_ERROR("Failed to parse environment certificate request");
            return -1;
        }
        
        cert_response_t response;
        bool success = cert_manager_request_environment_certificate(&request, &response);
        
        if (!success) {
            LOG_ERROR("Failed to generate environment certificate for client %s", client->client_id);
        }
        
        char* response_json = cert_manager_serialize_response(&response);
        if (response_json) {
            char response_topic[256];
            snprintf(response_topic, sizeof(response_topic), "sys/cert/environment/response/%s", client->client_id);
            
            mqtt_publish_t env_response = {0};
            env_response.topic = response_topic;
            env_response.payload = (uint8_t*)response_json;
            env_response.payload_len = strlen(response_json);
            env_response.qos = 1;
            env_response.retain = false;
            env_response.packet_id = client_manager_get_next_packet_id(client);
            
            uint8_t publish_buffer[8192];
            int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &env_response);
            
            if (publish_len > 0) {
                message_handler_send_packet(client, publish_buffer, publish_len);
                LOG_INFO("Sent environment certificate response to client %s", client->client_id);
            }
            
            free(response_json);
        }
        return 0;
    } else if (strncmp(publish->topic, "sys/cert/list/environment/", 26) == 0) {
        // Handle list certificates by environment
        LOG_INFO("Environment certificate list request from client %s", client->client_id);
        
        // Extract environment from topic: sys/cert/list/environment/{env}
        const char* env_start = publish->topic + 26;
        cert_environment_t environment = cert_manager_parse_environment_string(env_start);
        
        char response_buffer[4096];
        bool success = cert_manager_list_certificates_by_environment(environment, response_buffer, sizeof(response_buffer));
        
        if (success) {
            char response_topic[256];
            snprintf(response_topic, sizeof(response_topic), "sys/cert/list/environment/response/%s", client->client_id);
            
            mqtt_publish_t list_response = {0};
            list_response.topic = response_topic;
            list_response.payload = (uint8_t*)response_buffer;
            list_response.payload_len = strlen(response_buffer);
            list_response.qos = 1;
            list_response.retain = false;
            list_response.packet_id = client_manager_get_next_packet_id(client);
            
            uint8_t publish_buffer[8192];
            int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &list_response);
            
            if (publish_len > 0) {
                message_handler_send_packet(client, publish_buffer, publish_len);
                LOG_INFO("Sent environment certificate list to client %s", client->client_id);
            }
        }
        return 0;
    } else if (strncmp(publish->topic, "sys/cert/batch", 14) == 0) {
        // Handle batch certificate generation
        LOG_INFO("Batch certificate generation request from client %s", client->client_id);
        
        char payload_str[publish->payload_len + 1];
        memcpy(payload_str, publish->payload, publish->payload_len);
        payload_str[publish->payload_len] = '\0';
        
        cJSON* batch_json = cJSON_Parse(payload_str);
        if (!batch_json) {
            LOG_ERROR("Invalid batch certificate request JSON");
            return -1;
        }
        
        cJSON* requests_array = cJSON_GetObjectItem(batch_json, "requests");
        if (!cJSON_IsArray(requests_array)) {
            cJSON_Delete(batch_json);
            LOG_ERROR("Missing or invalid requests array in batch request");
            return -1;
        }
        
        int request_count = cJSON_GetArraySize(requests_array);
        cert_request_t* requests = malloc(request_count * sizeof(cert_request_t));
        cert_response_t* responses = malloc(request_count * sizeof(cert_response_t));
        
        if (!requests || !responses) {
            free(requests);
            free(responses);
            cJSON_Delete(batch_json);
            LOG_ERROR("Failed to allocate memory for batch requests");
            return -1;
        }
        
        // Parse each request
        bool parse_success = true;
        for (int i = 0; i < request_count; i++) {
            cJSON* request_item = cJSON_GetArrayItem(requests_array, i);
            char* request_str = cJSON_Print(request_item);
            if (!request_str || !cert_manager_parse_request(request_str, &requests[i])) {
                parse_success = false;
                free(request_str);
                break;
            }
            free(request_str);
        }
        
        if (parse_success) {
            cert_manager_batch_generate_certificates(requests, request_count, responses);
            
            // Create batch response
            cJSON* batch_response = cJSON_CreateObject();
            cJSON* responses_array = cJSON_CreateArray();
            cJSON_AddItemToObject(batch_response, "responses", responses_array);
            cJSON_AddNumberToObject(batch_response, "total_requests", request_count);
            
            for (int i = 0; i < request_count; i++) {
                char* response_json = cert_manager_serialize_response(&responses[i]);
                if (response_json) {
                    cJSON* response_item = cJSON_Parse(response_json);
                    if (response_item) {
                        cJSON_AddItemToArray(responses_array, response_item);
                    }
                    free(response_json);
                }
            }
            
            char* batch_response_str = cJSON_Print(batch_response);
            if (batch_response_str) {
                char response_topic[256];
                snprintf(response_topic, sizeof(response_topic), "sys/cert/batch/response/%s", client->client_id);
                
                mqtt_publish_t batch_resp = {0};
                batch_resp.topic = response_topic;
                batch_resp.payload = (uint8_t*)batch_response_str;
                batch_resp.payload_len = strlen(batch_response_str);
                batch_resp.qos = 1;
                batch_resp.retain = false;
                batch_resp.packet_id = client_manager_get_next_packet_id(client);
                
                uint8_t publish_buffer[16384];
                int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &batch_resp);
                
                if (publish_len > 0) {
                    message_handler_send_packet(client, publish_buffer, publish_len);
                    LOG_INFO("Sent batch certificate response to client %s", client->client_id);
                }
                
                free(batch_response_str);
            }
            
            cJSON_Delete(batch_response);
        }
        
        free(requests);
        free(responses);
        cJSON_Delete(batch_json);
        return 0;
    } else if (strncmp(publish->topic, "sys/cert/monitor", 16) == 0) {
        // Handle certificate expiration monitoring
        LOG_INFO("Certificate expiration monitoring request from client %s", client->client_id);
        
        char payload_str[publish->payload_len + 1];
        memcpy(payload_str, publish->payload, publish->payload_len);
        payload_str[publish->payload_len] = '\0';
        
        cJSON* monitor_json = cJSON_Parse(payload_str);
        if (!monitor_json) {
            LOG_ERROR("Invalid monitor request JSON");
            return -1;
        }
        
        cJSON* env_item = cJSON_GetObjectItem(monitor_json, "environment");
        cJSON* days_item = cJSON_GetObjectItem(monitor_json, "days_until_expiry");
        
        cert_environment_t environment = CERT_ENV_PROD; // Default
        int days_until_expiry = 30; // Default
        
        if (cJSON_IsString(env_item)) {
            environment = cert_manager_parse_environment_string(env_item->valuestring);
        }
        if (cJSON_IsNumber(days_item)) {
            days_until_expiry = days_item->valueint;
        }
        
        char response_buffer[8192];
        bool success = cert_manager_monitor_certificate_expiration(environment, days_until_expiry, 
                                                                   response_buffer, sizeof(response_buffer));
        
        if (success) {
            char response_topic[256];
            snprintf(response_topic, sizeof(response_topic), "sys/cert/monitor/response/%s", client->client_id);
            
            mqtt_publish_t monitor_response = {0};
            monitor_response.topic = response_topic;
            monitor_response.payload = (uint8_t*)response_buffer;
            monitor_response.payload_len = strlen(response_buffer);
            monitor_response.qos = 1;
            monitor_response.retain = false;
            monitor_response.packet_id = client_manager_get_next_packet_id(client);
            
            uint8_t publish_buffer[16384];
            int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &monitor_response);
            
            if (publish_len > 0) {
                message_handler_send_packet(client, publish_buffer, publish_len);
                LOG_INFO("Sent certificate monitor response to client %s", client->client_id);
            }
        }
        
        cJSON_Delete(monitor_json);
        return 0;
    } else if (strncmp(publish->topic, "sys/cert/search", 15) == 0) {
        // Handle certificate search
        LOG_INFO("Certificate search request from client %s", client->client_id);
        
        char payload_str[publish->payload_len + 1];
        memcpy(payload_str, publish->payload, publish->payload_len);
        payload_str[publish->payload_len] = '\0';
        
        char response_buffer[8192];
        bool success = cert_manager_search_certificates(payload_str, response_buffer, sizeof(response_buffer));
        
        if (success) {
            char response_topic[256];
            snprintf(response_topic, sizeof(response_topic), "sys/cert/search/response/%s", client->client_id);
            
            mqtt_publish_t search_response = {0};
            search_response.topic = response_topic;
            search_response.payload = (uint8_t*)response_buffer;
            search_response.payload_len = strlen(response_buffer);
            search_response.qos = 1;
            search_response.retain = false;
            search_response.packet_id = client_manager_get_next_packet_id(client);
            
            uint8_t publish_buffer[16384];
            int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &search_response);
            
            if (publish_len > 0) {
                message_handler_send_packet(client, publish_buffer, publish_len);
                LOG_INFO("Sent certificate search response to client %s", client->client_id);
            }
        }
        return 0;
    }
    
    // Broadcast to subscribers
    int subscriber_count = message_handler_broadcast(broker, publish->topic, 
                                                   publish->payload, publish->payload_len,
                                                   publish->qos, publish->retain, client);
    
    // Send topic publish notification if notification system is enabled
    if (broker->config.notification_enabled && broker->notification_manager) {
        // Get client IP address
        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(client->socket_fd, (struct sockaddr*)&addr, &addr_len) == 0) {
            inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        } else {
            strncpy(client_ip, "unknown", sizeof(client_ip) - 1);
        }
        
        notification_manager_send_topic_notification(broker->notification_manager,
                                                   &broker->client_manager,
                                                   NOTIFICATION_TOPIC_PUBLISH,
                                                   client->client_id,
                                                   client_ip,
                                                   publish->topic,
                                                   broker->config.notification_destination_client_id);
    }
    
    LOG_DEBUG("Published to %d subscribers", subscriber_count);
    return 0;
}

int message_handler_subscribe(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_subscribe_t *subscribe) {
    if (!client || !broker || !subscribe) return -1;
    
    uint8_t *return_codes = malloc(subscribe->topic_count);
    if (!return_codes) {
        LOG_ERROR("Failed to allocate return codes");
        return -1;
    }
    
    for (uint16_t i = 0; i < subscribe->topic_count; i++) {
        const char *topic_filter = subscribe->topics[i];
        uint8_t qos = subscribe->qos_levels[i];
        
        // Validate topic filter
        if (!topic_filter || strlen(topic_filter) == 0) {
            return_codes[i] = 0x80; // Failure
            continue;
        }
        
        // Check authorization
        if (!message_handler_authorize_topic(broker, client, topic_filter, 0)) {
            LOG_WARNING("Client %s not authorized to subscribe to %s", client->client_id, topic_filter);
            return_codes[i] = 0x80; // Failure
            continue;
        }
        
        // Add subscription
        if (client_manager_add_subscription(client, topic_filter, qos) == 0) {
            return_codes[i] = qos; // Success
            
            // Send retained messages
            message_handler_send_retained(broker, client, topic_filter, qos);
            
            // Send topic subscribe notification if notification system is enabled
            if (broker->config.notification_enabled && broker->notification_manager) {
                // Get client IP address
                char client_ip[INET_ADDRSTRLEN];
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                if (getpeername(client->socket_fd, (struct sockaddr*)&addr, &addr_len) == 0) {
                    inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                } else {
                    strncpy(client_ip, "unknown", sizeof(client_ip) - 1);
                }
                
                notification_manager_send_topic_notification(broker->notification_manager,
                                                           &broker->client_manager,
                                                           NOTIFICATION_TOPIC_SUBSCRIBE,
                                                           client->client_id,
                                                           client_ip,
                                                           topic_filter,
                                                           broker->config.notification_destination_client_id);
            }
            
            LOG_DEBUG("Client %s subscribed to %s (QoS %d)", client->client_id, topic_filter, qos);
        } else {
            return_codes[i] = 0x80; // Failure
        }
    }
    
    // Send SUBACK
    uint8_t suback_buffer[256];
    int suback_len = mqtt_serialize_suback(suback_buffer, sizeof(suback_buffer), 
                                         subscribe->packet_id, return_codes, subscribe->topic_count);
    
    if (suback_len > 0) {
        message_handler_send_packet(client, suback_buffer, suback_len);
    }
    
    free(return_codes);
    return 0;
}

int message_handler_unsubscribe(mqtt_client_t *client, mqtt_broker_t *broker, const mqtt_unsubscribe_t *unsubscribe) {
    if (!client || !broker || !unsubscribe) return -1;
    
    for (uint16_t i = 0; i < unsubscribe->topic_count; i++) {
        const char *topic_filter = unsubscribe->topics[i];
        
        if (client_manager_remove_subscription(client, topic_filter) == 0) {
            LOG_DEBUG("Client %s unsubscribed from %s", client->client_id, topic_filter);
        }
    }
    
    // Send UNSUBACK
    uint8_t unsuback_buffer[4];
    int unsuback_len = mqtt_serialize_unsuback(unsuback_buffer, sizeof(unsuback_buffer), 
                                             unsubscribe->packet_id);
    
    if (unsuback_len > 0) {
        message_handler_send_packet(client, unsuback_buffer, unsuback_len);
    }
    
    return 0;
}

int message_handler_puback(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id) {
    if (!client || !broker) return -1;
    
    // Remove pending message
    if (client_manager_remove_pending_message(client, packet_id, true) == 0) {
        LOG_DEBUG("Received PUBACK from client %s for packet %u", client->client_id, packet_id);
    }
    
    return 0;
}

int message_handler_pingreq(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) return -1;
    
    LOG_DEBUG("PING from client %s", client->client_id);
    
    // Create PINGRESP packet (fixed header: 0xD0, 0x00)
    uint8_t pingresp_buffer[2] = {0xD0, 0x00};
    
    // Send PINGRESP directly
    int result = message_handler_send_packet(client, pingresp_buffer, 2);
    if (result == 0) {
        LOG_DEBUG("PINGRESP sent to client %s", client->client_id);
    }
    
    return result;
}

int message_handler_disconnect(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) return -1;
    
    LOG_INFO("Client %s disconnected gracefully", client->client_id);
    
    // Send disconnection notification
    if (broker->notification_manager) {
        notification_manager_send_notification(broker->notification_manager, &broker->client_manager, NOTIFICATION_CLIENT_DISCONNECTED, client->client_id, "");
    }
    
    // Clear will message on graceful disconnect
    client->will_flag = false;
    client->state = MQTT_CLIENT_DISCONNECTED;
    
    return 0;
}

int message_handler_broadcast(mqtt_broker_t *broker, const char *topic, 
                             const uint8_t *payload, uint32_t payload_len,
                             uint8_t qos, bool retain, mqtt_client_t *sender_client) {
    if (!broker || !topic) return 0;
    
    int subscriber_count = 0;
    mqtt_client_t *client = broker->client_manager.clients;
    
    while (client) {
        if (client->state == MQTT_CLIENT_CONNECTED && client != sender_client) {
            uint8_t client_qos;
            if (client_manager_is_subscribed(client, topic, &client_qos)) {
                // Use minimum QoS
                uint8_t effective_qos = (qos < client_qos) ? qos : client_qos;
                
                // Create PUBLISH packet
                mqtt_publish_t publish = {0};
                publish.topic = (char*)topic;
                publish.payload = (uint8_t*)payload;
                publish.payload_len = payload_len;
                publish.qos = effective_qos;
                publish.retain = retain;
                
                if (effective_qos > 0) {
                    publish.packet_id = client_manager_get_next_packet_id(client);
                }
                
                uint8_t publish_buffer[MQTT_BUFFER_SIZE];
                int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
                
                if (publish_len > 0) {
                    if (message_handler_send_packet(client, publish_buffer, publish_len) == 0) {
                        subscriber_count++;
                        
                        // Add to pending for QoS > 0
                        if (effective_qos > 0) {
                            client_manager_add_pending_message(client, publish.packet_id, 
                                                             publish_buffer, publish_len, effective_qos);
                        }
                    }
                }
            }
        }
        client = client->next;
    }
    
    return subscriber_count;
}

int message_handler_publish_will(mqtt_broker_t *broker, mqtt_client_t *client) {
    if (!broker || !client || !client->will_flag) return -1;
    
    LOG_INFO("Publishing will message for client %s: %s", client->client_id, client->will_topic);
    
    return message_handler_broadcast(broker, client->will_topic, 
                                   (uint8_t*)client->will_message, strlen(client->will_message),
                                   client->will_qos, client->will_retain, NULL);
}

int message_handler_send_packet(mqtt_client_t *client, const uint8_t *data, uint32_t length) {
    if (!client || !data || length == 0) return -1;
    
    ssize_t sent = client_manager_send(client, data, length);
    if (sent == length) {
        client->messages_sent++;
        return 0;
    }
    
    LOG_WARNING("Failed to send complete packet to client %s", client->client_id);
    return -1;
}

bool message_handler_authenticate(mqtt_broker_t *broker, const char *username, const char *password) {
    if (!broker) return false;
    
    // Allow anonymous if configured
    if (broker->config.allow_anonymous && (!username || strlen(username) == 0)) {
        return true;
    }
    
    // Simple authentication (in production, use proper authentication)
    if (username && password) {
        // TODO: Implement proper authentication from auth file
        return true;
    }
    
    return broker->config.allow_anonymous;
}



bool message_handler_authorize_topic(mqtt_broker_t *broker, mqtt_client_t *client, const char *topic, int action) {
    if (!broker || !client || !topic) return false;
    
    // Basic authorization - allow everything for now
    // TODO: Implement proper ACL from configuration
    (void)action; // Suppress unused parameter warning
    
    return true;
}

int message_handler_cert_request(mqtt_client_t *client, mqtt_broker_t *broker, 
                                const char *topic, const char *payload, size_t payload_len) {
    if (!client || !broker || !payload) {
        return -1;
    }
    
    LOG_INFO("Certificate request from client %s on topic %s", client->client_id, topic);
    
    // Parse certificate request
    cert_request_t request;
    if (!cert_manager_parse_request(payload, &request)) {
        LOG_ERROR("Failed to parse certificate request from client %s", client->client_id);
        
        // Send error response
        cert_response_t error_response = {0};
        strncpy(error_response.client_id, client->client_id, sizeof(error_response.client_id) - 1);
        error_response.success = false;
        strncpy(error_response.error_message, "Invalid certificate request format", 
                sizeof(error_response.error_message) - 1);
        
        char* response_json = cert_manager_serialize_response(&error_response);
        if (response_json) {
            message_handler_send_cert_response(client, broker, response_json);
            free(response_json);
        }
        return -1;
    }
    
    // Validate that client_id matches the requesting client
    if (strcmp(request.client_id, client->client_id) != 0) {
        LOG_WARNING("Certificate request client_id mismatch: %s vs %s", 
                   request.client_id, client->client_id);
        
        cert_response_t error_response = {0};
        strncpy(error_response.client_id, client->client_id, sizeof(error_response.client_id) - 1);
        error_response.success = false;
        strncpy(error_response.error_message, "Client ID mismatch in certificate request", 
                sizeof(error_response.error_message) - 1);
        
        char* response_json = cert_manager_serialize_response(&error_response);
        if (response_json) {
            message_handler_send_cert_response(client, broker, response_json);
            free(response_json);
        }
        return -1;
    }
    
    // Generate certificate
    cert_response_t response;
    bool success = cert_manager_generate_certificate(&request, &response);
    
    if (success) {
        LOG_INFO("Successfully generated certificate for client %s: cert=%s, key=%s", 
                 client->client_id, response.cert_path, response.key_path);
    } else {
        LOG_ERROR("Failed to generate certificate for client %s: %s", 
                 client->client_id, response.error_message);
    }
    
    // Send response back to client
    char* response_json = cert_manager_serialize_response(&response);
    if (response_json) {
        message_handler_send_cert_response(client, broker, response_json);
        free(response_json);
    }
    
    return success ? 0 : -1;
}

int message_handler_send_cert_response(mqtt_client_t *client, mqtt_broker_t *broker, 
                                      const char *response_json) {
    if (!client || !broker || !response_json) {
        return -1;
    }
    
    // Create response topic for this client
    char response_topic[256];
    snprintf(response_topic, sizeof(response_topic), "sys/cert/response/%s", client->client_id);
    
    // Create PUBLISH packet for response
    mqtt_publish_t publish = {0};
    publish.topic = response_topic;
    publish.payload = (uint8_t*)response_json;
    publish.payload_len = strlen(response_json);
    publish.qos = 1; // Use QoS 1 for reliable delivery
    publish.retain = false;
    publish.packet_id = client_manager_get_next_packet_id(client);
    
    uint8_t publish_buffer[MQTT_BUFFER_SIZE];
    int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
    
    if (publish_len > 0) {
        int result = message_handler_send_packet(client, publish_buffer, publish_len);
        if (result == 0) {
            LOG_DEBUG("Sent certificate response to client %s on topic %s", 
                     client->client_id, response_topic);
            
            // Add to pending for QoS 1
            client_manager_add_pending_message(client, publish.packet_id, 
                                             publish_buffer, publish_len, 1);
            return 0;
        }
    }
    
    LOG_ERROR("Failed to send certificate response to client %s", client->client_id);
    return -1;
}

int message_handler_cert_list(mqtt_client_t *client, mqtt_broker_t *broker) {
    if (!client || !broker) {
        return -1;
    }

    LOG_INFO("Certificate list request from client %s", client->client_id);

    // Get list of certificates for this client
    char* cert_list_json = cert_manager_serialize_certificate_list(client->client_id);
    if (!cert_list_json) {
        // Create empty response
        cJSON* json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "client_id", client->client_id);
        cJSON_AddNumberToObject(json, "total_count", 0);
        cJSON_AddItemToObject(json, "certificates", cJSON_CreateArray());
        cJSON_AddNumberToObject(json, "timestamp", time(NULL));
        cert_list_json = cJSON_Print(json);
        cJSON_Delete(json);
    }

    if (cert_list_json) {
        // Send response back to client
        char response_topic[256];
        snprintf(response_topic, sizeof(response_topic), "sys/cert/list/response/%s", client->client_id);
        
        mqtt_publish_t publish = {0};
        publish.topic = response_topic;
        publish.payload = (uint8_t*)cert_list_json;
        publish.payload_len = strlen(cert_list_json);
        publish.qos = 1;
        publish.retain = false;
        publish.packet_id = client_manager_get_next_packet_id(client);
        
        uint8_t publish_buffer[MQTT_BUFFER_SIZE];
        int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
        
        if (publish_len > 0) {
            int result = message_handler_send_packet(client, publish_buffer, publish_len);
            if (result == 0) {
                LOG_DEBUG("Sent certificate list to client %s", client->client_id);
                client_manager_add_pending_message(client, publish.packet_id, 
                                                 publish_buffer, publish_len, 1);
                free(cert_list_json);
                return 0;
            }
        }
        
        free(cert_list_json);
    }
    
    LOG_ERROR("Failed to send certificate list to client %s", client->client_id);
    return -1;
}

int message_handler_cert_revoke(mqtt_client_t *client, mqtt_broker_t *broker, const char *payload) {
    if (!client || !broker || !payload) {
        return -1;
    }

    LOG_INFO("Certificate revocation request from client %s", client->client_id);

    // Parse revocation request JSON
    cJSON* json = cJSON_Parse(payload);
    if (!json) {
        LOG_ERROR("Failed to parse certificate revocation request JSON from client %s", client->client_id);
        return -1;
    }

    cJSON* reference_field = cJSON_GetObjectItem(json, "reference_field");
    if (!cJSON_IsString(reference_field)) {
        LOG_ERROR("Missing or invalid reference_field in certificate revocation request from client %s", client->client_id);
        cJSON_Delete(json);
        return -1;
    }

    // Revoke the certificate
    bool success = cert_manager_revoke_certificate(client->client_id, reference_field->valuestring);
    
    // Create response
    cJSON* response_json = cJSON_CreateObject();
    cJSON_AddStringToObject(response_json, "client_id", client->client_id);
    cJSON_AddStringToObject(response_json, "reference_field", reference_field->valuestring);
    cJSON_AddBoolToObject(response_json, "success", success);
    cJSON_AddNumberToObject(response_json, "timestamp", time(NULL));
    
    if (!success) {
        cJSON_AddStringToObject(response_json, "error_message", "Certificate not found or already revoked");
    }

    char* response_str = cJSON_Print(response_json);
    if (response_str) {
        // Send response back to client
        char response_topic[256];
        snprintf(response_topic, sizeof(response_topic), "sys/cert/revoke/response/%s", client->client_id);
        
        mqtt_publish_t publish = {0};
        publish.topic = response_topic;
        publish.payload = (uint8_t*)response_str;
        publish.payload_len = strlen(response_str);
        publish.qos = 1;
        publish.retain = false;
        publish.packet_id = client_manager_get_next_packet_id(client);
        
        uint8_t publish_buffer[MQTT_BUFFER_SIZE];
        int publish_len = mqtt_serialize_publish(publish_buffer, sizeof(publish_buffer), &publish);
        
        if (publish_len > 0) {
            int result = message_handler_send_packet(client, publish_buffer, publish_len);
            if (result == 0) {
                LOG_DEBUG("Sent certificate revocation response to client %s", client->client_id);
                client_manager_add_pending_message(client, publish.packet_id, 
                                                 publish_buffer, publish_len, 1);
                free(response_str);
                cJSON_Delete(response_json);
                cJSON_Delete(json);
                return 0;
            }
        }
        
        free(response_str);
    }
    
    cJSON_Delete(response_json);
    cJSON_Delete(json);
    LOG_ERROR("Failed to send certificate revocation response to client %s", client->client_id);
    return -1;
}

int message_handler_send_retained(mqtt_broker_t *broker, mqtt_client_t *client, const char *topic_filter, uint8_t qos) {
    if (!broker || !client || !topic_filter) return 0;
    
    // TODO: Implement retained message storage and retrieval
    // For now, return 0 (no retained messages)
    (void)qos; // Suppress unused parameter warning
    
    return 0;
}

int message_handler_pubrec(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id) {
    if (!client || !broker) return -1;
    
    LOG_DEBUG("Received PUBREC from client %s for packet %u", client->client_id, packet_id);
    
    // Send PUBREL in response to PUBREC
    uint8_t pubrel_buffer[4];
    pubrel_buffer[0] = (MQTT_PUBREL << 4) | 0x02; // Fixed header with required flags
    pubrel_buffer[1] = 2; // Remaining length
    pubrel_buffer[2] = (packet_id >> 8) & 0xFF; // Packet ID MSB
    pubrel_buffer[3] = packet_id & 0xFF; // Packet ID LSB
    
    int result = message_handler_send_packet(client, pubrel_buffer, 4);
    if (result == 0) {
        LOG_DEBUG("Sent PUBREL to client %s for packet %u", client->client_id, packet_id);
        // Keep track of pending PUBREL for QoS 2 flow
        client_manager_add_pending_message(client, packet_id, pubrel_buffer, 4, 2);
    }
    
    return result;
}

int message_handler_pubrel(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id) {
    if (!client || !broker) return -1;
    
    LOG_DEBUG("Received PUBREL from client %s for packet %u", client->client_id, packet_id);
    
    // Send PUBCOMP in response to PUBREL
    uint8_t pubcomp_buffer[4];
    pubcomp_buffer[0] = MQTT_PUBCOMP << 4; // Fixed header
    pubcomp_buffer[1] = 2; // Remaining length
    pubcomp_buffer[2] = (packet_id >> 8) & 0xFF; // Packet ID MSB
    pubcomp_buffer[3] = packet_id & 0xFF; // Packet ID LSB
    
    int result = message_handler_send_packet(client, pubcomp_buffer, 4);
    if (result == 0) {
        LOG_DEBUG("Sent PUBCOMP to client %s for packet %u", client->client_id, packet_id);
        // Remove any pending QoS 2 message for this packet ID
        client_manager_remove_pending_message(client, packet_id, false);
    }
    
    return result;
}

int message_handler_pubcomp(mqtt_client_t *client, mqtt_broker_t *broker, uint16_t packet_id) {
    if (!client || !broker) return -1;
    
    LOG_DEBUG("Received PUBCOMP from client %s for packet %u", client->client_id, packet_id);
    
    // Remove pending PUBREL message for QoS 2 flow completion
    if (client_manager_remove_pending_message(client, packet_id, false) == 0) {
        LOG_DEBUG("QoS 2 message flow completed for packet %u from client %s", 
                 packet_id, client->client_id);
    }
    
    return 0;
}
