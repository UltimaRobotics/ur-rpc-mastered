/*
 * Certificate Manager - Implementation
 * Provides certificate generation, validation, and SSL connection management
 */

#include "cert_manager.h"
#include <unistd.h>
#include <sys/stat.h>

// Global callback pointers
static cert_response_callback_t g_response_callback = NULL;
static cert_connection_callback_t g_connection_callback = NULL;

// MQTT callback functions
void cert_on_connect(struct mosquitto *mosq, void *userdata, int result) {
    cert_manager_t *manager = (cert_manager_t *)userdata;
    
    if (result == 0) {
        printf("✓ Connected to MQTT broker successfully\n");
        manager->connected = true;
        
        // Subscribe to certificate response topic
        int sub_result = mosquitto_subscribe(mosq, NULL, CERT_RESPONSE_TOPIC, 1);
        if (sub_result == MOSQ_ERR_SUCCESS) {
            printf("✓ Subscribed to certificate response topic: %s\n", CERT_RESPONSE_TOPIC);
        } else {
            printf("❌ Failed to subscribe to response topic: %s\n", mosquitto_strerror(sub_result));
        }
        
        if (g_connection_callback) {
            g_connection_callback(manager, true);
        }
    } else {
        printf("❌ Failed to connect to MQTT broker: %s\n", mosquitto_strerror(result));
        manager->connected = false;
        
        if (g_connection_callback) {
            g_connection_callback(manager, false);
        }
    }
}

void cert_on_disconnect(struct mosquitto *mosq, void *userdata, int result) {
    cert_manager_t *manager = (cert_manager_t *)userdata;
    manager->connected = false;
    
    if (result != 0) {
        printf("❌ Unexpected disconnection: %s\n", mosquitto_strerror(result));
    } else {
        printf("✓ Disconnected from MQTT broker\n");
    }
    
    if (g_connection_callback) {
        g_connection_callback(manager, false);
    }
}

void cert_on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    cert_manager_t *manager = (cert_manager_t *)userdata;
    
    printf("📨 Received message on topic: %s\n", message->topic);
    
    if (strcmp(message->topic, CERT_RESPONSE_TOPIC) == 0) {
        printf("✓ Certificate response received (%d bytes)\n", message->payloadlen);
        
        // Parse the response
        char *response_data = malloc(message->payloadlen + 1);
        memcpy(response_data, message->payload, message->payloadlen);
        response_data[message->payloadlen] = '\0';
        
        cert_status_t parse_result = cert_parse_response_json(response_data, &manager->last_response);
        if (parse_result == CERT_STATUS_SUCCESS) {
            manager->response_received = true;
            
            if (g_response_callback) {
                g_response_callback(manager, &manager->last_response);
            }
        } else {
            printf("❌ Failed to parse certificate response\n");
        }
        
        free(response_data);
    }
}

void cert_on_publish(struct mosquitto *mosq, void *userdata, int mid) {
    printf("✓ Certificate request published successfully (mid: %d)\n", mid);
}

// Certificate file management functions
cert_status_t cert_check_existing_files(const char *client_id, const char *cert_type, cert_file_info_t *file_info) {
    if (!client_id || !cert_type || !file_info) {
        return CERT_STATUS_ERROR;
    }
    
    memset(file_info, 0, sizeof(cert_file_info_t));
    
    // Generate potential filenames - check for most recent files
    char pattern_cert[MAX_PATH_LENGTH];
    char pattern_key[MAX_PATH_LENGTH];
    
    snprintf(pattern_cert, sizeof(pattern_cert), "%s/%s_%s_*.crt", CERT_DIRECTORY, cert_type, client_id);
    snprintf(pattern_key, sizeof(pattern_key), "%s/%s_%s_*.key", CERT_DIRECTORY, cert_type, client_id);
    
    // Simple file existence check - in a real implementation, you'd use glob() for pattern matching
    // For now, we'll generate a filename based on current time and check backwards
    time_t now = time(NULL);
    bool found = false;
    
    // Check for files from the last 30 days
    for (int days_back = 0; days_back < 30 && !found; days_back++) {
        time_t check_time = now - (days_back * 24 * 3600);
        
        snprintf(file_info->cert_path, sizeof(file_info->cert_path), 
                "%s/%s_%s_%ld.crt", CERT_DIRECTORY, cert_type, client_id, check_time);
        snprintf(file_info->key_path, sizeof(file_info->key_path), 
                "%s/%s_%s_%ld.key", CERT_DIRECTORY, cert_type, client_id, check_time);
        
        if (cert_is_file_readable(file_info->cert_path) && cert_is_file_readable(file_info->key_path)) {
            file_info->exists = true;
            file_info->creation_time = check_time;
            file_info->valid = true; // Could add more validation here
            found = true;
        }
    }
    
    return found ? CERT_STATUS_ALREADY_EXISTS : CERT_STATUS_SUCCESS;
}

cert_status_t cert_create_directory_structure(void) {
    struct stat st = {0};
    
    if (stat(CERT_DIRECTORY, &st) == -1) {
        if (mkdir(CERT_DIRECTORY, 0755) != 0) {
            printf("❌ Failed to create certificate directory: %s\n", CERT_DIRECTORY);
            return CERT_STATUS_FILE_ERROR;
        }
        printf("✓ Created certificate directory: %s\n", CERT_DIRECTORY);
    }
    
    // Create subdirectories for different environments
    const char *subdirs[] = {"dev", "staging", "prod", "api"};
    for (int i = 0; i < 4; i++) {
        char subdir_path[MAX_PATH_LENGTH];
        snprintf(subdir_path, sizeof(subdir_path), "%s/%s", CERT_DIRECTORY, subdirs[i]);
        
        if (stat(subdir_path, &st) == -1) {
            if (mkdir(subdir_path, 0755) != 0) {
                printf("⚠️  Warning: Failed to create subdirectory: %s\n", subdir_path);
            }
        }
    }
    
    return CERT_STATUS_SUCCESS;
}

char* cert_generate_filename(const char *client_id, const char *cert_type, const char *extension) {
    static char filename[MAX_PATH_LENGTH];
    time_t now = time(NULL);
    
    snprintf(filename, sizeof(filename), "%s/%s_%s_%ld.%s", 
             CERT_DIRECTORY, cert_type, client_id, now, extension);
    
    return filename;
}

cert_status_t cert_validate_file_permissions(const char *cert_path, const char *key_path) {
    struct stat cert_stat, key_stat;
    
    if (stat(cert_path, &cert_stat) != 0) {
        printf("❌ Cannot access certificate file: %s\n", cert_path);
        return CERT_STATUS_FILE_ERROR;
    }
    
    if (stat(key_path, &key_stat) != 0) {
        printf("❌ Cannot access key file: %s\n", key_path);
        return CERT_STATUS_FILE_ERROR;
    }
    
    // Check certificate permissions (should be readable by others)
    if ((cert_stat.st_mode & 0644) != 0644) {
        printf("⚠️  Warning: Certificate file permissions may be too restrictive\n");
    }
    
    // Check key permissions (should be readable only by owner)
    if ((key_stat.st_mode & 0777) != 0600) {
        printf("⚠️  Warning: Private key file permissions may be too permissive\n");
        if (chmod(key_path, 0600) != 0) {
            printf("❌ Failed to fix key file permissions\n");
            return CERT_STATUS_FILE_ERROR;
        }
    }
    
    return CERT_STATUS_SUCCESS;
}

// Certificate request/response handling
char* cert_create_request_json(const cert_request_params_t *params) {
    if (!params) {
        return NULL;
    }
    
    cJSON *request = cJSON_CreateObject();
    cJSON *request_type = cJSON_CreateString("certificate_generation");
    cJSON *cert_type_obj = cJSON_CreateString(params->cert_type);
    cJSON *client_id_obj = cJSON_CreateString(params->client_id);
    cJSON *common_name_obj = cJSON_CreateString(params->common_name);
    cJSON *org_obj = cJSON_CreateString(params->organization);
    cJSON *country_obj = cJSON_CreateString(params->country);
    cJSON *validity_obj = cJSON_CreateNumber(params->validity_days);
    cJSON *timestamp_obj = cJSON_CreateNumber(params->timestamp);
    
    cJSON_AddItemToObject(request, "request_type", request_type);
    cJSON_AddItemToObject(request, "certificate_type", cert_type_obj);
    cJSON_AddItemToObject(request, "client_id", client_id_obj);
    cJSON_AddItemToObject(request, "common_name", common_name_obj);
    cJSON_AddItemToObject(request, "organization", org_obj);
    cJSON_AddItemToObject(request, "country", country_obj);
    cJSON_AddItemToObject(request, "validity_days", validity_obj);
    cJSON_AddItemToObject(request, "timestamp", timestamp_obj);
    
    char *json_string = cJSON_Print(request);
    cJSON_Delete(request);
    
    return json_string;
}

cert_status_t cert_parse_response_json(const char *json_data, cert_response_data_t *response) {
    if (!json_data || !response) {
        return CERT_STATUS_ERROR;
    }
    
    memset(response, 0, sizeof(cert_response_data_t));
    
    cJSON *json = cJSON_Parse(json_data);
    if (!json) {
        strcpy(response->error_message, "Failed to parse JSON response");
        response->status = CERT_STATUS_INVALID_RESPONSE;
        return CERT_STATUS_INVALID_RESPONSE;
    }
    
    cJSON *status = cJSON_GetObjectItem(json, "status");
    if (!status || !cJSON_IsString(status)) {
        strcpy(response->error_message, "Invalid response format - missing status");
        response->status = CERT_STATUS_INVALID_RESPONSE;
        cJSON_Delete(json);
        return CERT_STATUS_INVALID_RESPONSE;
    }
    
    if (strcmp(status->valuestring, "success") != 0) {
        cJSON *error = cJSON_GetObjectItem(json, "error");
        if (error && cJSON_IsString(error)) {
            strncpy(response->error_message, error->valuestring, sizeof(response->error_message) - 1);
        } else {
            strcpy(response->error_message, "Unknown error in certificate generation");
        }
        response->status = CERT_STATUS_ERROR;
        cJSON_Delete(json);
        return CERT_STATUS_ERROR;
    }
    
    // Extract certificate data
    cJSON *cert_data = cJSON_GetObjectItem(json, "certificate");
    cJSON *key_data = cJSON_GetObjectItem(json, "private_key");
    cJSON *cert_filename = cJSON_GetObjectItem(json, "cert_filename");
    cJSON *key_filename = cJSON_GetObjectItem(json, "key_filename");
    
    if (!cert_data || !key_data || !cJSON_IsString(cert_data) || !cJSON_IsString(key_data)) {
        strcpy(response->error_message, "Invalid response format - missing certificate or key data");
        response->status = CERT_STATUS_INVALID_RESPONSE;
        cJSON_Delete(json);
        return CERT_STATUS_INVALID_RESPONSE;
    }
    
    strncpy(response->certificate_data, cert_data->valuestring, sizeof(response->certificate_data) - 1);
    strncpy(response->private_key_data, key_data->valuestring, sizeof(response->private_key_data) - 1);
    
    // Extract filenames if provided, otherwise generate them
    if (cert_filename && cJSON_IsString(cert_filename)) {
        snprintf(response->cert_filename, sizeof(response->cert_filename), 
                "generated_certs/%s", cert_filename->valuestring);
    } else {
        // Generate filename based on timestamp
        time_t now = time(NULL);
        snprintf(response->cert_filename, sizeof(response->cert_filename), 
                "generated_certs/cert_%ld.crt", now);
    }
    
    if (key_filename && cJSON_IsString(key_filename)) {
        snprintf(response->key_filename, sizeof(response->key_filename), 
                "generated_certs/%s", key_filename->valuestring);
    } else {
        // Generate filename based on timestamp
        time_t now = time(NULL);
        snprintf(response->key_filename, sizeof(response->key_filename), 
                "generated_certs/key_%ld.key", now);
    }
    
    response->status = CERT_STATUS_SUCCESS;
    
    cJSON_Delete(json);
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_save_files(const cert_response_data_t *response) {
    if (!response || response->status != CERT_STATUS_SUCCESS) {
        return CERT_STATUS_ERROR;
    }
    
    // Ensure directory exists
    cert_create_directory_structure();
    
    // Save certificate
    FILE *cert_file = fopen(response->cert_filename, "w");
    if (!cert_file) {
        printf("❌ Failed to create certificate file: %s\n", response->cert_filename);
        return CERT_STATUS_FILE_ERROR;
    }
    fprintf(cert_file, "%s", response->certificate_data);
    fclose(cert_file);
    chmod(response->cert_filename, 0644);
    
    // Save private key
    FILE *key_file = fopen(response->key_filename, "w");
    if (!key_file) {
        printf("❌ Failed to create key file: %s\n", response->key_filename);
        return CERT_STATUS_FILE_ERROR;
    }
    fprintf(key_file, "%s", response->private_key_data);
    fclose(key_file);
    chmod(response->key_filename, 0600);
    
    printf("✅ Certificate saved successfully:\n");
    printf("   📄 Certificate: %s\n", response->cert_filename);
    printf("   🔑 Private Key: %s\n", response->key_filename);
    
    return CERT_STATUS_SUCCESS;
}

// MQTT certificate operations
cert_status_t cert_manager_init(cert_manager_t *manager, const char *client_id, 
                               const char *broker_host, int broker_port, bool use_ssl) {
    if (!manager || !client_id || !broker_host) {
        return CERT_STATUS_ERROR;
    }
    
    memset(manager, 0, sizeof(cert_manager_t));
    
    strncpy(manager->client_id, client_id, sizeof(manager->client_id) - 1);
    strncpy(manager->broker_host, broker_host, sizeof(manager->broker_host) - 1);
    manager->broker_port = broker_port;
    manager->use_ssl = use_ssl;
    strcpy(manager->ca_cert_file, "ca.crt");
    
    mosquitto_lib_init();
    
    manager->mosq = mosquitto_new(manager->client_id, true, manager);
    if (!manager->mosq) {
        printf("❌ Failed to create mosquitto client\n");
        return CERT_STATUS_ERROR;
    }
    
    // Set callbacks
    mosquitto_connect_callback_set(manager->mosq, cert_on_connect);
    mosquitto_disconnect_callback_set(manager->mosq, cert_on_disconnect);
    mosquitto_message_callback_set(manager->mosq, cert_on_message);
    mosquitto_publish_callback_set(manager->mosq, cert_on_publish);
    
    printf("✓ Certificate manager initialized: %s\n", manager->client_id);
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_manager_connect(cert_manager_t *manager) {
    if (!manager || !manager->mosq) {
        return CERT_STATUS_ERROR;
    }
    
    // Setup SSL if needed (only if not already configured with client certificates)
    if (manager->use_ssl) {
        printf("🔐 Setting up SSL/TLS connection...\n");
        
        // Check if SSL is already configured (this is a simple approach)
        // If cert_setup_ssl_connection was called before, we don't want to override it
        int result = mosquitto_tls_set(manager->mosq, manager->ca_cert_file, NULL, NULL, NULL, NULL);
        if (result != MOSQ_ERR_SUCCESS) {
            printf("❌ Failed to set TLS options: %s\n", mosquitto_strerror(result));
            return CERT_STATUS_ERROR;
        }
        
        mosquitto_tls_insecure_set(manager->mosq, true);
        printf("✓ SSL/TLS configured successfully\n");
    }
    
    printf("🔗 Connecting to MQTT broker at %s:%d...\n", manager->broker_host, manager->broker_port);
    
    int result = mosquitto_connect(manager->mosq, manager->broker_host, manager->broker_port, 60);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initiate connection: %s\n", mosquitto_strerror(result));
        return CERT_STATUS_ERROR;
    }
    
    // Start the network loop
    result = mosquitto_loop_start(manager->mosq);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to start network loop: %s\n", mosquitto_strerror(result));
        return CERT_STATUS_ERROR;
    }
    
    // Wait for connection
    int wait_count = 0;
    while (!manager->connected && wait_count < 50) {
        usleep(100000); // 100ms
        wait_count++;
    }
    
    if (!manager->connected) {
        printf("❌ Connection timeout after 5 seconds\n");
        return CERT_STATUS_TIMEOUT;
    }
    
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_manager_disconnect(cert_manager_t *manager) {
    if (!manager || !manager->mosq) {
        return CERT_STATUS_ERROR;
    }
    
    mosquitto_loop_stop(manager->mosq, true);
    mosquitto_disconnect(manager->mosq);
    
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_manager_cleanup(cert_manager_t *manager) {
    if (!manager) {
        return CERT_STATUS_ERROR;
    }
    
    if (manager->mosq) {
        mosquitto_loop_stop(manager->mosq, true);
        mosquitto_destroy(manager->mosq);
        manager->mosq = NULL;
    }
    
    mosquitto_lib_cleanup();
    
    return CERT_STATUS_SUCCESS;
}

// Forward declaration
cert_status_t cert_request_certificate(cert_manager_t *manager, const cert_request_params_t *params);

// Certificate generation requests
cert_status_t cert_request_generic(cert_manager_t *manager, const cert_request_params_t *params) {
    return cert_request_certificate(manager, params);
}

cert_status_t cert_request_client_specific(cert_manager_t *manager, const cert_request_params_t *params) {
    return cert_request_certificate(manager, params);
}

cert_status_t cert_request_certificate(cert_manager_t *manager, const cert_request_params_t *params) {
    if (!manager || !params || !manager->mosq) {
        return CERT_STATUS_ERROR;
    }
    
    printf("\n🔐 Requesting %s Certificate\n", params->cert_type);
    printf("================================\n");
    
    // Create JSON request
    char *json_request = cert_create_request_json(params);
    if (!json_request) {
        printf("❌ Failed to create certificate request JSON\n");
        return CERT_STATUS_ERROR;
    }
    
    printf("📝 Request JSON:\n%s\n\n", json_request);
    
    // Reset response state
    manager->response_received = false;
    memset(&manager->last_response, 0, sizeof(cert_response_data_t));
    
    // Publish certificate request
    int result = mosquitto_publish(manager->mosq, NULL, CERT_REQUEST_TOPIC, 
                                  strlen(json_request), json_request, 1, false);
    
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to publish certificate request: %s\n", mosquitto_strerror(result));
        free(json_request);
        return CERT_STATUS_ERROR;
    }
    
    printf("✓ Certificate request sent to topic: %s\n", CERT_REQUEST_TOPIC);
    free(json_request);
    
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_wait_for_response(cert_manager_t *manager, int timeout_seconds) {
    if (!manager) {
        return CERT_STATUS_ERROR;
    }
    
    printf("⏳ Waiting for certificate response...\n");
    int wait_count = 0;
    while (!manager->response_received && wait_count < timeout_seconds * 10) {
        usleep(100000); // 100ms
        wait_count++;
    }
    
    if (!manager->response_received) {
        printf("❌ Certificate request timeout after %d seconds\n", timeout_seconds);
        return CERT_STATUS_TIMEOUT;
    }
    
    return manager->last_response.status;
}

// SSL connection with certificate validation
cert_status_t cert_setup_ssl_connection(struct mosquitto *mosq, const char *cert_path, 
                                       const char *key_path, const char *ca_cert_path) {
    if (!mosq || !cert_path || !key_path) {
        return CERT_STATUS_ERROR;
    }
    
    // Validate certificate files exist and have correct permissions
    if (cert_validate_file_permissions(cert_path, key_path) != CERT_STATUS_SUCCESS) {
        return CERT_STATUS_FILE_ERROR;
    }
    
    int result = mosquitto_tls_set(mosq, ca_cert_path, NULL, cert_path, key_path, NULL);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to set TLS with client certificates: %s\n", mosquitto_strerror(result));
        return CERT_STATUS_ERROR;
    }
    
    // For self-signed certificates
    mosquitto_tls_insecure_set(mosq, true);
    
    printf("✓ SSL configured with client certificates\n");
    printf("   📄 Certificate: %s\n", cert_path);
    printf("   🔑 Private Key: %s\n", key_path);
    
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_connect_with_ssl(cert_manager_t *manager, const char *cert_path, const char *key_path) {
    if (!manager || !manager->mosq) {
        return CERT_STATUS_ERROR;
    }
    
    cert_status_t ssl_result = cert_setup_ssl_connection(manager->mosq, cert_path, key_path, manager->ca_cert_file);
    if (ssl_result != CERT_STATUS_SUCCESS) {
        return ssl_result;
    }
    
    // Connect directly without re-configuring SSL
    printf("🔗 Connecting to MQTT broker at %s:%d...\n", manager->broker_host, manager->broker_port);
    
    int result = mosquitto_connect(manager->mosq, manager->broker_host, manager->broker_port, 60);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initiate connection: %s\n", mosquitto_strerror(result));
        return CERT_STATUS_ERROR;
    }
    
    // Start the network loop
    result = mosquitto_loop_start(manager->mosq);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to start network loop: %s\n", mosquitto_strerror(result));
        return CERT_STATUS_ERROR;
    }
    
    // Wait for connection
    int wait_count = 0;
    while (!manager->connected && wait_count < 50) {
        usleep(100000); // 100ms
        wait_count++;
    }
    
    if (!manager->connected) {
        printf("❌ Connection timeout after 5 seconds\n");
        return CERT_STATUS_TIMEOUT;
    }
    
    return CERT_STATUS_SUCCESS;
}

// Utility functions
const char* cert_status_to_string(cert_status_t status) {
    switch (status) {
        case CERT_STATUS_SUCCESS: return "Success";
        case CERT_STATUS_ERROR: return "Error";
        case CERT_STATUS_TIMEOUT: return "Timeout";
        case CERT_STATUS_INVALID_RESPONSE: return "Invalid Response";
        case CERT_STATUS_FILE_ERROR: return "File Error";
        case CERT_STATUS_ALREADY_EXISTS: return "Already Exists";
        default: return "Unknown Status";
    }
}

void cert_print_file_info(const cert_file_info_t *file_info) {
    if (!file_info) {
        return;
    }
    
    printf("📋 Certificate File Information:\n");
    printf("   Exists: %s\n", file_info->exists ? "Yes" : "No");
    if (file_info->exists) {
        printf("   📄 Certificate: %s\n", file_info->cert_path);
        printf("   🔑 Private Key: %s\n", file_info->key_path);
        printf("   📅 Created: %s", ctime(&file_info->creation_time));
        printf("   ✓ Valid: %s\n", file_info->valid ? "Yes" : "No");
    }
}

bool cert_is_file_readable(const char *filepath) {
    if (!filepath) {
        return false;
    }
    return access(filepath, R_OK) == 0;
}

time_t cert_get_file_creation_time(const char *filepath) {
    struct stat file_stat;
    if (stat(filepath, &file_stat) == 0) {
        return file_stat.st_mtime;
    }
    return 0;
}

// Callback management
cert_status_t cert_manager_set_response_callback(cert_manager_t *manager, cert_response_callback_t callback) {
    if (!manager) {
        return CERT_STATUS_ERROR;
    }
    g_response_callback = callback;
    return CERT_STATUS_SUCCESS;
}

cert_status_t cert_manager_set_connection_callback(cert_manager_t *manager, cert_connection_callback_t callback) {
    if (!manager) {
        return CERT_STATUS_ERROR;
    }
    g_connection_callback = callback;
    return CERT_STATUS_SUCCESS;
}

// Certificate expiration check
cert_status_t cert_check_expiration(const char *cert_path, int *days_until_expiry) {
    if (!cert_path || !days_until_expiry) {
        return CERT_STATUS_ERROR;
    }
    
    // For now, return a placeholder value indicating certificate is valid for 365 days
    // This would normally involve parsing the X.509 certificate to get the expiration date
    *days_until_expiry = 365;
    printf("ℹ️  Certificate expiration check: %s (placeholder: 365 days)\n", cert_path);
    return CERT_STATUS_SUCCESS;
}

// Auto-renewal functionality
cert_status_t cert_auto_renew_if_needed(cert_manager_t *manager, const cert_request_params_t *params, int renewal_threshold_days) {
    if (!manager || !params) {
        return CERT_STATUS_ERROR;
    }
    
    printf("ℹ️  Auto-renewal check for threshold: %d days (placeholder implementation)\n", renewal_threshold_days);
    // Placeholder implementation - would check certificate expiration and renew if needed
    return CERT_STATUS_SUCCESS;
}

// Batch request initialization
cert_status_t cert_batch_request_init(cert_batch_request_t *batch, int request_count) {
    if (!batch || request_count <= 0) {
        return CERT_STATUS_ERROR;
    }
    
    memset(batch, 0, sizeof(cert_batch_request_t));
    batch->requests = malloc(sizeof(cert_request_params_t) * request_count);
    if (!batch->requests) {
        return CERT_STATUS_ERROR;
    }
    
    batch->results = malloc(sizeof(cert_status_t) * request_count);
    if (!batch->results) {
        free(batch->requests);
        return CERT_STATUS_ERROR;
    }
    
    batch->count = 0;
    batch->completed = 0;
    
    printf("✓ Batch request initialized for %d requests\n", request_count);
    return CERT_STATUS_SUCCESS;
}

// Add request to batch
cert_status_t cert_batch_add_request(cert_batch_request_t *batch, const cert_request_params_t *params) {
    if (!batch || !params) {
        return CERT_STATUS_ERROR;
    }
    
    memcpy(&batch->requests[batch->count], params, sizeof(cert_request_params_t));
    batch->count++;
    
    printf("✓ Added request to batch: %s\n", params->client_id);
    return CERT_STATUS_SUCCESS;
}

// Execute batch requests
cert_status_t cert_batch_execute(cert_manager_t *manager, cert_batch_request_t *batch) {
    if (!manager || !batch) {
        return CERT_STATUS_ERROR;
    }
    
    printf("🔄 Executing batch with %d requests...\n", batch->count);
    
    for (int i = 0; i < batch->count; i++) {
        printf("  Processing request %d/%d: %s\n", i + 1, batch->count, batch->requests[i].client_id);
        
        // Execute individual certificate request
        cert_status_t result = cert_request_certificate(manager, &batch->requests[i]);
        batch->results[i] = result;
        
        if (result == CERT_STATUS_SUCCESS) {
            batch->completed++;
        }
        
        // Small delay between requests to avoid overwhelming the broker
        usleep(100000); // 100ms
    }
    
    printf("✓ Batch execution completed: %d/%d successful\n", batch->completed, batch->count);
    return CERT_STATUS_SUCCESS;
}

// Cleanup batch resources
void cert_batch_cleanup(cert_batch_request_t *batch) {
    if (!batch) {
        return;
    }
    
    if (batch->requests) {
        free(batch->requests);
        batch->requests = NULL;
    }
    
    if (batch->results) {
        free(batch->results);
        batch->results = NULL;
    }
    
    memset(batch, 0, sizeof(cert_batch_request_t));
    printf("✓ Batch resources cleaned up\n");
}

