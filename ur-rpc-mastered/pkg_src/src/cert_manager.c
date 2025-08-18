#include "cert_manager.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <cJSON.h>

// Certificate manager configuration
static struct {
    char ca_cert_path[512];
    char ca_key_path[512];
    char output_dir[512];
    bool initialized;
    cert_registry_entry_t* registry_head;  // Linked list of certificate registry entries
    uint32_t total_certificates;
    uint32_t active_certificates;
} cert_config = {0};

// Generate unique certificate serial number
static void generate_cert_serial(char* serial_buffer, size_t buffer_size) {
    static uint32_t serial_counter = 1;
    time_t now = time(NULL);
    snprintf(serial_buffer, buffer_size, "%08lx%08x", (unsigned long)now, serial_counter++);
}

bool cert_manager_init(const char* ca_cert_path, const char* ca_key_path, const char* output_dir) {
    if (!ca_cert_path || !ca_key_path || !output_dir) {
        return false;
    }

    // Verify CA certificate and key files exist
    if (access(ca_cert_path, R_OK) != 0) {
        LOG_ERROR("CA certificate file not accessible: %s", ca_cert_path);
        return false;
    }

    if (access(ca_key_path, R_OK) != 0) {
        LOG_ERROR("CA private key file not accessible: %s", ca_key_path);
        return false;
    }

    // Create output directory if it doesn't exist
    struct stat st = {0};
    if (stat(output_dir, &st) == -1) {
        if (mkdir(output_dir, 0755) != 0) {
            LOG_ERROR("Failed to create output directory: %s", output_dir);
            return false;
        }
    }

    // Store configuration
    strncpy(cert_config.ca_cert_path, ca_cert_path, sizeof(cert_config.ca_cert_path) - 1);
    strncpy(cert_config.ca_key_path, ca_key_path, sizeof(cert_config.ca_key_path) - 1);
    strncpy(cert_config.output_dir, output_dir, sizeof(cert_config.output_dir) - 1);
    cert_config.initialized = true;
    cert_config.registry_head = NULL;
    cert_config.total_certificates = 0;
    cert_config.active_certificates = 0;

    LOG_INFO("Certificate manager initialized successfully");
    LOG_INFO("CA Certificate: %s", ca_cert_path);
    LOG_INFO("CA Private Key: %s", ca_key_path);
    LOG_INFO("Output Directory: %s", output_dir);

    return true;
}

void cert_manager_cleanup(void) {
    // Clean up certificate registry
    cert_registry_entry_t* current = cert_config.registry_head;
    while (current) {
        cert_registry_entry_t* next = current->next;
        free(current);
        current = next;
    }
    memset(&cert_config, 0, sizeof(cert_config));
    LOG_INFO("Certificate manager cleaned up");
}

bool cert_manager_parse_request(const char* json_payload, cert_request_t* request) {
    if (!json_payload || !request) {
        return false;
    }

    LOG_DEBUG("Parsing certificate request JSON: %s", json_payload);
    
    cJSON* json = cJSON_Parse(json_payload);
    if (!json) {
        LOG_ERROR("Failed to parse certificate request JSON: %s", json_payload);
        return false;
    }

    bool success = true;
    memset(request, 0, sizeof(cert_request_t));

    // Parse required fields
    cJSON* client_id = cJSON_GetObjectItem(json, "client_id");
    if (cJSON_IsString(client_id)) {
        strncpy(request->client_id, client_id->valuestring, sizeof(request->client_id) - 1);
    } else {
        LOG_ERROR("Missing or invalid client_id in certificate request");
        success = false;
    }

    cJSON* cert_filename = cJSON_GetObjectItem(json, "cert_filename");
    if (cJSON_IsString(cert_filename)) {
        strncpy(request->cert_filename, cert_filename->valuestring, sizeof(request->cert_filename) - 1);
        LOG_DEBUG("Found cert_filename: %s", cert_filename->valuestring);
    } else {
        LOG_ERROR("Missing or invalid cert_filename in certificate request (found type: %d)", cert_filename ? cert_filename->type : -1);
        success = false;
    }

    cJSON* key_filename = cJSON_GetObjectItem(json, "key_filename");
    if (cJSON_IsString(key_filename)) {
        strncpy(request->key_filename, key_filename->valuestring, sizeof(request->key_filename) - 1);
        LOG_DEBUG("Found key_filename: %s", key_filename->valuestring);
    } else {
        LOG_ERROR("Missing or invalid key_filename in certificate request (found type: %d)", key_filename ? key_filename->type : -1);
        success = false;
    }

    // Parse optional fields with defaults
    cJSON* common_name = cJSON_GetObjectItem(json, "common_name");
    if (cJSON_IsString(common_name)) {
        strncpy(request->common_name, common_name->valuestring, sizeof(request->common_name) - 1);
    } else {
        strncpy(request->common_name, request->client_id, sizeof(request->common_name) - 1);
    }

    cJSON* organization = cJSON_GetObjectItem(json, "organization");
    if (cJSON_IsString(organization)) {
        strncpy(request->organization, organization->valuestring, sizeof(request->organization) - 1);
    } else {
        strncpy(request->organization, "MQTT Client", sizeof(request->organization) - 1);
    }

    cJSON* country = cJSON_GetObjectItem(json, "country");
    if (cJSON_IsString(country)) {
        strncpy(request->country, country->valuestring, sizeof(request->country) - 1);
    } else {
        strncpy(request->country, "US", sizeof(request->country) - 1);
    }

    cJSON* validity_days = cJSON_GetObjectItem(json, "validity_days");
    if (cJSON_IsNumber(validity_days)) {
        request->validity_days = validity_days->valueint;
    } else {
        request->validity_days = 365; // Default 1 year
    }

    cJSON* key_size = cJSON_GetObjectItem(json, "key_size");
    if (cJSON_IsNumber(key_size)) {
        request->key_size = key_size->valueint;
    } else {
        request->key_size = 2048; // Default RSA key size
    }

    // Parse reference field - allows clients to identify different certificates
    cJSON* reference_field = cJSON_GetObjectItem(json, "reference_field");
    if (cJSON_IsString(reference_field)) {
        strncpy(request->reference_field, reference_field->valuestring, sizeof(request->reference_field) - 1);
    } else {
        // Generate default reference if not provided
        snprintf(request->reference_field, sizeof(request->reference_field), "default_%s", request->client_id);
    }

    // Parse certificate type (generic or client-specific)
    cJSON* cert_type = cJSON_GetObjectItem(json, "cert_type");
    if (cJSON_IsNumber(cert_type)) {
        request->cert_type = (cert_type_e)cert_type->valueint;
    } else {
        request->cert_type = CERT_TYPE_CLIENT_SPECIFIC; // Default to client-specific
    }

    // Parse authorized clients for generic certificates
    cJSON* authorized_clients = cJSON_GetObjectItem(json, "authorized_clients");
    if (cJSON_IsString(authorized_clients)) {
        strncpy(request->authorized_clients, authorized_clients->valuestring, sizeof(request->authorized_clients) - 1);
    } else {
        request->authorized_clients[0] = '\0'; // Empty by default
    }

    // Parse enhanced certificate type
    cJSON* cert_request_type = cJSON_GetObjectItem(json, "certificate_type");
    if (cJSON_IsString(cert_request_type)) {
        const char* type_str = cert_request_type->valuestring;
        if (strcmp(type_str, "client") == 0) {
            request->cert_request_type = CERT_TYPE_CLIENT;
        } else if (strcmp(type_str, "server") == 0) {
            request->cert_request_type = CERT_TYPE_SERVER;
        } else if (strcmp(type_str, "ca") == 0) {
            request->cert_request_type = CERT_TYPE_CA;
        } else {
            request->cert_request_type = CERT_TYPE_CLIENT; // Default
        }
    } else {
        request->cert_request_type = CERT_TYPE_CLIENT; // Default
    }

    // Parse client auth flag
    cJSON* enable_client_auth = cJSON_GetObjectItem(json, "enable_client_auth");
    if (cJSON_IsBool(enable_client_auth)) {
        request->enable_client_auth = cJSON_IsTrue(enable_client_auth);
    } else {
        request->enable_client_auth = true; // Default to enabled
    }

    // Parse environment
    cJSON* environment = cJSON_GetObjectItem(json, "environment");
    if (cJSON_IsString(environment)) {
        request->environment = cert_manager_parse_environment_string(environment->valuestring);
    } else {
        request->environment = CERT_ENV_PROD; // Default to production
    }

    // Parse auto generate suffix flag
    cJSON* auto_suffix = cJSON_GetObjectItem(json, "auto_generate_suffix");
    if (cJSON_IsBool(auto_suffix)) {
        request->auto_generate_suffix = cJSON_IsTrue(auto_suffix);
    } else {
        request->auto_generate_suffix = true; // Default to auto-generate
    }

    // Parse custom hex suffix
    cJSON* custom_suffix = cJSON_GetObjectItem(json, "custom_hex_suffix");
    if (cJSON_IsString(custom_suffix)) {
        strncpy(request->custom_hex_suffix, custom_suffix->valuestring, sizeof(request->custom_hex_suffix) - 1);
    } else {
        request->custom_hex_suffix[0] = '\0'; // Empty by default
    }

    // Initialize metadata
    request->metadata.created_at = time(NULL);
    request->metadata.last_used = 0;
    request->metadata.usage_count = 0;
    request->metadata.version = 1;
    request->metadata.env_type = request->environment;
    strncpy(request->metadata.environment, cert_manager_get_environment_string(request->environment), 
            sizeof(request->metadata.environment) - 1);

    cJSON_Delete(json);
    return success;
}

char* cert_manager_serialize_response(const cert_response_t* response) {
    if (!response) {
        return NULL;
    }

    cJSON* json = cJSON_CreateObject();
    if (!json) {
        return NULL;
    }

    cJSON_AddStringToObject(json, "client_id", response->client_id);
    cJSON_AddStringToObject(json, "cert_filename", response->cert_filename);
    cJSON_AddStringToObject(json, "key_filename", response->key_filename);
    cJSON_AddStringToObject(json, "reference_field", response->reference_field);
    cJSON_AddBoolToObject(json, "success", response->success);

    if (!response->success) {
        cJSON_AddStringToObject(json, "error_message", response->error_message);
    } else {
        cJSON_AddStringToObject(json, "cert_path", response->cert_path);
        cJSON_AddStringToObject(json, "key_path", response->key_path);
        cJSON_AddStringToObject(json, "cert_serial", response->cert_serial);
        cJSON_AddStringToObject(json, "expiry_date", response->expiry_date);
    }

    cJSON_AddNumberToObject(json, "timestamp", time(NULL));

    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);

    return json_string;
}

bool cert_manager_validate_request(const cert_request_t* request) {
    if (!request) {
        return false;
    }

    // Validate client ID
    if (strlen(request->client_id) == 0 || strlen(request->client_id) >= sizeof(request->client_id)) {
        LOG_ERROR("Invalid client_id length");
        return false;
    }

    // Validate filenames
    if (!cert_manager_validate_filename(request->cert_filename)) {
        LOG_ERROR("Invalid certificate filename: %s", request->cert_filename);
        return false;
    }

    if (!cert_manager_validate_filename(request->key_filename)) {
        LOG_ERROR("Invalid key filename: %s", request->key_filename);
        return false;
    }

    // Validate key size (supported RSA key sizes)
    if (request->key_size != 1024 && request->key_size != 2048 && request->key_size != 4096) {
        LOG_ERROR("Invalid key size: %u (supported: 1024, 2048, 4096)", request->key_size);
        return false;
    }

    // Validate validity period (reasonable range)
    if (request->validity_days < 1 || request->validity_days > 3650) {
        LOG_ERROR("Invalid validity period: %u days (range: 1-3650)", request->validity_days);
        return false;
    }

    return true;
}

bool cert_manager_validate_filename(const char* filename) {
    if (!filename || strlen(filename) == 0) {
        return false;
    }

    // Check for path traversal attempts
    if (strstr(filename, "..") || strstr(filename, "/") || strstr(filename, "\\")) {
        return false;
    }

    // Check filename length
    if (strlen(filename) > 200) {
        return false;
    }

    // Check for valid characters (alphanumeric, dots, dashes, underscores)
    for (const char* p = filename; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_') {
            return false;
        }
    }

    return true;
}

bool cert_manager_generate_certificate(const cert_request_t* request, cert_response_t* response) {
    if (!cert_config.initialized) {
        LOG_ERROR("Certificate manager not initialized");
        return false;
    }

    if (!request || !response) {
        return false;
    }

    // Initialize response
    memset(response, 0, sizeof(cert_response_t));
    strncpy(response->client_id, request->client_id, sizeof(response->client_id) - 1);
    strncpy(response->cert_filename, request->cert_filename, sizeof(response->cert_filename) - 1);
    strncpy(response->key_filename, request->key_filename, sizeof(response->key_filename) - 1);

    // Validate request
    if (!cert_manager_validate_request(request)) {
        strncpy(response->error_message, "Invalid certificate request parameters", sizeof(response->error_message) - 1);
        return false;
    }

    // Generate full file paths
    snprintf(response->cert_path, sizeof(response->cert_path), "%s/%s", cert_config.output_dir, request->cert_filename);
    snprintf(response->key_path, sizeof(response->key_path), "%s/%s", cert_config.output_dir, request->key_filename);

    // Check if files already exist
    if (access(response->cert_path, F_OK) == 0) {
        snprintf(response->error_message, sizeof(response->error_message), 
                 "Certificate file already exists: %s", request->cert_filename);
        return false;
    }

    if (access(response->key_path, F_OK) == 0) {
        snprintf(response->error_message, sizeof(response->error_message), 
                 "Key file already exists: %s", request->key_filename);
        return false;
    }

    // Generate keypair using OpenSSL command
    char openssl_cmd[1024];
    snprintf(openssl_cmd, sizeof(openssl_cmd),
             "openssl genrsa -out %s %u 2>/dev/null", response->key_path, request->key_size);
    
    if (system(openssl_cmd) != 0) {
        snprintf(response->error_message, sizeof(response->error_message), 
                 "Failed to generate private key");
        return false;
    }

    // Generate certificate serial and response details
    generate_cert_serial(response->cert_serial, sizeof(response->cert_serial));
    strncpy(response->reference_field, request->reference_field, sizeof(response->reference_field) - 1);
    
    // Calculate expiry date
    time_t now = time(NULL);
    time_t expiry = now + (request->validity_days * 24 * 60 * 60);
    struct tm* expiry_tm = gmtime(&expiry);
    strftime(response->expiry_date, sizeof(response->expiry_date), "%Y-%m-%d", expiry_tm);

    // Generate certificate signing request
    char csr_path[512];
    snprintf(csr_path, sizeof(csr_path), "%s/%s_%s.csr", cert_config.output_dir, request->client_id, request->reference_field);

    snprintf(openssl_cmd, sizeof(openssl_cmd),
             "openssl req -new -key %s -out %s -subj \"/C=%s/O=%s/CN=%s\" 2>/dev/null",
             response->key_path, csr_path, request->country, request->organization, request->common_name);

    if (system(openssl_cmd) != 0) {
        unlink(response->key_path); // Cleanup private key
        snprintf(response->error_message, sizeof(response->error_message), 
                 "Failed to generate certificate signing request");
        return false;
    }

    // Sign certificate with CA
    snprintf(openssl_cmd, sizeof(openssl_cmd),
             "openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days %u 2>/dev/null",
             csr_path, cert_config.ca_cert_path, cert_config.ca_key_path, 
             response->cert_path, request->validity_days);

    if (system(openssl_cmd) != 0) {
        unlink(response->key_path); // Cleanup private key
        unlink(csr_path); // Cleanup CSR
        snprintf(response->error_message, sizeof(response->error_message), 
                 "Failed to sign certificate with CA");
        return false;
    }

    // Cleanup CSR file
    unlink(csr_path);

    // Set appropriate file permissions
    chmod(response->key_path, 0600);  // Private key: owner read/write only
    chmod(response->cert_path, 0644); // Certificate: owner read/write, others read

    response->success = true;
    
    // Register certificate in the registry
    if (!cert_manager_register_certificate(request, response)) {
        LOG_WARNING("Failed to register certificate in registry, but certificate generation succeeded");
    }
    
    // Save certificate for reuse in organized directory structure
    if (!cert_manager_save_certificate_for_reuse(request, response)) {
        LOG_WARNING("Failed to save certificate for reuse, but certificate generation succeeded");
    }
    
    LOG_INFO("Generated certificate for client %s (ref: %s, type: %s): cert=%s, key=%s", 
             request->client_id, request->reference_field, 
             (request->cert_type == CERT_TYPE_GENERIC) ? "generic" : "client-specific",
             response->cert_path, response->key_path);

    return true;
}

// Certificate registry management functions
bool cert_manager_register_certificate(const cert_request_t* request, const cert_response_t* response) {
    if (!request || !response || !response->success) {
        return false;
    }

    cert_registry_entry_t* entry = malloc(sizeof(cert_registry_entry_t));
    if (!entry) {
        LOG_ERROR("Failed to allocate memory for certificate registry entry");
        return false;
    }

    memset(entry, 0, sizeof(cert_registry_entry_t));
    
    // Copy data from request and response
    strncpy(entry->client_id, request->client_id, sizeof(entry->client_id) - 1);
    strncpy(entry->reference_field, request->reference_field, sizeof(entry->reference_field) - 1);
    strncpy(entry->cert_filename, request->cert_filename, sizeof(entry->cert_filename) - 1);
    strncpy(entry->key_filename, request->key_filename, sizeof(entry->key_filename) - 1);
    strncpy(entry->cert_serial, response->cert_serial, sizeof(entry->cert_serial) - 1);
    strncpy(entry->cert_path, response->cert_path, sizeof(entry->cert_path) - 1);
    strncpy(entry->key_path, response->key_path, sizeof(entry->key_path) - 1);
    entry->creation_time = time(NULL);
    entry->expiry_time = entry->creation_time + (request->validity_days * 24 * 60 * 60);
    entry->active = true;
    entry->cert_type = request->cert_type;
    strncpy(entry->authorized_clients, request->authorized_clients, sizeof(entry->authorized_clients) - 1);
    entry->usage_count = 0;
    
    // Enhanced fields for environment-based management
    entry->environment = request->environment;
    entry->version = request->metadata.version;
    entry->metadata = request->metadata;
    entry->metadata.created_at = entry->creation_time;
    
    // Generate or use provided hex suffix
    if (strlen(request->custom_hex_suffix) > 0) {
        strncpy(entry->hex_suffix, request->custom_hex_suffix, sizeof(entry->hex_suffix) - 1);
        strncpy(entry->metadata.hex_suffix, request->custom_hex_suffix, sizeof(entry->metadata.hex_suffix) - 1);
    } else {
        cert_manager_generate_hex_suffix(entry->hex_suffix);
        strncpy(entry->metadata.hex_suffix, entry->hex_suffix, sizeof(entry->metadata.hex_suffix) - 1);
    }

    // Add to linked list (at head)
    entry->next = cert_config.registry_head;
    cert_config.registry_head = entry;
    cert_config.total_certificates++;
    cert_config.active_certificates++;

    LOG_INFO("Registered certificate: client=%s, reference=%s, serial=%s", 
             entry->client_id, entry->reference_field, entry->cert_serial);

    return true;
}

cert_registry_entry_t* cert_manager_find_certificate_by_client_and_reference(const char* client_id, const char* reference_field) {
    if (!client_id || !reference_field) {
        return NULL;
    }

    cert_registry_entry_t* current = cert_config.registry_head;
    while (current) {
        if (current->active && 
            strcmp(current->client_id, client_id) == 0 && 
            strcmp(current->reference_field, reference_field) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

cert_registry_entry_t* cert_manager_list_client_certificates(const char* client_id) {
    // This returns the first certificate for the client
    // To get all certificates, the caller should iterate through the linked list
    if (!client_id) {
        return NULL;
    }

    cert_registry_entry_t* current = cert_config.registry_head;
    while (current) {
        if (current->active && strcmp(current->client_id, client_id) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

bool cert_manager_revoke_certificate(const char* client_id, const char* reference_field) {
    cert_registry_entry_t* entry = cert_manager_find_certificate_by_client_and_reference(client_id, reference_field);
    if (!entry) {
        return false;
    }

    entry->active = false;
    cert_config.active_certificates--;
    
    LOG_INFO("Revoked certificate: client=%s, reference=%s", client_id, reference_field);
    return true;
}

void cert_manager_cleanup_expired_certificates(void) {
    time_t now = time(NULL);
    cert_registry_entry_t* current = cert_config.registry_head;
    int expired_count = 0;

    while (current) {
        if (current->active && current->expiry_time < now) {
            current->active = false;
            cert_config.active_certificates--;
            expired_count++;
            LOG_INFO("Expired certificate: client=%s, reference=%s", 
                     current->client_id, current->reference_field);
        }
        current = current->next;
    }

    if (expired_count > 0) {
        LOG_INFO("Cleaned up %d expired certificates", expired_count);
    }
}

int cert_manager_get_client_certificate_count(const char* client_id) {
    if (!client_id) {
        return 0;
    }

    int count = 0;
    cert_registry_entry_t* current = cert_config.registry_head;
    while (current) {
        if (current->active && strcmp(current->client_id, client_id) == 0) {
            count++;
        }
        current = current->next;
    }
    return count;
}

char* cert_manager_serialize_certificate_list(const char* client_id) {
    if (!client_id) {
        return NULL;
    }

    cJSON* json = cJSON_CreateObject();
    cJSON* certificates = cJSON_CreateArray();
    
    if (!json || !certificates) {
        if (json) cJSON_Delete(json);
        if (certificates) cJSON_Delete(certificates);
        return NULL;
    }

    cJSON_AddStringToObject(json, "client_id", client_id);
    cJSON_AddItemToObject(json, "certificates", certificates);

    cert_registry_entry_t* current = cert_config.registry_head;
    int count = 0;
    while (current) {
        if (current->active && strcmp(current->client_id, client_id) == 0) {
            cJSON* cert_info = cJSON_CreateObject();
            cJSON_AddStringToObject(cert_info, "reference_field", current->reference_field);
            cJSON_AddStringToObject(cert_info, "cert_filename", current->cert_filename);
            cJSON_AddStringToObject(cert_info, "key_filename", current->key_filename);
            cJSON_AddStringToObject(cert_info, "cert_serial", current->cert_serial);
            cJSON_AddNumberToObject(cert_info, "creation_time", current->creation_time);
            cJSON_AddNumberToObject(cert_info, "expiry_time", current->expiry_time);
            cJSON_AddItemToArray(certificates, cert_info);
            count++;
        }
        current = current->next;
    }

    cJSON_AddNumberToObject(json, "total_count", count);
    cJSON_AddNumberToObject(json, "timestamp", time(NULL));

    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);

    return json_string;
}

// Enhanced certificate management functions for generic and client-specific certificates

bool cert_manager_validate_client_authorization(const char* client_id, const cert_registry_entry_t* cert_entry) {
    if (!client_id || !cert_entry) {
        return false;
    }

    // For client-specific certificates, verify exact client ID match
    if (cert_entry->cert_type == CERT_TYPE_CLIENT_SPECIFIC) {
        return strcmp(cert_entry->client_id, client_id) == 0;
    }

    // For generic certificates, check if client is in authorized list
    if (cert_entry->cert_type == CERT_TYPE_GENERIC) {
        if (strlen(cert_entry->authorized_clients) == 0) {
            // No restrictions - any client can use
            return true;
        }

        // Check if client_id is in the comma-separated authorized_clients list
        char* auth_list = strdup(cert_entry->authorized_clients);
        char* token = strtok(auth_list, ",");
        
        while (token != NULL) {
            // Trim whitespace
            while (*token == ' ') token++;
            char* end = token + strlen(token) - 1;
            while (end > token && *end == ' ') end--;
            *(end + 1) = '\0';
            
            if (strcmp(token, client_id) == 0) {
                free(auth_list);
                return true;
            }
            token = strtok(NULL, ",");
        }
        
        free(auth_list);
        return false;
    }

    return false;
}

bool cert_manager_create_certificate_directory(const char* client_id, const char* cert_type_name) {
    if (!client_id || !cert_type_name) {
        return false;
    }

    char dir_path[1024];
    snprintf(dir_path, sizeof(dir_path), "%s/%s/%s", cert_config.output_dir, cert_type_name, client_id);
    
    // Create directory recursively
    char* p = dir_path;
    for (p = strchr(dir_path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
            LOG_ERROR("Failed to create directory: %s", dir_path);
            return false;
        }
        *p = '/';
    }
    
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR("Failed to create final directory: %s", dir_path);
        return false;
    }

    LOG_INFO("Created certificate directory: %s", dir_path);
    return true;
}

char* cert_manager_get_certificate_storage_path(const char* client_id, const char* reference_field, cert_type_e cert_type) {
    if (!client_id || !reference_field) {
        return NULL;
    }

    static char storage_path[1024];
    const char* cert_type_name = (cert_type == CERT_TYPE_GENERIC) ? "generic" : "client-specific";
    
    snprintf(storage_path, sizeof(storage_path), "%s/%s/%s/%s", 
             cert_config.output_dir, cert_type_name, client_id, reference_field);
    
    return storage_path;
}

bool cert_manager_save_certificate_for_reuse(const cert_request_t* request, const cert_response_t* response) {
    if (!request || !response || !response->success) {
        return false;
    }

    const char* cert_type_name = (request->cert_type == CERT_TYPE_GENERIC) ? "generic" : "client-specific";
    
    // Create directory structure
    if (!cert_manager_create_certificate_directory(request->client_id, cert_type_name)) {
        return false;
    }

    // Get storage path
    char* storage_path = cert_manager_get_certificate_storage_path(
        request->client_id, request->reference_field, request->cert_type);
    
    if (!storage_path) {
        return false;
    }

    // Create subdirectory for this specific certificate
    if (mkdir(storage_path, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR("Failed to create certificate storage directory: %s", storage_path);
        return false;
    }

    // Copy certificate files to storage location
    char cert_dest[1024], key_dest[1024];
    snprintf(cert_dest, sizeof(cert_dest), "%s/%s", storage_path, request->cert_filename);
    snprintf(key_dest, sizeof(key_dest), "%s/%s", storage_path, request->key_filename);

    // Copy certificate file
    char copy_cmd[2048];
    snprintf(copy_cmd, sizeof(copy_cmd), "cp %s %s", response->cert_path, cert_dest);
    if (system(copy_cmd) != 0) {
        LOG_ERROR("Failed to copy certificate to storage");
        return false;
    }

    // Copy key file
    snprintf(copy_cmd, sizeof(copy_cmd), "cp %s %s", response->key_path, key_dest);
    if (system(copy_cmd) != 0) {
        LOG_ERROR("Failed to copy private key to storage");
        return false;
    }

    // Set appropriate permissions
    chmod(key_dest, 0600);  // Private key: owner read/write only
    chmod(cert_dest, 0644); // Certificate: owner read/write, others read

    // Create metadata file
    char metadata_path[1024];
    snprintf(metadata_path, sizeof(metadata_path), "%s/metadata.json", storage_path);
    
    cJSON* metadata = cJSON_CreateObject();
    cJSON_AddStringToObject(metadata, "client_id", request->client_id);
    cJSON_AddStringToObject(metadata, "reference_field", request->reference_field);
    cJSON_AddNumberToObject(metadata, "cert_type", request->cert_type);
    cJSON_AddStringToObject(metadata, "cert_filename", request->cert_filename);
    cJSON_AddStringToObject(metadata, "key_filename", request->key_filename);
    cJSON_AddStringToObject(metadata, "cert_serial", response->cert_serial);
    cJSON_AddNumberToObject(metadata, "creation_time", time(NULL));
    cJSON_AddNumberToObject(metadata, "validity_days", request->validity_days);
    cJSON_AddStringToObject(metadata, "authorized_clients", request->authorized_clients);
    
    char* metadata_json = cJSON_Print(metadata);
    FILE* metadata_file = fopen(metadata_path, "w");
    if (metadata_file) {
        fprintf(metadata_file, "%s", metadata_json);
        fclose(metadata_file);
    }
    
    free(metadata_json);
    cJSON_Delete(metadata);

    LOG_INFO("Saved certificate for reuse: %s (type: %s)", storage_path, cert_type_name);
    return true;
}

cert_registry_entry_t* cert_manager_find_reusable_certificate(const char* client_id, const char* reference_field) {
    if (!client_id || !reference_field) {
        return NULL;
    }

    cert_registry_entry_t* current = cert_config.registry_head;
    while (current) {
        if (current->active && 
            strcmp(current->reference_field, reference_field) == 0 &&
            cert_manager_validate_client_authorization(client_id, current)) {
            
            // Update usage count
            current->usage_count++;
            LOG_INFO("Found reusable certificate: client=%s, reference=%s, type=%s, usage_count=%u",
                     client_id, reference_field, 
                     (current->cert_type == CERT_TYPE_GENERIC) ? "generic" : "client-specific",
                     current->usage_count);
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

char* cert_manager_serialize_generic_certificate_list(void) {
    cJSON* json = cJSON_CreateObject();
    cJSON* certificates = cJSON_CreateArray();
    
    if (!json || !certificates) {
        if (json) cJSON_Delete(json);
        if (certificates) cJSON_Delete(certificates);
        return NULL;
    }

    cJSON_AddStringToObject(json, "cert_list_type", "generic_certificates");
    cJSON_AddItemToObject(json, "certificates", certificates);

    cert_registry_entry_t* current = cert_config.registry_head;
    int count = 0;
    while (current) {
        if (current->active && current->cert_type == CERT_TYPE_GENERIC) {
            cJSON* cert_info = cJSON_CreateObject();
            cJSON_AddStringToObject(cert_info, "client_id", current->client_id);
            cJSON_AddStringToObject(cert_info, "reference_field", current->reference_field);
            cJSON_AddStringToObject(cert_info, "cert_filename", current->cert_filename);
            cJSON_AddStringToObject(cert_info, "key_filename", current->key_filename);
            cJSON_AddStringToObject(cert_info, "cert_serial", current->cert_serial);
            cJSON_AddStringToObject(cert_info, "authorized_clients", current->authorized_clients);
            cJSON_AddNumberToObject(cert_info, "creation_time", current->creation_time);
            cJSON_AddNumberToObject(cert_info, "expiry_time", current->expiry_time);
            cJSON_AddNumberToObject(cert_info, "usage_count", current->usage_count);
            cJSON_AddItemToArray(certificates, cert_info);
            count++;
        }
        current = current->next;
    }

    cJSON_AddNumberToObject(json, "total_count", count);
    cJSON_AddNumberToObject(json, "timestamp", time(NULL));

    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);

    return json_string;
}

bool cert_manager_verify_client_specific_certificate(const char* client_id, const char* cert_path) {
    if (!client_id || !cert_path) {
        return false;
    }

    // Check if file exists
    if (access(cert_path, R_OK) != 0) {
        LOG_ERROR("Certificate file not accessible: %s", cert_path);
        return false;
    }

    // Use OpenSSL to extract subject from certificate
    char openssl_cmd[1024];
    char temp_file[] = "/tmp/cert_subject_XXXXXX";
    int temp_fd = mkstemp(temp_file);
    if (temp_fd == -1) {
        LOG_ERROR("Failed to create temporary file");
        return false;
    }
    close(temp_fd);

    snprintf(openssl_cmd, sizeof(openssl_cmd),
             "openssl x509 -in %s -noout -subject -nameopt RFC2253 2>/dev/null > %s",
             cert_path, temp_file);

    if (system(openssl_cmd) != 0) {
        unlink(temp_file);
        LOG_ERROR("Failed to extract certificate subject");
        return false;
    }

    // Read the subject from temp file
    FILE* subject_file = fopen(temp_file, "r");
    if (!subject_file) {
        unlink(temp_file);
        LOG_ERROR("Failed to read certificate subject");
        return false;
    }

    char subject_line[512];
    bool found_client_id = false;
    if (fgets(subject_line, sizeof(subject_line), subject_file)) {
        // Look for CN=client_id in the subject
        char expected_cn[128];
        snprintf(expected_cn, sizeof(expected_cn), "CN=%s", client_id);
        if (strstr(subject_line, expected_cn) != NULL) {
            found_client_id = true;
        }
    }

    fclose(subject_file);
    unlink(temp_file);

    if (found_client_id) {
        LOG_INFO("Client-specific certificate verified for client: %s", client_id);
        return true;
    } else {
        LOG_WARNING("Client ID verification failed for certificate: %s (expected client: %s)", 
                   cert_path, client_id);
        return false;
    }
}

// ===== ENHANCED ENVIRONMENT-BASED CERTIFICATE MANAGEMENT FUNCTIONS =====

const char* cert_manager_get_environment_string(cert_environment_t environment) {
    switch (environment) {
        case CERT_ENV_API:     return "api";
        case CERT_ENV_DEV:     return "dev";
        case CERT_ENV_PROD:    return "prod";
        case CERT_ENV_STAGING: return "staging";
        default:               return "prod";
    }
}

cert_environment_t cert_manager_parse_environment_string(const char* env_string) {
    if (!env_string) return CERT_ENV_PROD;
    
    if (strcmp(env_string, "api") == 0)     return CERT_ENV_API;
    if (strcmp(env_string, "dev") == 0)     return CERT_ENV_DEV;
    if (strcmp(env_string, "prod") == 0)    return CERT_ENV_PROD;
    if (strcmp(env_string, "staging") == 0) return CERT_ENV_STAGING;
    
    return CERT_ENV_PROD; // Default
}

bool cert_manager_generate_hex_suffix(char* suffix) {
    if (!suffix) return false;
    
    static const char hex_chars[] = "0123456789abcdef";
    srand(time(NULL) + rand());
    
    for (int i = 0; i < 8; i++) {
        suffix[i] = hex_chars[rand() % 16];
    }
    suffix[8] = '\0';
    
    return true;
}

bool cert_manager_generate_environment_filename(cert_environment_t environment, const char* client_id, 
                                               const char* reference_field, const char* hex_suffix,
                                               char* cert_filename, char* key_filename) {
    if (!client_id || !reference_field || !cert_filename || !key_filename) {
        return false;
    }
    
    const char* env_str = cert_manager_get_environment_string(environment);
    char generated_suffix[MAX_HEX_SUFFIX_LEN];
    
    // Use provided suffix or generate one
    if (hex_suffix && strlen(hex_suffix) > 0) {
        strncpy(generated_suffix, hex_suffix, sizeof(generated_suffix) - 1);
        generated_suffix[sizeof(generated_suffix) - 1] = '\0';
    } else {
        if (!cert_manager_generate_hex_suffix(generated_suffix)) {
            return false;
        }
    }
    
    // Generate filenames in format: {env}_cert_{reference}_{suffix}.crt/key
    snprintf(cert_filename, MAX_FILENAME_LEN, "%s_cert_%s_%s.crt", 
             env_str, reference_field, generated_suffix);
    snprintf(key_filename, MAX_FILENAME_LEN, "%s_cert_%s_%s.key", 
             env_str, reference_field, generated_suffix);
    
    return true;
}

bool cert_manager_request_environment_certificate(const cert_request_t* request, cert_response_t* response) {
    if (!request || !response) {
        return false;
    }
    
    LOG_INFO("Generating environment-based certificate for client %s in %s environment", 
             request->client_id, cert_manager_get_environment_string(request->environment));
    
    // Generate environment-based filenames if not provided
    char env_cert_filename[MAX_FILENAME_LEN];
    char env_key_filename[MAX_FILENAME_LEN];
    
    if (strlen(request->cert_filename) == 0 || strlen(request->key_filename) == 0) {
        const char* suffix = (strlen(request->custom_hex_suffix) > 0) ? 
                           request->custom_hex_suffix : NULL;
        
        if (!cert_manager_generate_environment_filename(request->environment, request->client_id,
                                                       request->reference_field, suffix,
                                                       env_cert_filename, env_key_filename)) {
            response->status = CERT_REQUEST_FAILED;
            strncpy(response->error_message, "Failed to generate environment filename", 
                   sizeof(response->error_message) - 1);
            return false;
        }
    } else {
        strncpy(env_cert_filename, request->cert_filename, sizeof(env_cert_filename) - 1);
        strncpy(env_key_filename, request->key_filename, sizeof(env_key_filename) - 1);
    }
    
    // Create modified request with environment filenames
    cert_request_t env_request = *request;
    strncpy(env_request.cert_filename, env_cert_filename, sizeof(env_request.cert_filename) - 1);
    strncpy(env_request.key_filename, env_key_filename, sizeof(env_request.key_filename) - 1);
    
    // Generate the certificate using existing logic
    bool success = cert_manager_generate_certificate(&env_request, response);
    
    if (success) {
        response->status = CERT_REQUEST_SUCCESS;
        response->broker_ssl_enabled = true;
        response->issued_at = time(NULL);
        response->expires_at = response->issued_at + (request->validity_days * 24 * 60 * 60);
        
        LOG_INFO("Environment certificate generated successfully: %s", env_cert_filename);
    } else {
        response->status = CERT_REQUEST_FAILED;
        LOG_ERROR("Failed to generate environment certificate for client %s", request->client_id);
    }
    
    return success;
}

bool cert_manager_list_certificates_by_environment(cert_environment_t environment, char* response, size_t response_size) {
    if (!response || response_size == 0) {
        return false;
    }
    
    cJSON* json = cJSON_CreateObject();
    cJSON* certificates = cJSON_CreateArray();
    
    cJSON_AddStringToObject(json, "environment", cert_manager_get_environment_string(environment));
    cJSON_AddStringToObject(json, "status", "success");
    cJSON_AddItemToObject(json, "certificates", certificates);
    
    // Iterate through certificate registry
    cert_registry_entry_t* current = cert_config.registry_head;
    int count = 0;
    
    while (current) {
        if (current->environment == environment && current->active) {
            cJSON* cert_info = cJSON_CreateObject();
            cJSON_AddStringToObject(cert_info, "client_id", current->client_id);
            cJSON_AddStringToObject(cert_info, "reference_field", current->reference_field);
            cJSON_AddStringToObject(cert_info, "cert_filename", current->cert_filename);
            cJSON_AddStringToObject(cert_info, "cert_serial", current->cert_serial);
            cJSON_AddNumberToObject(cert_info, "creation_time", current->creation_time);
            cJSON_AddNumberToObject(cert_info, "expiry_time", current->expiry_time);
            cJSON_AddNumberToObject(cert_info, "usage_count", current->usage_count);
            cJSON_AddStringToObject(cert_info, "hex_suffix", current->hex_suffix);
            cJSON_AddItemToArray(certificates, cert_info);
            count++;
        }
        current = current->next;
    }
    
    cJSON_AddNumberToObject(json, "certificate_count", count);
    
    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);
    
    if (json_string) {
        size_t len = strlen(json_string);
        if (len < response_size) {
            strcpy(response, json_string);
            free(json_string);
            return true;
        }
        free(json_string);
    }
    
    return false;
}

bool cert_manager_batch_generate_certificates(const cert_request_t* requests, int request_count, cert_response_t* responses) {
    if (!requests || !responses || request_count <= 0) {
        return false;
    }
    
    LOG_INFO("Starting batch certificate generation for %d requests", request_count);
    
    bool overall_success = true;
    
    for (int i = 0; i < request_count; i++) {
        LOG_DEBUG("Processing batch request %d/%d for client %s", 
                 i + 1, request_count, requests[i].client_id);
        
        bool request_success = cert_manager_request_environment_certificate(&requests[i], &responses[i]);
        if (!request_success) {
            overall_success = false;
            LOG_ERROR("Batch request %d failed for client %s", i + 1, requests[i].client_id);
        }
    }
    
    LOG_INFO("Batch certificate generation completed: %s", 
             overall_success ? "All successful" : "Some failures");
    
    return overall_success;
}

bool cert_manager_monitor_certificate_expiration(cert_environment_t environment, int days_until_expiry, 
                                                char* response, size_t response_size) {
    if (!response || response_size == 0 || days_until_expiry < 0) {
        return false;
    }
    
    time_t now = time(NULL);
    time_t threshold = now + (days_until_expiry * 24 * 60 * 60);
    
    cJSON* json = cJSON_CreateObject();
    cJSON* expiring_certs = cJSON_CreateArray();
    
    cJSON_AddStringToObject(json, "environment", 
                           environment == -1 ? "all" : cert_manager_get_environment_string(environment));
    cJSON_AddNumberToObject(json, "days_until_expiry", days_until_expiry);
    cJSON_AddNumberToObject(json, "check_timestamp", now);
    cJSON_AddItemToObject(json, "expiring_certificates", expiring_certs);
    
    cert_registry_entry_t* current = cert_config.registry_head;
    int expiring_count = 0;
    
    while (current) {
        bool env_match = (environment == -1) || (current->environment == environment);
        bool expires_soon = current->expiry_time <= threshold;
        
        if (current->active && env_match && expires_soon) {
            cJSON* cert_info = cJSON_CreateObject();
            cJSON_AddStringToObject(cert_info, "client_id", current->client_id);
            cJSON_AddStringToObject(cert_info, "reference_field", current->reference_field);
            cJSON_AddStringToObject(cert_info, "cert_filename", current->cert_filename);
            cJSON_AddNumberToObject(cert_info, "expiry_time", current->expiry_time);
            cJSON_AddNumberToObject(cert_info, "days_remaining", 
                                   (current->expiry_time - now) / (24 * 60 * 60));
            cJSON_AddStringToObject(cert_info, "environment", 
                                   cert_manager_get_environment_string(current->environment));
            cJSON_AddItemToArray(expiring_certs, cert_info);
            expiring_count++;
        }
        current = current->next;
    }
    
    cJSON_AddNumberToObject(json, "expiring_count", expiring_count);
    cJSON_AddStringToObject(json, "status", "success");
    
    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);
    
    if (json_string) {
        size_t len = strlen(json_string);
        if (len < response_size) {
            strcpy(response, json_string);
            free(json_string);
            return true;
        }
        free(json_string);
    }
    
    return false;
}

bool cert_manager_track_certificate_usage(cert_environment_t environment, const char* client_id) {
    if (!client_id) {
        return false;
    }
    
    cert_registry_entry_t* current = cert_config.registry_head;
    
    while (current) {
        if (current->environment == environment && 
            strcmp(current->client_id, client_id) == 0 && 
            current->active) {
            current->usage_count++;
            current->metadata.last_used = time(NULL);
            current->metadata.usage_count = current->usage_count;
            
            LOG_DEBUG("Updated usage count for certificate %s (client: %s, env: %s): %d",
                     current->cert_filename, client_id, 
                     cert_manager_get_environment_string(environment),
                     current->usage_count);
            return true;
        }
        current = current->next;
    }
    
    return false;
}

const char* cert_manager_get_status_string(cert_request_status_t status) {
    switch (status) {
        case CERT_REQUEST_SUCCESS:           return "Success";
        case CERT_REQUEST_FAILED:            return "Failed";
        case CERT_REQUEST_TIMEOUT:           return "Timeout";
        case CERT_REQUEST_INVALID_RESPONSE:  return "Invalid Response";
        case CERT_REQUEST_BROKER_NOT_SSL:    return "Broker Not SSL";
        case CERT_REQUEST_CONNECTION_FAILED: return "Connection Failed";
        case CERT_REQUEST_PARSE_ERROR:       return "Parse Error";
        default:                             return "Unknown Status";
    }
}

const char* cert_manager_get_validation_string(cert_validation_status_t status) {
    switch (status) {
        case CERT_VALID:                return "Valid";
        case CERT_INVALID_FORMAT:       return "Invalid Format";
        case CERT_EXPIRED:              return "Expired";
        case CERT_NOT_YET_VALID:        return "Not Yet Valid";
        case CERT_SIGNATURE_INVALID:    return "Invalid Signature";
        case CERT_FILE_NOT_FOUND:       return "File Not Found";
        default:                        return "Unknown Validation Status";
    }
}

cert_validation_status_t cert_manager_validate_certificate(const char* cert_file, cert_info_t* cert_info) {
    if (!cert_file || access(cert_file, R_OK) != 0) {
        return CERT_FILE_NOT_FOUND;
    }
    
    if (cert_info) {
        memset(cert_info, 0, sizeof(cert_info_t));
    }
    
    // Use OpenSSL to validate certificate
    char openssl_cmd[1024];
    char temp_file[] = "/tmp/cert_validation_XXXXXX";
    int temp_fd = mkstemp(temp_file);
    if (temp_fd == -1) {
        return CERT_INVALID_FORMAT;
    }
    close(temp_fd);
    
    // Check certificate validity
    snprintf(openssl_cmd, sizeof(openssl_cmd),
             "openssl x509 -in %s -noout -checkend 0 2>/dev/null", cert_file);
    
    int result = system(openssl_cmd);
    if (result != 0) {
        unlink(temp_file);
        return CERT_EXPIRED;
    }
    
    // Extract certificate info if requested
    if (cert_info) {
        // Get subject
        snprintf(openssl_cmd, sizeof(openssl_cmd),
                 "openssl x509 -in %s -noout -subject -nameopt RFC2253 2>/dev/null > %s",
                 cert_file, temp_file);
        
        if (system(openssl_cmd) == 0) {
            FILE* info_file = fopen(temp_file, "r");
            if (info_file) {
                if (fgets(cert_info->subject, sizeof(cert_info->subject), info_file)) {
                    // Remove newline
                    cert_info->subject[strcspn(cert_info->subject, "\n")] = '\0';
                }
                fclose(info_file);
            }
        }
        
        // Get serial number
        snprintf(openssl_cmd, sizeof(openssl_cmd),
                 "openssl x509 -in %s -noout -serial 2>/dev/null > %s",
                 cert_file, temp_file);
        
        if (system(openssl_cmd) == 0) {
            FILE* info_file = fopen(temp_file, "r");
            if (info_file) {
                if (fgets(cert_info->serial_number, sizeof(cert_info->serial_number), info_file)) {
                    cert_info->serial_number[strcspn(cert_info->serial_number, "\n")] = '\0';
                }
                fclose(info_file);
            }
        }
    }
    
    unlink(temp_file);
    return CERT_VALID;
}

// Additional missing functions implementations

bool cert_manager_search_certificates(const char* search_query, char* response, size_t response_size) {
    if (!search_query || !response || response_size == 0) {
        return false;
    }
    
    cJSON* query_json = cJSON_Parse(search_query);
    if (!query_json) {
        return false;
    }
    
    cJSON* result_json = cJSON_CreateObject();
    cJSON* certificates = cJSON_CreateArray();
    
    cJSON_AddStringToObject(result_json, "status", "success");
    cJSON_AddItemToObject(result_json, "certificates", certificates);
    
    // Extract search criteria
    cJSON* client_id_filter = cJSON_GetObjectItem(query_json, "client_id");
    cJSON* environment_filter = cJSON_GetObjectItem(query_json, "environment");
    cJSON* reference_filter = cJSON_GetObjectItem(query_json, "reference_field");
    
    cert_registry_entry_t* current = cert_config.registry_head;
    int match_count = 0;
    
    while (current) {
        bool matches = true;
        
        // Apply filters
        if (client_id_filter && cJSON_IsString(client_id_filter)) {
            if (strcmp(current->client_id, client_id_filter->valuestring) != 0) {
                matches = false;
            }
        }
        
        if (environment_filter && cJSON_IsString(environment_filter)) {
            cert_environment_t search_env = cert_manager_parse_environment_string(environment_filter->valuestring);
            if (current->environment != search_env) {
                matches = false;
            }
        }
        
        if (reference_filter && cJSON_IsString(reference_filter)) {
            if (strstr(current->reference_field, reference_filter->valuestring) == NULL) {
                matches = false;
            }
        }
        
        if (matches && current->active) {
            cJSON* cert_info = cJSON_CreateObject();
            cJSON_AddStringToObject(cert_info, "client_id", current->client_id);
            cJSON_AddStringToObject(cert_info, "reference_field", current->reference_field);
            cJSON_AddStringToObject(cert_info, "cert_filename", current->cert_filename);
            cJSON_AddStringToObject(cert_info, "cert_serial", current->cert_serial);
            cJSON_AddStringToObject(cert_info, "environment", cert_manager_get_environment_string(current->environment));
            cJSON_AddStringToObject(cert_info, "hex_suffix", current->hex_suffix);
            cJSON_AddNumberToObject(cert_info, "creation_time", current->creation_time);
            cJSON_AddNumberToObject(cert_info, "expiry_time", current->expiry_time);
            cJSON_AddNumberToObject(cert_info, "usage_count", current->usage_count);
            cJSON_AddItemToArray(certificates, cert_info);
            match_count++;
        }
        
        current = current->next;
    }
    
    cJSON_AddNumberToObject(result_json, "match_count", match_count);
    
    char* json_string = cJSON_Print(result_json);
    cJSON_Delete(result_json);
    cJSON_Delete(query_json);
    
    if (json_string) {
        size_t len = strlen(json_string);
        if (len < response_size) {
            strcpy(response, json_string);
            free(json_string);
            return true;
        }
        free(json_string);
    }
    
    return false;
}

bool cert_manager_revoke_certificate_by_environment(cert_environment_t environment, const char* client_id, cert_response_t* response) {
    if (!client_id || !response) {
        return false;
    }
    
    cert_registry_entry_t* current = cert_config.registry_head;
    bool found = false;
    
    while (current) {
        if (current->environment == environment && 
            strcmp(current->client_id, client_id) == 0 && 
            current->active) {
            
            current->active = false;
            cert_config.active_certificates--;
            
            // Fill response
            response->status = CERT_REQUEST_SUCCESS;
            response->success = true;
            strncpy(response->client_id, client_id, sizeof(response->client_id) - 1);
            strncpy(response->cert_filename, current->cert_filename, sizeof(response->cert_filename) - 1);
            strncpy(response->key_filename, current->key_filename, sizeof(response->key_filename) - 1);
            
            LOG_INFO("Revoked certificate for client %s in %s environment", 
                     client_id, cert_manager_get_environment_string(environment));
            found = true;
            break;
        }
        current = current->next;
    }
    
    if (!found) {
        response->status = CERT_REQUEST_FAILED;
        response->success = false;
        strncpy(response->error_message, "Certificate not found", sizeof(response->error_message) - 1);
    }
    
    return found;
}

bool cert_manager_rollback_certificate(cert_environment_t environment, const char* client_id, int version, cert_response_t* response) {
    if (!client_id || !response) {
        return false;
    }
    
    // For now, return a simple not implemented response
    response->status = CERT_REQUEST_FAILED;
    response->success = false;
    strncpy(response->error_message, "Certificate rollback not yet implemented", sizeof(response->error_message) - 1);
    
    LOG_WARNING("Certificate rollback requested but not yet implemented (client: %s, env: %s, version: %d)", 
               client_id, cert_manager_get_environment_string(environment), version);
    
    return false;
}