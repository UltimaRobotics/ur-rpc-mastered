/*
 * Mosquitto SSL Certificate Client - Real MQTT Broker Communication
 * Connects to SSL MQTT broker and generates actual certificates via MQTT protocol
 * Enhanced with Certificate Manager API for comprehensive certificate lifecycle management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>
#include <time.h>
#include <sys/stat.h>
#include "../../deps/cjson/cJSON.h"
#include "cert_manager.h"

#define DEFAULT_BROKER_HOST "127.0.0.1"
#define DEFAULT_BROKER_PORT 1856
#define DEFAULT_SSL_PORT 1855
#define CERT_REQUEST_TOPIC "sys/cert/request"
#define CERT_RESPONSE_TOPIC "sys/cert/response"
#define MAX_WAIT_TIME 30

typedef struct {
    struct mosquitto *mosq;
    char broker_host[256];
    int broker_port;
    char client_id[128];
    bool connected;
    bool response_received;
    bool use_ssl;
    char ca_cert_file[512];
    char *response_data;
    int response_length;
    cert_manager_t cert_manager;
    char client_cert_path[512];
    char client_key_path[512];
    bool has_client_certs;
} MQTTCertClient;

static MQTTCertClient g_client = {0};

// Function to check for existing client certificates
int check_existing_certificates(MQTTCertClient *client, const char *cert_type) {
    cert_file_info_t file_info;
    cert_status_t status = cert_check_existing_files(client->client_id, cert_type, &file_info);
    
    if (status == CERT_STATUS_ALREADY_EXISTS) {
        printf("✓ Found existing certificates for %s\n", cert_type);
        cert_print_file_info(&file_info);
        
        strcpy(client->client_cert_path, file_info.cert_path);
        strcpy(client->client_key_path, file_info.key_path);
        client->has_client_certs = true;
        
        return 1; // Certificates exist
    }
    
    printf("ℹ️  No existing certificates found for %s\n", cert_type);
    return 0; // No certificates found
}

// Function to setup SSL with client certificates
int setup_ssl_with_client_certs(MQTTCertClient *client) {
    if (!client->use_ssl) {
        printf("ℹ️  SSL disabled - using plain TCP connection\n");
        return 0;
    }
    
    printf("🔐 Setting up SSL/TLS connection...\n");
    
    // Setup SSL with or without client certificates
    int result;
    if (client->has_client_certs) {
        printf("🔑 Using client certificates for authentication\n");
        result = mosquitto_tls_set(client->mosq, client->ca_cert_file, NULL, 
                                  client->client_cert_path, client->client_key_path, NULL);
    } else {
        printf("🔐 Using CA certificate only (no client authentication)\n");
        result = mosquitto_tls_set(client->mosq, client->ca_cert_file, NULL, NULL, NULL, NULL);
    }
    
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to set TLS options: %s\n", mosquitto_strerror(result));
        return -1;
    }
    
    // Allow insecure connections for self-signed certificates
    mosquitto_tls_insecure_set(client->mosq, true);
    
    printf("✓ SSL/TLS configured successfully\n");
    if (client->has_client_certs) {
        printf("   📄 Client Certificate: %s\n", client->client_cert_path);
        printf("   🔑 Client Key: %s\n", client->client_key_path);
    }
    printf("   🏛️  CA Certificate: %s\n", client->ca_cert_file);
    
    return 0;
}

// Enhanced certificate generation with automatic saving
int generate_and_save_certificate(MQTTCertClient *client, const char *cert_type,
                                 const char *common_name, const char *organization,
                                 const char *country, int validity_days) {
    
    // Initialize certificate manager
    cert_status_t status = cert_manager_init(&client->cert_manager, client->client_id,
                                           client->broker_host, client->broker_port, client->use_ssl);
    if (status != CERT_STATUS_SUCCESS) {
        printf("❌ Failed to initialize certificate manager\n");
        return -1;
    }
    
    // Connect to broker
    status = cert_manager_connect(&client->cert_manager);
    if (status != CERT_STATUS_SUCCESS) {
        printf("❌ Certificate manager failed to connect to broker\n");
        cert_manager_cleanup(&client->cert_manager);
        return -1;
    }
    
    // Prepare certificate request parameters
    cert_request_params_t params = {0};
    strncpy(params.client_id, client->client_id, sizeof(params.client_id) - 1);
    strncpy(params.cert_type, cert_type, sizeof(params.cert_type) - 1);
    strncpy(params.common_name, common_name, sizeof(params.common_name) - 1);
    strncpy(params.organization, organization, sizeof(params.organization) - 1);
    strncpy(params.country, country, sizeof(params.country) - 1);
    params.validity_days = validity_days;
    params.timestamp = time(NULL);
    
    // Request certificate
    status = cert_request_certificate(&client->cert_manager, &params);
    if (status != CERT_STATUS_SUCCESS) {
        printf("❌ Failed to send certificate request\n");
        cert_manager_cleanup(&client->cert_manager);
        return -1;
    }
    
    // Wait for response
    status = cert_wait_for_response(&client->cert_manager, MAX_WAIT_TIME);
    if (status != CERT_STATUS_SUCCESS) {
        printf("❌ Certificate request failed: %s\n", cert_status_to_string(status));
        cert_manager_cleanup(&client->cert_manager);
        return -1;
    }
    
    // Save the certificate files
    status = cert_save_files(&client->cert_manager.last_response);
    if (status == CERT_STATUS_SUCCESS) {
        // Update client paths for immediate use
        strcpy(client->client_cert_path, client->cert_manager.last_response.cert_filename);
        strcpy(client->client_key_path, client->cert_manager.last_response.key_filename);
        client->has_client_certs = true;
    }
    
    cert_manager_cleanup(&client->cert_manager);
    return (status == CERT_STATUS_SUCCESS) ? 0 : -1;
}

void on_connect(struct mosquitto *mosq, void *userdata, int result) {
    MQTTCertClient *client = (MQTTCertClient *)userdata;
    
    if (result == 0) {
        printf("✓ Connected to MQTT broker successfully\n");
        client->connected = true;
        
        // Subscribe to certificate response topic
        int sub_result = mosquitto_subscribe(mosq, NULL, CERT_RESPONSE_TOPIC, 1);
        if (sub_result == MOSQ_ERR_SUCCESS) {
            printf("✓ Subscribed to certificate response topic: %s\n", CERT_RESPONSE_TOPIC);
        } else {
            printf("❌ Failed to subscribe to response topic: %s\n", mosquitto_strerror(sub_result));
        }
    } else {
        printf("❌ Failed to connect to MQTT broker: %s\n", mosquitto_strerror(result));
        client->connected = false;
    }
}

void on_disconnect(struct mosquitto *mosq, void *userdata, int result) {
    MQTTCertClient *client = (MQTTCertClient *)userdata;
    client->connected = false;
    
    if (result != 0) {
        printf("❌ Unexpected disconnection: %s\n", mosquitto_strerror(result));
    } else {
        printf("✓ Disconnected from MQTT broker\n");
    }
}

void on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    MQTTCertClient *client = (MQTTCertClient *)userdata;
    
    printf("📨 Received message on topic: %s\n", message->topic);
    
    if (strcmp(message->topic, CERT_RESPONSE_TOPIC) == 0) {
        printf("✓ Certificate response received (%d bytes)\n", message->payloadlen);
        
        // Store response data
        if (client->response_data) {
            free(client->response_data);
        }
        client->response_data = malloc(message->payloadlen + 1);
        memcpy(client->response_data, message->payload, message->payloadlen);
        client->response_data[message->payloadlen] = '\0';
        client->response_length = message->payloadlen;
        client->response_received = true;
        
        printf("📄 Response content preview: %.100s%s\n", 
               client->response_data, 
               message->payloadlen > 100 ? "..." : "");
    }
}

void on_publish(struct mosquitto *mosq, void *userdata, int mid) {
    printf("✓ Certificate request published successfully (mid: %d)\n", mid);
}



int init_mqtt_client(MQTTCertClient *client) {
    mosquitto_lib_init();
    
    client->mosq = mosquitto_new(client->client_id, true, client);
    if (!client->mosq) {
        printf("❌ Failed to create mosquitto client\n");
        return -1;
    }
    
    // Set callbacks
    mosquitto_connect_callback_set(client->mosq, on_connect);
    mosquitto_disconnect_callback_set(client->mosq, on_disconnect);
    mosquitto_message_callback_set(client->mosq, on_message);
    mosquitto_publish_callback_set(client->mosq, on_publish);
    
    // Setup SSL if needed
    if (setup_ssl_with_client_certs(client) != 0) {
        return -1;
    }
    
    printf("✓ MQTT client initialized: %s\n", client->client_id);
    return 0;
}

int connect_to_broker(MQTTCertClient *client) {
    printf("🔗 Connecting to MQTT broker at %s:%d...\n", client->broker_host, client->broker_port);
    
    int result = mosquitto_connect(client->mosq, client->broker_host, client->broker_port, 60);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to initiate connection: %s\n", mosquitto_strerror(result));
        return -1;
    }
    
    // Start the network loop
    result = mosquitto_loop_start(client->mosq);
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to start network loop: %s\n", mosquitto_strerror(result));
        return -1;
    }
    
    // Wait for connection
    int wait_count = 0;
    while (!client->connected && wait_count < 50) {
        usleep(100000); // 100ms
        wait_count++;
    }
    
    if (!client->connected) {
        printf("❌ Connection timeout after 5 seconds\n");
        return -1;
    }
    
    return 0;
}

char* create_certificate_request_json(const char *cert_type, const char *client_id, 
                                     const char *common_name, const char *organization, 
                                     const char *country, int validity_days) {
    cJSON *request = cJSON_CreateObject();
    cJSON *request_type = cJSON_CreateString("certificate_generation");
    cJSON *cert_type_obj = cJSON_CreateString(cert_type);
    cJSON *client_id_obj = cJSON_CreateString(client_id);
    cJSON *common_name_obj = cJSON_CreateString(common_name);
    cJSON *org_obj = cJSON_CreateString(organization);
    cJSON *country_obj = cJSON_CreateString(country);
    cJSON *validity_obj = cJSON_CreateNumber(validity_days);
    cJSON *timestamp_obj = cJSON_CreateNumber(time(NULL));
    
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

int request_certificate(MQTTCertClient *client, const char *cert_type, 
                       const char *common_name, const char *organization, 
                       const char *country, int validity_days) {
    
    printf("\n🔐 Requesting %s Certificate\n", cert_type);
    printf("================================\n");
    
    // Create JSON request
    char *json_request = create_certificate_request_json(cert_type, client->client_id,
                                                        common_name, organization, 
                                                        country, validity_days);
    
    printf("📝 Request JSON:\n%s\n\n", json_request);
    
    // Publish certificate request
    int result = mosquitto_publish(client->mosq, NULL, CERT_REQUEST_TOPIC, 
                                  strlen(json_request), json_request, 1, false);
    
    if (result != MOSQ_ERR_SUCCESS) {
        printf("❌ Failed to publish certificate request: %s\n", mosquitto_strerror(result));
        free(json_request);
        return -1;
    }
    
    printf("✓ Certificate request sent to topic: %s\n", CERT_REQUEST_TOPIC);
    free(json_request);
    
    // Wait for response
    printf("⏳ Waiting for certificate response...\n");
    int wait_count = 0;
    while (!client->response_received && wait_count < MAX_WAIT_TIME * 10) {
        usleep(100000); // 100ms
        wait_count++;
    }
    
    if (!client->response_received) {
        printf("❌ Certificate request timeout after %d seconds\n", MAX_WAIT_TIME);
        return -1;
    }
    
    return 0;
}

int save_certificate_from_response(MQTTCertClient *client, const char *cert_type) {
    if (!client->response_data) {
        printf("❌ No response data to process\n");
        return -1;
    }
    
    printf("🔍 Processing certificate response...\n");
    
    // Parse JSON response
    cJSON *response = cJSON_Parse(client->response_data);
    if (!response) {
        printf("❌ Failed to parse JSON response\n");
        return -1;
    }
    
    cJSON *status = cJSON_GetObjectItem(response, "status");
    if (!status || !cJSON_IsString(status)) {
        printf("❌ Invalid response format - missing status\n");
        cJSON_Delete(response);
        return -1;
    }
    
    if (strcmp(status->valuestring, "success") != 0) {
        cJSON *error = cJSON_GetObjectItem(response, "error");
        printf("❌ Certificate generation failed: %s\n", 
               error && cJSON_IsString(error) ? error->valuestring : "Unknown error");
        cJSON_Delete(response);
        return -1;
    }
    
    // Extract certificate data
    cJSON *cert_data = cJSON_GetObjectItem(response, "certificate");
    cJSON *key_data = cJSON_GetObjectItem(response, "private_key");
    
    if (!cert_data || !key_data || !cJSON_IsString(cert_data) || !cJSON_IsString(key_data)) {
        printf("❌ Invalid response format - missing certificate or key data\n");
        cJSON_Delete(response);
        return -1;
    }
    
    // Create output directory
    system("mkdir -p generated_certs");
    
    // Generate filenames
    time_t now = time(NULL);
    char cert_filename[256];
    char key_filename[256];
    
    snprintf(cert_filename, sizeof(cert_filename), "generated_certs/%s_%s_%ld.crt", 
             cert_type, client->client_id, now);
    snprintf(key_filename, sizeof(key_filename), "generated_certs/%s_%s_%ld.key", 
             cert_type, client->client_id, now);
    
    // Save certificate
    FILE *cert_file = fopen(cert_filename, "w");
    if (!cert_file) {
        printf("❌ Failed to create certificate file: %s\n", cert_filename);
        cJSON_Delete(response);
        return -1;
    }
    fprintf(cert_file, "%s", cert_data->valuestring);
    fclose(cert_file);
    chmod(cert_filename, 0644);
    
    // Save private key
    FILE *key_file = fopen(key_filename, "w");
    if (!key_file) {
        printf("❌ Failed to create key file: %s\n", key_filename);
        cJSON_Delete(response);
        return -1;
    }
    fprintf(key_file, "%s", key_data->valuestring);
    fclose(key_file);
    chmod(key_filename, 0600);
    
    printf("✅ Certificate saved successfully:\n");
    printf("   📄 Certificate: %s\n", cert_filename);
    printf("   🔑 Private Key: %s\n", key_filename);
    
    cJSON_Delete(response);
    return 0;
}

void cleanup_client(MQTTCertClient *client) {
    if (client->mosq) {
        mosquitto_loop_stop(client->mosq, true);
        mosquitto_destroy(client->mosq);
    }
    
    if (client->response_data) {
        free(client->response_data);
    }
    
    mosquitto_lib_cleanup();
}

void print_usage(const char *program_name) {
    printf("🔐 Mosquitto SSL Certificate Client with Enhanced Certificate Manager\n");
    printf("====================================================================\n\n");
    printf("Usage: %s [OPTIONS] COMMAND\n\n", program_name);
    printf("Commands:\n");
    printf("  demo                    Generate both generic and client-specific certificates\n");
    printf("  generic                 Generate a generic certificate\n");
    printf("  client-specific         Generate a client-specific certificate\n");
    printf("  connect-ssl             Connect using existing SSL certificates\n");
    printf("  check-certs             Check for existing certificates\n");
    printf("  generate-and-connect    Generate certificates and connect with SSL\n\n");
    printf("Options:\n");
    printf("  -h, --host HOST         Broker hostname (default: %s)\n", DEFAULT_BROKER_HOST);
    printf("  -p, --port PORT         Broker port (default: %d for TCP, %d for SSL)\n", DEFAULT_BROKER_PORT, DEFAULT_SSL_PORT);
    printf("  -c, --client-id ID      Client ID (default: auto-generated)\n");
    printf("  -s, --ssl               Use SSL connection\n");
    printf("  --ca-cert FILE          CA certificate file for SSL\n");
    printf("  --cert-file FILE        Client certificate file path\n");
    printf("  --key-file FILE         Client private key file path\n");
    printf("  --cn COMMON_NAME        Common name (default: test.example.com)\n");
    printf("  --org ORGANIZATION      Organization (default: Test Organization)\n");
    printf("  --country COUNTRY       Country code (default: US)\n");
    printf("  --days DAYS             Validity days (default: 365)\n");
    printf("  --help                  Show this help\n\n");
    printf("Examples:\n");
    printf("  %s demo                                          # Generate demo certificates\n", program_name);
    printf("  %s -p 1883 generic --cn api.test.com            # Generate generic cert via TCP\n", program_name);
    printf("  %s -s -p 1855 connect-ssl                       # Connect with existing SSL certs\n", program_name);
    printf("  %s -s generate-and-connect                      # Generate certs and connect\n", program_name);
    printf("  %s check-certs                                  # Check for existing certificates\n", program_name);
    printf("  %s --cert-file client.crt --key-file client.key connect-ssl  # Use specific cert files\n", program_name);
}

int main(int argc, char *argv[]) {
    // Initialize client with defaults
    strcpy(g_client.broker_host, DEFAULT_BROKER_HOST);
    g_client.broker_port = DEFAULT_SSL_PORT;  // Default to SSL port
    g_client.use_ssl = true;                  // Default to SSL enabled
    snprintf(g_client.client_id, sizeof(g_client.client_id), "mqtt_cert_client_%d", getpid());
    strcpy(g_client.ca_cert_file, "ca.crt");
    g_client.has_client_certs = false;
    
    bool ssl_explicitly_set = false;
    
    // Certificate request defaults
    const char *common_name = "test.example.com";
    const char *organization = "Test Organization";
    const char *country = "US";
    int validity_days = 365;
    
    // Parse command line arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Enhanced argument parsing
    const char *command = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_client.broker_port = atoi(argv[++i]);
            printf("ℹ️  Using port: %d\n", g_client.broker_port);
            // Auto-detect SSL based on port if not explicitly set
            if (!ssl_explicitly_set) {
                g_client.use_ssl = (g_client.broker_port == DEFAULT_SSL_PORT);
            }
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            strcpy(g_client.broker_host, argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strcpy(g_client.client_id, argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0) {
            g_client.use_ssl = true;
            ssl_explicitly_set = true;
        } else if (strcmp(argv[i], "--cert-file") == 0 && i + 1 < argc) {
            strcpy(g_client.client_cert_path, argv[++i]);
            g_client.has_client_certs = true;
        } else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) {
            strcpy(g_client.client_key_path, argv[++i]);
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
            strcpy(g_client.ca_cert_file, argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            command = argv[i];
        }
    }
    
    if (!command) {
        print_usage(argv[0]);
        return 1;
    }
    
    printf("🚀 Starting Enhanced Mosquitto SSL Certificate Client\n");
    printf("=====================================================\n");
    printf("Broker: %s:%d\n", g_client.broker_host, g_client.broker_port);
    printf("Client ID: %s\n", g_client.client_id);
    printf("SSL: %s\n", g_client.use_ssl ? "enabled" : "disabled");
    if (g_client.has_client_certs) {
        printf("Client Certificate: %s\n", g_client.client_cert_path);
        printf("Client Key: %s\n", g_client.client_key_path);
    }
    printf("=====================================================\n\n");
    
    int result = 0;
    
    // Handle certificate checking commands that don't require connection
    if (strcmp(command, "check-certs") == 0) {
        printf("🔍 Checking for existing certificates...\n");
        printf("=======================================\n");
        
        // Check for generic certificates
        printf("\n📋 Generic Certificates:\n");
        if (check_existing_certificates(&g_client, "generic")) {
            printf("✓ Generic certificates found and loaded\n");
        } else {
            printf("ℹ️  No generic certificates found\n");
        }
        
        // Reset certificate paths for client-specific check
        g_client.has_client_certs = false;
        memset(g_client.client_cert_path, 0, sizeof(g_client.client_cert_path));
        memset(g_client.client_key_path, 0, sizeof(g_client.client_key_path));
        
        // Check for client-specific certificates
        printf("\n📋 Client-Specific Certificates:\n");
        if (check_existing_certificates(&g_client, "client_specific")) {
            printf("✓ Client-specific certificates found and loaded\n");
        } else {
            printf("ℹ️  No client-specific certificates found\n");
        }
        
        return 0;
    }
    
    // Handle generate-and-connect command
    if (strcmp(command, "generate-and-connect") == 0) {
        printf("🔄 Generate Certificates and Connect Workflow\n");
        printf("============================================\n");
        
        // Check for existing certificates first
        if (!check_existing_certificates(&g_client, "client_specific")) {
            printf("📝 Generating new client-specific certificate...\n");
            if (generate_and_save_certificate(&g_client, "client_specific", common_name, organization, country, validity_days) != 0) {
                printf("❌ Failed to generate certificate\n");
                return 1;
            }
        }
        
        // Now proceed to connect with SSL
        command = "connect-ssl";
    }
    
    // Initialize and connect for all other commands
    if (init_mqtt_client(&g_client) != 0) {
        return 1;
    }
    
    if (connect_to_broker(&g_client) != 0) {
        cleanup_client(&g_client);
        return 1;
    }
    
    if (strcmp(command, "demo") == 0) {
        printf("\n🎯 Running Certificate Generation Demo\n");
        printf("=====================================\n");
        
        // Generate generic certificate
        if (generate_and_save_certificate(&g_client, "generic", common_name, organization, country, validity_days) == 0) {
            printf("✓ Generic certificate generated successfully\n");
        }
        
        // Generate client-specific certificate
        if (generate_and_save_certificate(&g_client, "client_specific", common_name, organization, country, validity_days) == 0) {
            printf("✓ Client-specific certificate generated successfully\n");
        }
        
    } else if (strcmp(command, "generic") == 0) {
        result = generate_and_save_certificate(&g_client, "generic", common_name, organization, country, validity_days);
        
    } else if (strcmp(command, "client-specific") == 0) {
        result = generate_and_save_certificate(&g_client, "client_specific", common_name, organization, country, validity_days);
        
    } else if (strcmp(command, "connect-ssl") == 0) {
        printf("\n🔐 SSL Connection Test\n");
        printf("=====================\n");
        
        if (g_client.has_client_certs) {
            printf("✓ Using client certificates for authentication\n");
            printf("  📄 Certificate: %s\n", g_client.client_cert_path);
            printf("  🔑 Private Key: %s\n", g_client.client_key_path);
            
            // Test SSL connection features
            printf("\n🧪 Testing SSL connection features...\n");
            printf("⏳ Connection established, testing message publishing...\n");
            
            // Test publishing a message
            char test_message[256];
            snprintf(test_message, sizeof(test_message), 
                    "{\"test\": \"ssl_connection\", \"client_id\": \"%s\", \"timestamp\": %ld}", 
                    g_client.client_id, time(NULL));
            
            int pub_result = mosquitto_publish(g_client.mosq, NULL, "test/ssl_connection", 
                                             strlen(test_message), test_message, 1, false);
            if (pub_result == MOSQ_ERR_SUCCESS) {
                printf("✓ SSL message publishing successful\n");
            } else {
                printf("❌ SSL message publishing failed: %s\n", mosquitto_strerror(pub_result));
            }
            
        } else {
            printf("⚠️  No client certificates available\n");
            printf("💡 Use 'generate-and-connect' to generate certificates first\n");
            result = 1;
        }
        
    } else {
        printf("❌ Unknown command: %s\n", command);
        print_usage(argv[0]);
        result = 1;
    }
    
    printf("\n🏁 Certificate client operation completed\n");
    cleanup_client(&g_client);
    return result;
}
