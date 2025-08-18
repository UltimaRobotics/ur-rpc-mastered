
/*
 * SSL/TLS MQTT Certificate Generation Client
 * 
 * This application connects to an SSL/TLS MQTT broker using CA certificate
 * and key files, then performs certificate generation for both generic and
 * client-specific types using the cert_manager API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include "cert_manager.h"

// SSL/TLS configuration
#define SSL_BROKER_HOST "0.0.0.0"
#define SSL_BROKER_PORT 1855

// Client configuration
#define CLIENT_ID_PREFIX "runner"
#define RESPONSE_TIMEOUT 30

// Global variables for signal handling
static volatile bool running = true;
static cert_manager_t cert_manager;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    printf("\n[INFO] Received signal %d, shutting down gracefully...\n", signum);
    running = false;
}

// Setup signal handlers
void setup_signal_handlers(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

// Print usage information
void print_usage(const char *program_name) {
    printf("Usage: %s [options] <ca_cert> <client_cert> <client_key>\n", program_name);
    printf("Required arguments:\n");
    printf("  ca_cert        Path to CA certificate file\n");
    printf("  client_cert    Path to client certificate file\n");
    printf("  client_key     Path to client key file\n");
    printf("\nOptions:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -v, --verbose       Enable verbose output\n");
    printf("  -c, --client-id ID  Set custom client ID (default: auto-generated)\n");
    printf("  -o, --org ORG       Set organization name (default: TestOrg)\n");
    printf("  -n, --cn CN         Set common name (default: mqtt-client)\n");
    printf("  -d, --days DAYS     Set validity days (default: 365)\n");
    printf("  -H, --host HOST     Set broker host (default: %s)\n", SSL_BROKER_HOST);
    printf("  -p, --port PORT     Set broker port (default: %d)\n", SSL_BROKER_PORT);
    printf("\nThis client connects to SSL/TLS broker and generates certificates.\n");
}

// Generate unique client ID with timestamp
char* generate_client_id(const char *prefix) {
    static char client_id[MAX_CLIENT_ID_LENGTH];
    time_t now = time(NULL);
    int random_num = rand() % 10000;
    
    snprintf(client_id, sizeof(client_id), "%s_%d_%ld", 
             prefix, random_num, now);
    
    return client_id;
}

// Create certificate request parameters
cert_request_params_t create_cert_params(const char *client_id, const char *cert_type, 
                                       const char *common_name, const char *organization, 
                                       int validity_days) {
    cert_request_params_t params;
    memset(&params, 0, sizeof(params));
    
    strncpy(params.client_id, client_id, sizeof(params.client_id) - 1);
    strncpy(params.cert_type, cert_type, sizeof(params.cert_type) - 1);
    strncpy(params.common_name, common_name, sizeof(params.common_name) - 1);
    strncpy(params.organization, organization, sizeof(params.organization) - 1);
    strncpy(params.country, "US", sizeof(params.country) - 1);
    params.validity_days = validity_days;
    params.timestamp = time(NULL);
    
    return params;
}

// Perform certificate generation with detailed logging
cert_status_t perform_certificate_generation(cert_manager_t *manager, 
                                            const char *cert_type,
                                            const char *client_id,
                                            const char *common_name,
                                            const char *organization,
                                            int validity_days) {
    
    printf("\n[INFO] === Starting %s certificate generation ===\n", cert_type);
    printf("[INFO] Client ID: %s\n", client_id);
    printf("[INFO] Common Name: %s\n", common_name);
    printf("[INFO] Organization: %s\n", organization);
    printf("[INFO] Validity Days: %d\n", validity_days);
    
    // Check for existing certificates
    cert_file_info_t file_info;
    cert_status_t check_status = cert_check_existing_files(client_id, cert_type, &file_info);
    
    if (check_status == CERT_STATUS_ALREADY_EXISTS && file_info.exists) {
        printf("[INFO] Certificate already exists:\n");
        cert_print_file_info(&file_info);
        printf("[INFO] Skipping generation for existing certificate.\n");
        return CERT_STATUS_ALREADY_EXISTS;
    }
    
    // Create certificate request parameters
    cert_request_params_t params = create_cert_params(client_id, cert_type, 
                                                     common_name, organization, 
                                                     validity_days);
    
    // Send certificate request
    cert_status_t request_status;
    if (strcmp(cert_type, CERT_TYPE_GENERIC) == 0) {
        printf("[INFO] Sending generic certificate request...\n");
        request_status = cert_request_generic(manager, &params);
    } else {
        printf("[INFO] Sending client-specific certificate request...\n");
        request_status = cert_request_client_specific(manager, &params);
    }
    
    if (request_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to send certificate request: %s\n", 
               cert_status_to_string(request_status));
        return request_status;
    }
    
    printf("[INFO] Certificate request sent, waiting for response...\n");
    
    // Wait for response
    cert_status_t wait_status = cert_wait_for_response(manager, RESPONSE_TIMEOUT);
    
    if (wait_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to receive certificate response: %s\n", 
               cert_status_to_string(wait_status));
        return wait_status;
    }
    
    // Check response status
    if (manager->last_response.status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Certificate generation failed: %s\n", 
               manager->last_response.error_message);
        return manager->last_response.status;
    }
    
    // Save certificate files
    cert_status_t save_status = cert_save_files(&manager->last_response);
    
    if (save_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to save certificate files: %s\n", 
               cert_status_to_string(save_status));
        return save_status;
    }
    
    printf("[SUCCESS] %s certificate generated successfully!\n", cert_type);
    printf("[INFO] Certificate file: %s\n", manager->last_response.cert_filename);
    printf("[INFO] Key file: %s\n", manager->last_response.key_filename);
    
    return CERT_STATUS_SUCCESS;
}

// Test SSL connection with generated certificates
cert_status_t test_ssl_connection_with_cert(const char *cert_path, const char *key_path) {
    printf("\n[INFO] === Testing SSL connection with generated certificate ===\n");
    printf("[INFO] Certificate: %s\n", cert_path);
    printf("[INFO] Key: %s\n", key_path);
    
    // Create a test MQTT client for SSL connection
    struct mosquitto *test_mosq = mosquitto_new("ssl_test_client", true, NULL);
    if (!test_mosq) {
        printf("[ERROR] Failed to create test MQTT client\n");
        return CERT_STATUS_ERROR;
    }
    
    // Setup SSL connection
    cert_status_t ssl_status = cert_setup_ssl_connection(test_mosq, cert_path, 
                                                        key_path, cert_manager.ca_cert_file);
    
    if (ssl_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to setup SSL connection: %s\n", 
               cert_status_to_string(ssl_status));
        mosquitto_destroy(test_mosq);
        return ssl_status;
    }
    
    printf("[SUCCESS] SSL connection setup completed successfully\n");
    
    // Clean up
    mosquitto_destroy(test_mosq);
    return CERT_STATUS_SUCCESS;
}

// Main application function
int main(int argc, char *argv[]) {
    // Initialize variables
    char client_id[MAX_CLIENT_ID_LENGTH] = {0};
    char common_name[MAX_HOSTNAME_LENGTH] = "mqtt-client";
    char organization[128] = "TestOrg";
    char broker_host[256] = SSL_BROKER_HOST;
    int broker_port = SSL_BROKER_PORT;
    int validity_days = 365;
    bool verbose = false;
    
    // Required file paths
    char *ca_cert_file = NULL;
    char *client_cert_file = NULL;
    char *client_key_file = NULL;
    
    // Check minimum arguments
    if (argc < 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Parse command line arguments
    int arg_index = 1;
    while (arg_index < argc) {
        if (strcmp(argv[arg_index], "-h") == 0 || strcmp(argv[arg_index], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[arg_index], "-v") == 0 || strcmp(argv[arg_index], "--verbose") == 0) {
            verbose = true;
            arg_index++;
        } else if (strcmp(argv[arg_index], "-c") == 0 || strcmp(argv[arg_index], "--client-id") == 0) {
            if (arg_index + 1 < argc) {
                strncpy(client_id, argv[++arg_index], sizeof(client_id) - 1);
            }
            arg_index++;
        } else if (strcmp(argv[arg_index], "-o") == 0 || strcmp(argv[arg_index], "--org") == 0) {
            if (arg_index + 1 < argc) {
                strncpy(organization, argv[++arg_index], sizeof(organization) - 1);
            }
            arg_index++;
        } else if (strcmp(argv[arg_index], "-n") == 0 || strcmp(argv[arg_index], "--cn") == 0) {
            if (arg_index + 1 < argc) {
                strncpy(common_name, argv[++arg_index], sizeof(common_name) - 1);
            }
            arg_index++;
        } else if (strcmp(argv[arg_index], "-d") == 0 || strcmp(argv[arg_index], "--days") == 0) {
            if (arg_index + 1 < argc) {
                validity_days = atoi(argv[++arg_index]);
            }
            arg_index++;
        } else if (strcmp(argv[arg_index], "-H") == 0 || strcmp(argv[arg_index], "--host") == 0) {
            if (arg_index + 1 < argc) {
                strncpy(broker_host, argv[++arg_index], sizeof(broker_host) - 1);
            }
            arg_index++;
        } else if (strcmp(argv[arg_index], "-p") == 0 || strcmp(argv[arg_index], "--port") == 0) {
            if (arg_index + 1 < argc) {
                broker_port = atoi(argv[++arg_index]);
            }
            arg_index++;
        } else {
            // These should be the required file arguments
            if (!ca_cert_file) {
                ca_cert_file = argv[arg_index];
            } else if (!client_cert_file) {
                client_cert_file = argv[arg_index];
            } else if (!client_key_file) {
                client_key_file = argv[arg_index];
            } else {
                printf("[ERROR] Too many arguments\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            arg_index++;
        }
    }
    
    // Validate required arguments
    if (!ca_cert_file || !client_cert_file || !client_key_file) {
        printf("[ERROR] Missing required arguments: ca_cert, client_cert, client_key\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Generate client ID if not provided
    if (strlen(client_id) == 0) {
        strcpy(client_id, generate_client_id(CLIENT_ID_PREFIX));
    }
    
    printf("=== SSL/TLS MQTT Certificate Generation Client ===\n");
    printf("[INFO] Client ID: %s\n", client_id);
    printf("[INFO] Broker: %s:%d (SSL)\n", broker_host, broker_port);
    printf("[INFO] CA Certificate: %s\n", ca_cert_file);
    printf("[INFO] Client Certificate: %s\n", client_cert_file);
    printf("[INFO] Client Key: %s\n", client_key_file);
    printf("[INFO] Verbose: %s\n", verbose ? "enabled" : "disabled");
    
    // Setup signal handlers
    setup_signal_handlers();
    
    // Initialize random seed
    srand(time(NULL));
    
    // Initialize Mosquitto library
    if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
        printf("[ERROR] Failed to initialize Mosquitto library\n");
        return EXIT_FAILURE;
    }
    
    // Create certificate directory structure
    cert_status_t dir_status = cert_create_directory_structure();
    if (dir_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to create certificate directories: %s\n", 
               cert_status_to_string(dir_status));
        mosquitto_lib_cleanup();
        return EXIT_FAILURE;
    }
    
    // Initialize certificate manager
    cert_status_t init_status = cert_manager_init(&cert_manager, client_id, 
                                                 broker_host, broker_port, true);
    
    if (init_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to initialize certificate manager: %s\n", 
               cert_status_to_string(init_status));
        mosquitto_lib_cleanup();
        return EXIT_FAILURE;
    }
    
    // Set CA certificate file
    strncpy(cert_manager.ca_cert_file, ca_cert_file, sizeof(cert_manager.ca_cert_file) - 1);
    
    printf("[INFO] Certificate manager initialized successfully\n");
    
    // Connect to SSL/TLS broker
    printf("[INFO] Connecting to SSL/TLS broker...\n");
    cert_status_t connect_status = cert_connect_with_ssl(&cert_manager, 
                                                        client_cert_file, 
                                                        client_key_file);
    
    if (connect_status != CERT_STATUS_SUCCESS) {
        printf("[ERROR] Failed to connect to SSL/TLS broker: %s\n", 
               cert_status_to_string(connect_status));
        cert_manager_cleanup(&cert_manager);
        mosquitto_lib_cleanup();
        return EXIT_FAILURE;
    }
    
    printf("[SUCCESS] Connected to SSL/TLS broker successfully\n");
    
    // Perform certificate generation operations
    cert_status_t overall_status = CERT_STATUS_SUCCESS;
    
    // Generate generic certificate
    cert_status_t generic_status = perform_certificate_generation(&cert_manager, 
                                                                 CERT_TYPE_GENERIC,
                                                                 client_id,
                                                                 common_name,
                                                                 organization,
                                                                 validity_days);
    
    if (generic_status != CERT_STATUS_SUCCESS && generic_status != CERT_STATUS_ALREADY_EXISTS) {
        overall_status = generic_status;
    }
    
    // Generate client-specific certificate
    cert_status_t specific_status = perform_certificate_generation(&cert_manager, 
                                                                  CERT_TYPE_CLIENT_SPECIFIC,
                                                                  client_id,
                                                                  common_name,
                                                                  organization,
                                                                  validity_days);
    
    if (specific_status != CERT_STATUS_SUCCESS && specific_status != CERT_STATUS_ALREADY_EXISTS) {
        overall_status = specific_status;
    }
    
    // Test SSL connection with generated certificates if available
    if (generic_status == CERT_STATUS_SUCCESS || generic_status == CERT_STATUS_ALREADY_EXISTS) {
        char *generic_cert = cert_generate_filename(client_id, CERT_TYPE_GENERIC, ".crt");
        char *generic_key = cert_generate_filename(client_id, CERT_TYPE_GENERIC, ".key");
        
        if (generic_cert && generic_key) {
            char full_cert_path[MAX_PATH_LENGTH];
            char full_key_path[MAX_PATH_LENGTH];
            
            snprintf(full_cert_path, sizeof(full_cert_path), "%s/%s", CERT_DIRECTORY, generic_cert);
            snprintf(full_key_path, sizeof(full_key_path), "%s/%s", CERT_DIRECTORY, generic_key);
            
            if (cert_is_file_readable(full_cert_path) && cert_is_file_readable(full_key_path)) {
                test_ssl_connection_with_cert(full_cert_path, full_key_path);
            }
            
            free(generic_cert);
            free(generic_key);
        }
    }
    
    // Cleanup and disconnect
    printf("\n[INFO] Cleaning up and disconnecting...\n");
    cert_manager_disconnect(&cert_manager);
    cert_manager_cleanup(&cert_manager);
    mosquitto_lib_cleanup();
    
    // Print final status
    printf("\n=== Certificate Generation Summary ===\n");
    printf("[INFO] Generic certificate: %s\n", 
           cert_status_to_string(generic_status));
    printf("[INFO] Client-specific certificate: %s\n", 
           cert_status_to_string(specific_status));
    printf("[INFO] Overall status: %s\n", 
           cert_status_to_string(overall_status));
    
    if (overall_status == CERT_STATUS_SUCCESS || 
        (generic_status == CERT_STATUS_ALREADY_EXISTS && 
         specific_status == CERT_STATUS_ALREADY_EXISTS)) {
        printf("[SUCCESS] SSL/TLS certificate generation completed successfully!\n");
        return EXIT_SUCCESS;
    } else {
        printf("[ERROR] SSL/TLS certificate generation completed with errors\n");
        return EXIT_FAILURE;
    }
}

