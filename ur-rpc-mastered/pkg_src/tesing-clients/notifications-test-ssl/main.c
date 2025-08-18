#include "notification_client.h"

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nConnection Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -t, --tcp               Use TCP connection (port %d)\n", BROKER_PORT_TCP);
    printf("  -s, --ssl               Use SSL connection (port %d)\n", BROKER_PORT_SSL);
    printf("  -a, --auto              Auto-detect connection type (default)\n");
    printf("  --host HOST             Broker hostname/IP (default: %s)\n", BROKER_HOST);
    printf("  --port PORT             Broker port (overrides default)\n");
    printf("  --topic TOPIC           Notification topic (default: %s)\n", TOPIC);
    printf("\nSSL Certificate Options:\n");
    printf("  --ca-cert PATH          CA certificate file path\n");
    printf("  --client-cert PATH      Client certificate file path\n");
    printf("  --client-key PATH       Client private key file path\n");
    printf("  --verify-peer           Enable SSL peer verification\n");
    printf("\nDescription:\n");
    printf("Enhanced MQTT notification client with SSL/TLS support.\n");
    printf("Connects to MQTT broker and listens for real-time notifications.\n");
    printf("\nExamples:\n");
    printf("  %s --ssl                                    # Use default certificates\n", program_name);
    printf("  %s --tcp                                    # Plain TCP connection\n", program_name);
    printf("  %s --ssl --ca-cert /path/ca.crt             # Custom CA certificate\n", program_name);
    printf("  %s --ssl --ca-cert /path/ca.crt --client-cert /path/client.crt --client-key /path/client.key\n", program_name);
    printf("  %s --ssl --verify-peer                      # Enable strict SSL verification\n", program_name);
    printf("\nDefault certificate paths:\n");
    printf("  CA Certificate: %s\n", CA_CERT_PATH);
    printf("  Client Certificate: %s\n", CLIENT_CERT_PATH);
    printf("  Client Key: %s\n", CLIENT_KEY_PATH);
    printf("\n");
}

int main(int argc, char *argv[]) {
    connection_type_t connection_type = CONNECTION_SSL;  // Default to SSL
    bool auto_detect = false;
    
    // Connection parameters
    char *broker_host = BROKER_HOST;
    int broker_port = -1;  // Will be set based on connection type if not specified
    char *notification_topic = TOPIC;
    
    // SSL configuration
    char *ca_cert_path = NULL;
    char *client_cert_path = NULL;
    char *client_key_path = NULL;
    bool verify_peer = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
            connection_type = CONNECTION_TCP;
            auto_detect = false;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--ssl") == 0) {
            connection_type = CONNECTION_SSL;
            auto_detect = false;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--auto") == 0) {
            auto_detect = true;
        } else if (strcmp(argv[i], "--ca-cert") == 0) {
            if (i + 1 < argc) {
                ca_cert_path = argv[++i];
            } else {
                printf("Error: --ca-cert requires a file path\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--client-cert") == 0) {
            if (i + 1 < argc) {
                client_cert_path = argv[++i];
            } else {
                printf("Error: --client-cert requires a file path\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--client-key") == 0) {
            if (i + 1 < argc) {
                client_key_path = argv[++i];
            } else {
                printf("Error: --client-key requires a file path\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--verify-peer") == 0) {
            verify_peer = true;
        } else if (strcmp(argv[i], "--host") == 0) {
            if (i + 1 < argc) {
                broker_host = argv[++i];
            } else {
                printf("Error: --host requires a hostname/IP\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                broker_port = atoi(argv[++i]);
                if (broker_port <= 0 || broker_port > 65535) {
                    printf("Error: Invalid port number. Must be 1-65535\n");
                    return 1;
                }
            } else {
                printf("Error: --port requires a port number\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--topic") == 0) {
            if (i + 1 < argc) {
                notification_topic = argv[++i];
            } else {
                printf("Error: --topic requires a topic name\n");
                print_usage(argv[0]);
                return 1;
            }
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("🚀 Enhanced SSL/TCP MQTT Notification Client\n");
    printf("==================================================\n");
    printf("This client identifies notification event types and represents data\n");
    printf("according to the structs defined in notification_client.h\n");
    printf("==================================================\n\n");
    
    // Create SSL configuration if needed
    ssl_config_t *ssl_config = NULL;
    if (connection_type == CONNECTION_SSL || auto_detect) {
        ssl_config = ssl_config_create(ca_cert_path, client_cert_path, client_key_path);
        if (ssl_config) {
            ssl_config->verify_peer = verify_peer;
            if (verify_peer) {
                printf("🔒 SSL peer verification enabled\n");
            }
        }
    }
    
    // Set default port if not specified
    if (broker_port == -1) {
        broker_port = (connection_type == CONNECTION_SSL) ? BROKER_PORT_SSL : BROKER_PORT_TCP;
    }
    
    printf("🔧 Connection Configuration:\n");
    printf("   Host: %s\n", broker_host);
    printf("   Port: %d\n", broker_port);
    printf("   Topic: %s\n", notification_topic);
    printf("   Connection Type: %s\n", (connection_type == CONNECTION_SSL) ? "SSL/TLS" : "TCP");
    if (ssl_config) {
        printf("   CA Certificate: %s\n", ssl_config->ca_cert_path);
        printf("   Client Certificate: %s\n", ssl_config->client_cert_path);
        printf("   Client Key: %s\n", ssl_config->client_key_path);
        printf("   Peer Verification: %s\n", ssl_config->verify_peer ? "Enabled" : "Disabled");
    }
    printf("\n");
    
    int result;
    
    // Run the appropriate notification listener
    if (auto_detect) {
        result = run_notification_listener_auto(ssl_config, broker_host, broker_port, notification_topic);
    } else {
        result = run_notification_listener(connection_type, ssl_config, broker_host, broker_port, notification_topic);
    }
    
    // Cleanup
    if (ssl_config) {
        free(ssl_config);
    }
    
    return result;
}