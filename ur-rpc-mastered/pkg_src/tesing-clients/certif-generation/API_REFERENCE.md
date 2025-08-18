# MQTT Certificate Generation API Reference

Complete technical reference for the mosquitto-based certificate generation API.

## Table of Contents
1. [API Overview](#api-overview)
2. [Function Reference](#function-reference)
3. [Data Structures](#data-structures)
4. [MQTT Protocol Implementation](#mqtt-protocol-implementation)
5. [SSL Configuration](#ssl-configuration)
6. [Error Handling](#error-handling)
7. [Integration Examples](#integration-examples)

## API Overview

The certificate generation API uses the mosquitto.h library to implement secure MQTT communication for certificate generation. The API provides a complete abstraction layer for certificate requests and responses.

### Core Architecture
```
Application Layer
    ↓
Certificate API (mosquitto_cert_client.c)
    ↓
mosquitto.h (MQTT Protocol)
    ↓
SSL/TLS Layer (OpenSSL)
    ↓
Network Transport (TCP/IP)
```

## Function Reference

### Core Functions

#### `int init_mqtt_client(MQTTCertClient *client)`
Initializes the MQTT client with SSL configuration.

**Parameters:**
- `client`: Pointer to MQTTCertClient structure

**Returns:**
- `0`: Success
- `-1`: Initialization failed

**Usage:**
```c
MQTTCertClient client = {0};
if (init_mqtt_client(&client) != 0) {
    // Handle initialization error
    return -1;
}
```

#### `int connect_to_broker(MQTTCertClient *client)`
Establishes SSL connection to MQTT broker.

**Parameters:**
- `client`: Initialized MQTTCertClient structure

**Returns:**
- `0`: Connection successful
- `-1`: Connection failed

**Features:**
- SSL/TLS handshake
- Certificate validation
- Topic subscription setup

#### `int setup_ssl(MQTTCertClient *client)`
Configures SSL/TLS settings for secure communication.

**Parameters:**
- `client`: MQTTCertClient with SSL configuration

**Returns:**
- `0`: SSL configured successfully
- `-1`: SSL configuration failed

**SSL Features:**
- CA certificate validation
- Insecure connection support for development
- TLS version negotiation

#### `int request_certificate(MQTTCertClient *client, const char *cert_type, const char *common_name, const char *organization, const char *country, int validity_days)`
Sends certificate generation request via MQTT.

**Parameters:**
- `client`: Connected MQTT client
- `cert_type`: "generic" or "client_specific"
- `common_name`: Certificate common name
- `organization`: Organization name
- `country`: 2-letter country code
- `validity_days`: Certificate validity period

**Returns:**
- `0`: Request sent successfully
- `-1`: Request failed

**JSON Request Generated:**
```json
{
    "request_type": "certificate_generation",
    "certificate_type": "generic|client_specific",
    "client_id": "mqtt_cert_client_12345",
    "common_name": "api.example.com",
    "organization": "Test Organization",
    "country": "US",
    "validity_days": 365,
    "timestamp": 1753611582
}
```

#### `int save_certificate_from_response(MQTTCertClient *client, const char *cert_type)`
Processes MQTT response and saves certificate files.

**Parameters:**
- `client`: Client with received response data
- `cert_type`: Certificate type for filename generation

**Returns:**
- `0`: Certificate saved successfully
- `-1`: Save operation failed

**File Operations:**
- Parses JSON response
- Extracts certificate and private key data
- Creates files with proper permissions
- Validates certificate format

### Callback Functions

#### `void on_connect(struct mosquitto *mosq, void *userdata, int result)`
MQTT connection callback handler.

**Parameters:**
- `mosq`: Mosquitto client instance
- `userdata`: MQTTCertClient pointer
- `result`: Connection result code

**Behavior:**
- Sets connection status
- Subscribes to response topic
- Handles connection errors

#### `void on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)`
MQTT message reception callback.

**Parameters:**
- `mosq`: Mosquitto client instance
- `userdata`: MQTTCertClient pointer
- `message`: Received MQTT message

**Processing:**
- Validates message topic
- Stores response data
- Sets response received flag
- Logs message details

#### `void on_disconnect(struct mosquitto *mosq, void *userdata, int result)`
MQTT disconnection callback handler.

**Parameters:**
- `mosq`: Mosquitto client instance
- `userdata`: MQTTCertClient pointer
- `result`: Disconnection result code

#### `void on_publish(struct mosquitto *mosq, void *userdata, int mid)`
MQTT publish confirmation callback.

**Parameters:**
- `mosq`: Mosquitto client instance
- `userdata`: MQTTCertClient pointer
- `mid`: Message ID

## Data Structures

### MQTTCertClient Structure
```c
typedef struct {
    struct mosquitto *mosq;           // Mosquitto client instance
    char broker_host[256];            // Broker hostname
    int broker_port;                  // Broker port number
    char client_id[128];              // Unique client identifier
    bool connected;                   // Connection status flag
    bool response_received;           // Response received flag
    bool use_ssl;                     // SSL enabled flag
    char ca_cert_file[512];          // CA certificate file path
    char *response_data;              // Received response data
    int response_length;              // Response data length
} MQTTCertClient;
```

### Configuration Constants
```c
#define DEFAULT_BROKER_HOST "127.0.0.1"
#define DEFAULT_BROKER_PORT 1856        // TCP port
#define DEFAULT_SSL_PORT 1855           // SSL port
#define CERT_REQUEST_TOPIC "sys/cert/request"
#define CERT_RESPONSE_TOPIC "sys/cert/response"
#define MAX_WAIT_TIME 30                // Response timeout
```

## MQTT Protocol Implementation

### Topic Structure
- **Request Topic**: `sys/cert/request`
- **Response Topic**: `sys/cert/response`

### QoS Levels
- **Request Messages**: QoS 1 (At least once delivery)
- **Response Subscription**: QoS 1 (Reliable delivery)

### Message Flow
1. **Connection**: Client connects with SSL to broker
2. **Subscription**: Subscribe to `sys/cert/response`
3. **Request**: Publish JSON request to `sys/cert/request`
4. **Response**: Receive JSON response on `sys/cert/response`
5. **Processing**: Parse response and save certificates
6. **Cleanup**: Disconnect and cleanup resources

### JSON Protocol

#### Request Schema
```json
{
    "$schema": "certificate_request",
    "type": "object",
    "properties": {
        "request_type": {
            "type": "string",
            "enum": ["certificate_generation"]
        },
        "certificate_type": {
            "type": "string",
            "enum": ["generic", "client_specific"]
        },
        "client_id": {
            "type": "string",
            "description": "Unique client identifier"
        },
        "common_name": {
            "type": "string",
            "description": "Certificate common name"
        },
        "organization": {
            "type": "string",
            "description": "Organization name"
        },
        "country": {
            "type": "string",
            "pattern": "^[A-Z]{2}$",
            "description": "2-letter country code"
        },
        "validity_days": {
            "type": "integer",
            "minimum": 1,
            "maximum": 3650,
            "description": "Certificate validity in days"
        },
        "timestamp": {
            "type": "integer",
            "description": "Request timestamp"
        }
    },
    "required": ["request_type", "certificate_type", "client_id", "common_name", "organization", "country", "validity_days", "timestamp"]
}
```

#### Response Schema
```json
{
    "$schema": "certificate_response",
    "type": "object",
    "properties": {
        "ssl_enabled": {
            "type": "boolean",
            "description": "Broker SSL status"
        },
        "cert_generation_enabled": {
            "type": "boolean",
            "description": "Certificate generation capability"
        },
        "status": {
            "type": "string",
            "enum": ["success", "error"]
        },
        "client_id": {
            "type": "string",
            "description": "Requesting client ID"
        },
        "certificate_type": {
            "type": "string",
            "enum": ["generic", "client_specific"]
        },
        "certificate_data": {
            "type": "string",
            "description": "PEM-encoded certificate"
        },
        "private_key_data": {
            "type": "string",
            "description": "PEM-encoded private key"
        },
        "certificate_filename": {
            "type": "string",
            "description": "Generated certificate filename"
        },
        "private_key_filename": {
            "type": "string",
            "description": "Generated private key filename"
        },
        "message": {
            "type": "string",
            "description": "Status message"
        }
    },
    "required": ["ssl_enabled", "cert_generation_enabled", "status", "client_id", "certificate_type", "message"]
}
```

## SSL Configuration

### CA Certificate Setup
```c
// Set CA certificate for validation
int result = mosquitto_tls_set(client->mosq, 
                               client->ca_cert_file,  // CA cert path
                               NULL,                  // CA path
                               NULL,                  // Client cert
                               NULL,                  // Client key
                               NULL);                 // Password callback
```

### Development vs Production SSL
```c
// Development: Allow insecure connections
mosquitto_tls_insecure_set(client->mosq, true);

// Production: Strict certificate validation
mosquitto_tls_insecure_set(client->mosq, false);
```

### TLS Versions
- **Supported**: TLS 1.2, TLS 1.3
- **Default**: Negotiated automatically
- **Ciphers**: Modern cipher suites preferred

## Error Handling

### Connection Errors
```c
// Check connection result
if (result != MOSQ_ERR_SUCCESS) {
    switch (result) {
        case MOSQ_ERR_INVAL:
            printf("Invalid parameters\n");
            break;
        case MOSQ_ERR_NOMEM:
            printf("Out of memory\n");
            break;
        case MOSQ_ERR_NO_CONN:
            printf("Not connected to broker\n");
            break;
        case MOSQ_ERR_PROTOCOL:
            printf("Protocol error\n");
            break;
        case MOSQ_ERR_CONN_REFUSED:
            printf("Connection refused\n");
            break;
        default:
            printf("Unknown error: %s\n", mosquitto_strerror(result));
    }
}
```

### SSL Errors
```c
// SSL-specific error handling
if (result == MOSQ_ERR_TLS) {
    printf("TLS/SSL error occurred\n");
    // Check CA certificate file
    // Verify broker SSL configuration
    // Check network connectivity
}
```

### Certificate Processing Errors
```c
// JSON parsing errors
cJSON *json = cJSON_Parse(response_data);
if (!json) {
    printf("Invalid JSON response\n");
    return -1;
}

// File operation errors
FILE *cert_file = fopen(filename, "w");
if (!cert_file) {
    printf("Failed to create certificate file: %s\n", strerror(errno));
    return -1;
}
```

## Integration Examples

### Basic Integration
```c
#include <mosquitto.h>
#include "../../ur-rpc-mastered/pkg_src/deps/cjson/cJSON.h"

int main() {
    MQTTCertClient client = {0};
    
    // Initialize client
    strcpy(client.broker_host, "127.0.0.1");
    client.broker_port = 1855;
    client.use_ssl = true;
    strcpy(client.ca_cert_file, "ca.crt");
    snprintf(client.client_id, sizeof(client.client_id), 
             "cert_client_%d", getpid());
    
    // Connect and generate certificate
    if (init_mqtt_client(&client) == 0) {
        if (connect_to_broker(&client) == 0) {
            request_certificate(&client, "generic", 
                               "api.example.com", 
                               "My Organization", 
                               "US", 365);
            
            // Wait for response and save certificate
            save_certificate_from_response(&client, "generic");
        }
    }
    
    cleanup_client(&client);
    return 0;
}
```

### Advanced Integration with Error Handling
```c
typedef struct {
    bool success;
    char error_message[512];
    char cert_filename[256];
    char key_filename[256];
} CertificateResult;

CertificateResult generate_certificate_secure(const char *common_name, 
                                             const char *cert_type,
                                             int validity_days) {
    CertificateResult result = {0};
    MQTTCertClient client = {0};
    
    // Setup client with error checking
    if (setup_client_configuration(&client) != 0) {
        strcpy(result.error_message, "Failed to configure client");
        return result;
    }
    
    // Initialize with timeout
    if (init_mqtt_client(&client) != 0) {
        strcpy(result.error_message, "MQTT initialization failed");
        return result;
    }
    
    // Connect with retry logic
    int retry_count = 3;
    while (retry_count > 0 && !client.connected) {
        if (connect_to_broker(&client) == 0) {
            break;
        }
        retry_count--;
        sleep(1);
    }
    
    if (!client.connected) {
        strcpy(result.error_message, "Failed to connect after retries");
        cleanup_client(&client);
        return result;
    }
    
    // Request certificate with timeout
    if (request_certificate(&client, cert_type, common_name, 
                           "Production", "US", validity_days) == 0) {
        
        // Wait for response with timeout
        time_t start_time = time(NULL);
        while (!client.response_received && 
               (time(NULL) - start_time) < MAX_WAIT_TIME) {
            mosquitto_loop(client.mosq, 100, 1);
        }
        
        if (client.response_received) {
            if (save_certificate_from_response(&client, cert_type) == 0) {
                result.success = true;
                // Copy filenames from response
                extract_filenames_from_response(&client, &result);
            } else {
                strcpy(result.error_message, "Failed to save certificate");
            }
        } else {
            strcpy(result.error_message, "Certificate request timeout");
        }
    } else {
        strcpy(result.error_message, "Failed to send certificate request");
    }
    
    cleanup_client(&client);
    return result;
}
```

### Batch Certificate Generation
```c
typedef struct {
    char common_name[256];
    char cert_type[32];
    int validity_days;
} CertificateRequest;

int generate_batch_certificates(CertificateRequest *requests, 
                               int request_count) {
    MQTTCertClient client = {0};
    int successful_count = 0;
    
    // Single connection for multiple requests
    if (init_mqtt_client(&client) != 0 || 
        connect_to_broker(&client) != 0) {
        return 0;
    }
    
    for (int i = 0; i < request_count; i++) {
        // Reset response state
        client.response_received = false;
        if (client.response_data) {
            free(client.response_data);
            client.response_data = NULL;
        }
        
        // Send request
        if (request_certificate(&client, 
                               requests[i].cert_type,
                               requests[i].common_name,
                               "Batch Generation",
                               "US",
                               requests[i].validity_days) == 0) {
            
            // Wait for response
            time_t start_time = time(NULL);
            while (!client.response_received && 
                   (time(NULL) - start_time) < MAX_WAIT_TIME) {
                mosquitto_loop(client.mosq, 100, 1);
            }
            
            if (client.response_received) {
                if (save_certificate_from_response(&client, 
                                                  requests[i].cert_type) == 0) {
                    successful_count++;
                    printf("Certificate %d generated successfully\n", i + 1);
                }
            }
        }
        
        // Brief delay between requests
        usleep(100000); // 100ms
    }
    
    cleanup_client(&client);
    return successful_count;
}
```

This API reference provides complete technical documentation for integrating the mosquitto-based certificate generation system into applications requiring secure certificate management via MQTT protocols.