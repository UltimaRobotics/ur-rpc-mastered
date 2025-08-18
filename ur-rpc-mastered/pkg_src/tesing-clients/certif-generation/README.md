# MQTT Certificate Generation Client - Mosquitto API

This directory contains a comprehensive certificate generation client using the mosquitto.h library for secure MQTT communication with the SSL broker.

## Overview

The MQTT Certificate Generation Client provides a production-ready interface for generating SSL certificates through secure MQTT messaging. It uses the mosquitto library for reliable MQTT communication and supports both generic and client-specific certificate generation.

## Core Components

### Files Structure
```
tesing-clients/certif-generation/
├── mosquitto_cert_client.c    # Main certificate client implementation
├── main                       # Compiled executable (copy of mosquitto_cert_client)
├── mosquitto_cert_client      # Primary executable
├── Makefile                   # Build configuration
├── ca.crt                     # CA certificate for SSL verification
├── generated_certs/           # Directory for generated certificates
└── README.md                  # This documentation
```

## Prerequisites

### System Requirements
- GCC compiler with C99 support
- mosquitto development library (libmosquitto-dev)
- OpenSSL development library (libssl-dev)
- cJSON library (libcjson-dev)
- MQTT broker running with SSL support on port 1855

### Dependencies Installation
The build system automatically handles library linking via pkg-config:
- `libmosquitto` - MQTT client library
- `libcjson` - JSON parsing and generation
- `openssl` - SSL/TLS cryptographic operations

## Compilation

### Quick Build
```bash
make
```

### Clean Build
```bash
make clean && make
```

### Debug Build
```bash
make debug
```

### Legacy Compatibility
```bash
make main  # Creates 'main' executable as copy of mosquitto_cert_client
```

## Usage Guide

### Basic Command Structure
```bash
./mosquitto_cert_client [OPTIONS] COMMAND
```

### Connection Configuration

#### Default Settings
- **Broker Host**: 127.0.0.1
- **SSL Port**: 1855 (default)
- **TCP Port**: 1856 (fallback)
- **SSL**: Enabled by default
- **CA Certificate**: ca.crt (in current directory)

#### Connection Options
```bash
-h, --host HOST         # Broker hostname (default: 127.0.0.1)
-p, --port PORT         # Broker port (1855 for SSL, 1856 for TCP)
-c, --client-id ID      # Client ID (default: auto-generated)
-s, --ssl               # Use SSL connection (enabled by default)
--ca-cert FILE          # CA certificate file for SSL validation
```

### Certificate Generation Commands

#### 1. Demo Mode (Recommended for Testing)
```bash
./mosquitto_cert_client demo
```
**Description**: Generates both generic and client-specific certificates with default parameters.

**Output**:
- Generic certificate: `generated_certs/generic_[client_id]_[timestamp].crt`
- Generic private key: `generated_certs/generic_[client_id]_[timestamp].key`
- Client-specific certificate: `generated_certs/client_specific_[client_id]_[timestamp].crt`
- Client-specific private key: `generated_certs/client_specific_[client_id]_[timestamp].key`

#### 2. Generic Certificate Generation
```bash
./mosquitto_cert_client generic
```
**Description**: Generates a generic certificate that can be used by multiple clients.

**Use Cases**:
- Shared certificates for multiple IoT devices
- Load balancer SSL certificates
- Development and testing environments

#### 3. Client-Specific Certificate Generation
```bash
./mosquitto_cert_client client-specific
```
**Description**: Generates a certificate tied to a specific client ID.

**Use Cases**:
- Individual device authentication
- Client-specific access control
- Production device deployment

### Certificate Request Parameters

#### Basic Parameters
```bash
--cn COMMON_NAME        # Certificate common name (default: test.example.com)
--org ORGANIZATION      # Organization name (default: Test Organization)
--country COUNTRY       # 2-letter country code (default: US)
--days DAYS             # Validity period in days (default: 365)
```

#### Example with Custom Parameters
```bash
./mosquitto_cert_client generic \
    --cn api.production.com \
    --org "Production API Services" \
    --country "US" \
    --days 730
```

### Advanced Usage Examples

#### 1. Production API Certificate
```bash
./mosquitto_cert_client generic \
    --cn api.company.com \
    --org "Company API Division" \
    --country "US" \
    --days 365
```

#### 2. Device-Specific Certificate
```bash
./mosquitto_cert_client client-specific \
    --cn device-001.iot.company.com \
    --org "IoT Device Network" \
    --days 1095
```

#### 3. Development Environment
```bash
./mosquitto_cert_client demo \
    --cn dev.localhost \
    --org "Development Team" \
    --days 30
```

#### 4. Custom Broker Connection
```bash
./mosquitto_cert_client -h production.mqtt.com -p 8883 generic \
    --cn prod-api.service.com \
    --org "Production Services"
```

## API Communication Protocol

### MQTT Topics
- **Request Topic**: `sys/cert/request`
- **Response Topic**: `sys/cert/response`

### Request Format (JSON)
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

### Response Format (JSON)
```json
{
    "ssl_enabled": true,
    "cert_generation_enabled": true,
    "status": "success",
    "client_id": "mqtt_cert_client_12345",
    "certificate_type": "generic",
    "certificate_data": "-----BEGIN CERTIFICATE-----\n...",
    "private_key_data": "-----BEGIN PRIVATE KEY-----\n...",
    "certificate_filename": "generic_mqtt_cert_client_12345_1753611582.crt",
    "private_key_filename": "generic_mqtt_cert_client_12345_1753611582.key",
    "message": "Certificate generated successfully"
}
```

## SSL Configuration

### CA Certificate Setup
The client requires a CA certificate file (`ca.crt`) for SSL validation:

```bash
# Copy CA certificate from broker
cp ../../ur-rpc-mastered/pkg_src/certs/ca.crt .
```

### SSL Security Features
- **TLS Encryption**: All MQTT communication encrypted
- **Certificate Validation**: CA certificate verification
- **Secure Connections**: Self-signed certificate support for development

## Certificate File Management

### File Naming Convention
- **Generic**: `generic_[client_id]_[timestamp].crt|.key`
- **Client-Specific**: `client_specific_[client_id]_[timestamp].crt|.key`

### File Permissions
- **Certificates (.crt)**: 644 (readable by owner and group)
- **Private Keys (.key)**: 600 (readable by owner only)

### Storage Structure
```
generated_certs/
├── generic_mqtt_cert_client_12345_1753611582.crt
├── generic_mqtt_cert_client_12345_1753611582.key
├── client_specific_mqtt_cert_client_12345_1753611583.crt
├── client_specific_mqtt_cert_client_12345_1753611583.key
├── api/                # Environment-specific certificates
├── dev/
├── prod/
└── staging/
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
```
❌ Failed to initiate connection: Connection refused
```
**Solution**: Verify SSL broker is running on port 1855

#### 2. SSL Handshake Failed
```
❌ Failed to set TLS options: Invalid arguments provided
```
**Solution**: Ensure ca.crt file exists and is accessible

#### 3. Certificate Generation Failed
```
❌ Failed to generate certificate
```
**Solution**: Check broker logs and certificate manager initialization

### Debug Commands

#### Test SSL Connection
```bash
./mosquitto_cert_client --help  # View all options
```

#### Verify Certificate
```bash
openssl x509 -in generated_certs/certificate.crt -text -noout
```

#### Check Private Key
```bash
openssl rsa -in generated_certs/private_key.key -check
```

## Integration with MQTT Broker

### Broker Configuration Requirements
The SSL MQTT broker must be configured with:
- SSL enabled on port 1855
- Certificate generation enabled
- CA certificate and private key accessible
- Certificate output directory configured

### Compatible Broker Configuration
```json
{
    "ssl_enabled": true,
    "ssl_port": 1855,
    "cert_generation_enabled": true,
    "certificate_generation": {
        "enabled": true,
        "ca_cert_file": "certs/ca.crt",
        "ca_key_file": "certs/ca.key",
        "output_directory": "certs/generated"
    }
}
```

## Security Considerations

### Production Deployment
1. **Secure CA Certificate Storage**: Protect CA private key
2. **Certificate Validation**: Always verify generated certificates
3. **Access Control**: Restrict certificate generation to authorized clients
4. **Network Security**: Use SSL for all certificate requests
5. **Key Management**: Secure storage of private keys

### Development vs Production
- **Development**: Self-signed certificates acceptable
- **Production**: Use proper CA-signed certificates
- **Testing**: Shorter validity periods recommended

## Library Dependencies Details

### mosquitto.h Functions Used
- `mosquitto_lib_init()` - Initialize mosquitto library
- `mosquitto_new()` - Create new client instance
- `mosquitto_tls_set()` - Configure SSL/TLS settings
- `mosquitto_connect()` - Connect to MQTT broker
- `mosquitto_subscribe()` - Subscribe to response topic
- `mosquitto_publish()` - Send certificate requests
- `mosquitto_loop_start()` - Start message processing loop

### cJSON Functions Used
- `cJSON_CreateObject()` - Create JSON request objects
- `cJSON_AddStringToObject()` - Add string fields
- `cJSON_AddNumberToObject()` - Add numeric fields
- `cJSON_Print()` - Serialize JSON to string
- `cJSON_Parse()` - Parse JSON responses
- `cJSON_GetObjectItem()` - Extract JSON fields

## Examples Output

### Successful Generic Certificate Generation
```
🚀 Starting Mosquitto SSL Certificate Client
============================================
Broker: 127.0.0.1:1855
Client ID: mqtt_cert_client_12345
SSL: enabled
============================================

🔐 Setting up SSL/TLS connection...
✓ SSL/TLS configured successfully
✓ MQTT client initialized: mqtt_cert_client_12345
🔗 Connecting to MQTT broker at 127.0.0.1:1855...
✓ Connected to MQTT broker successfully
✓ Subscribed to certificate response topic: sys/cert/response

🔐 Requesting generic Certificate
================================
📝 Request JSON:
{
    "request_type":"certificate_generation",
    "certificate_type":"generic",
    "client_id":"mqtt_cert_client_12345",
    "common_name":"test.example.com",
    "organization":"Test Organization",
    "country":"US",
    "validity_days":365,
    "timestamp":1753611582
}

✓ Certificate request sent to topic: sys/cert/request
⏳ Waiting for certificate response...
✓ Certificate request published successfully (mid: 2)
📨 Received message on topic: sys/cert/response
✓ Certificate response received (3440 bytes)
🔍 Processing certificate response...
✅ Certificate saved successfully:
   📄 Certificate: generated_certs/generic_mqtt_cert_client_12345_1753611582.crt
   🔑 Private Key: generated_certs/generic_mqtt_cert_client_12345_1753611582.key
```

This documentation provides comprehensive guidance for using the mosquitto-based certificate generation API. The system is production-ready and provides secure, reliable certificate generation through SSL-encrypted MQTT communication.