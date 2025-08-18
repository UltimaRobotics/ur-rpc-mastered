# Getting Started - MQTT Certificate Generation

Quick start guide for the mosquitto-based certificate generation client.

## Prerequisites Check

Before starting, ensure you have:
- ✅ SSL MQTT broker running on port 1855
- ✅ CA certificate file available
- ✅ Development libraries installed (mosquitto, cJSON, OpenSSL)

## 5-Minute Quick Start

### Step 1: Navigate to Directory
```bash
cd tesing-clients/certif-generation
```

### Step 2: Verify Files
```bash
ls -la
# Should show:
# - mosquitto_cert_client.c (source code)
# - mosquitto_cert_client (executable)
# - main (executable copy)
# - Makefile (build configuration)
# - ca.crt (CA certificate)
# - README.md, API_REFERENCE.md, USAGE_EXAMPLES.md (documentation)
```

### Step 3: Build Client (if needed)
```bash
make clean && make
```

### Step 4: Generate Demo Certificates
```bash
./mosquitto_cert_client demo
```

Expected output:
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

🎯 Running Certificate Generation Demo
=====================================

🔐 Requesting generic Certificate
================================
✓ Certificate request sent to topic: sys/cert/request
✓ Certificate request published successfully
📨 Received message on topic: sys/cert/response
✓ Certificate response received (3440 bytes)
✅ Certificate saved successfully:
   📄 Certificate: generated_certs/generic_mqtt_cert_client_12345_timestamp.crt
   🔑 Private Key: generated_certs/generic_mqtt_cert_client_12345_timestamp.key

🔐 Requesting client_specific Certificate
================================
✓ Certificate request sent to topic: sys/cert/request
✓ Certificate request published successfully
📨 Received message on topic: sys/cert/response
✓ Certificate response received (3456 bytes)
✅ Certificate saved successfully:
   📄 Certificate: generated_certs/client_specific_mqtt_cert_client_12345_timestamp.crt
   🔑 Private Key: generated_certs/client_specific_mqtt_cert_client_12345_timestamp.key

🏁 Certificate client operation completed
```

### Step 5: Verify Generated Certificates
```bash
ls -la generated_certs/
# Should show newly generated .crt and .key files

# Verify certificate content
openssl x509 -in generated_certs/generic_*.crt -text -noout | head -15
```

## Common Commands

### Generate Generic Certificate
```bash
./mosquitto_cert_client generic --cn api.example.com --org "My Organization"
```

### Generate Client-Specific Certificate
```bash
./mosquitto_cert_client client-specific --cn device001.local --org "IoT Devices"
```

### View Help
```bash
./mosquitto_cert_client --help
```

## Troubleshooting

### Problem: Connection Refused
```
❌ Failed to initiate connection: Connection refused
```
**Solution**: Ensure SSL broker is running on port 1855

### Problem: SSL Handshake Failed
```
❌ Failed to set TLS options: Invalid arguments provided
```
**Solution**: Check that ca.crt file exists and is readable

### Problem: Certificate Generation Failed
```
❌ Failed to generate certificate
```
**Solution**: Check broker logs for certificate manager status

## Next Steps

1. **Read Full Documentation**: See README.md for comprehensive usage guide
2. **API Integration**: Review API_REFERENCE.md for technical implementation details
3. **Advanced Examples**: Check USAGE_EXAMPLES.md for real-world scenarios
4. **Production Deployment**: Follow security best practices in documentation

## Documentation Overview

- **README.md**: Complete user guide and feature documentation
- **API_REFERENCE.md**: Technical API documentation for developers
- **USAGE_EXAMPLES.md**: Practical examples for common scenarios
- **GETTING_STARTED.md**: This quick start guide

## Support

For issues or questions:
1. Check troubleshooting sections in documentation
2. Verify broker and client configurations
3. Review generated certificates for validity
4. Check network connectivity to broker

The certificate generation system is production-ready and provides secure, reliable SSL certificate generation through encrypted MQTT communication.