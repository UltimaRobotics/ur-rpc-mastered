# MQTT Certificate Generation - Usage Examples

Practical examples for using the mosquitto-based certificate generation API in real-world scenarios.

## Quick Start

### 1. Basic Setup
```bash
# Navigate to certificate generation directory
cd tesing-clients/certif-generation

# Ensure CA certificate is available
ls -la ca.crt

# Build the client
make clean && make
```

### 2. Test Connection
```bash
# Verify SSL broker is running on port 1855
./mosquitto_cert_client --help
```

### 3. Generate Demo Certificates
```bash
# Generate both generic and client-specific certificates
./mosquitto_cert_client demo
```

## Common Use Cases

### Development Environment Setup

#### Generate Development Certificates
```bash
# Short-lived certificates for development
./mosquitto_cert_client demo \
    --cn dev.localhost \
    --org "Development Team" \
    --days 30
```

#### API Testing Certificates
```bash
# Generic certificate for API testing
./mosquitto_cert_client generic \
    --cn api.dev.example.com \
    --org "API Development" \
    --days 90
```

### Production Deployment

#### Load Balancer Certificate
```bash
# Generic certificate for load balancer
./mosquitto_cert_client generic \
    --cn api.production.com \
    --org "Production Services" \
    --country "US" \
    --days 365
```

#### Microservice Certificates
```bash
# Service-specific certificates
./mosquitto_cert_client client-specific \
    --cn auth-service.internal \
    --org "Authentication Service" \
    --days 730

./mosquitto_cert_client client-specific \
    --cn payment-service.internal \
    --org "Payment Service" \
    --days 730
```

### IoT Device Deployment

#### Device Fleet Certificates
```bash
# Generic certificate for device fleet
./mosquitto_cert_client generic \
    --cn iot.devices.company.com \
    --org "IoT Device Network" \
    --days 1095

# Individual device certificates
for device_id in device-001 device-002 device-003; do
    ./mosquitto_cert_client client-specific \
        --cn ${device_id}.iot.company.com \
        --org "IoT Device ${device_id}" \
        --days 365
done
```

#### Sensor Network Setup
```bash
# Sensor gateway certificate
./mosquitto_cert_client generic \
    --cn sensor-gateway.monitoring.com \
    --org "Sensor Network Gateway" \
    --days 365

# Individual sensor certificates
./mosquitto_cert_client client-specific \
    --cn temperature-sensor-01.monitoring.com \
    --org "Temperature Monitoring" \
    --days 365
```

## Advanced Scenarios

### Multi-Environment Deployment

#### Staging Environment
```bash
# Staging API certificate
./mosquitto_cert_client generic \
    --cn api.staging.company.com \
    --org "Staging Environment" \
    --days 180
```

#### Production Environment
```bash
# Production API certificate
./mosquitto_cert_client generic \
    --cn api.company.com \
    --org "Production API" \
    --days 365
```

### Custom Broker Configuration

#### Connect to Remote Broker
```bash
# Connect to production MQTT broker
./mosquitto_cert_client -h production.mqtt.company.com -p 8883 generic \
    --cn remote-api.company.com \
    --org "Remote API Service"
```

#### Custom CA Certificate
```bash
# Use custom CA certificate
./mosquitto_cert_client --ca-cert /path/to/custom-ca.crt generic \
    --cn custom-api.example.com \
    --org "Custom API"
```

## Batch Operations

### Certificate Renewal Script
```bash
#!/bin/bash
# certificate_renewal.sh

SERVICES=("api-gateway" "auth-service" "payment-service" "user-service")
ORG="Production Services"
DAYS=365

for service in "${SERVICES[@]}"; do
    echo "Generating certificate for $service..."
    ./mosquitto_cert_client client-specific \
        --cn ${service}.internal.company.com \
        --org "$ORG - $service" \
        --days $DAYS
    
    if [ $? -eq 0 ]; then
        echo "✓ Certificate generated for $service"
    else
        echo "✗ Failed to generate certificate for $service"
    fi
    sleep 1
done
```

### Development Team Setup
```bash
#!/bin/bash
# dev_team_setup.sh

DEVELOPERS=("alice" "bob" "charlie" "diana")
ORG="Development Team"

for dev in "${DEVELOPERS[@]}"; do
    echo "Setting up development certificate for $dev..."
    ./mosquitto_cert_client client-specific \
        --cn ${dev}.dev.company.com \
        --org "$ORG - $dev" \
        --days 90
done
```

## Certificate Verification

### Verify Generated Certificates
```bash
# Check certificate validity
openssl x509 -in generated_certs/generic_*.crt -text -noout | head -20

# Verify certificate and key match
cert_file=$(ls generated_certs/generic_*.crt | head -1)
key_file=$(ls generated_certs/generic_*.key | head -1)

cert_modulus=$(openssl x509 -noout -modulus -in "$cert_file" | openssl md5)
key_modulus=$(openssl rsa -noout -modulus -in "$key_file" | openssl md5)

if [ "$cert_modulus" = "$key_modulus" ]; then
    echo "✓ Certificate and key match"
else
    echo "✗ Certificate and key do not match"
fi
```

### Certificate Information Extraction
```bash
# Extract certificate details
extract_cert_info() {
    local cert_file=$1
    echo "Certificate: $cert_file"
    echo "Subject: $(openssl x509 -noout -subject -in "$cert_file")"
    echo "Issuer: $(openssl x509 -noout -issuer -in "$cert_file")"
    echo "Valid from: $(openssl x509 -noout -startdate -in "$cert_file")"
    echo "Valid until: $(openssl x509 -noout -enddate -in "$cert_file")"
    echo "---"
}

# Process all certificates
for cert in generated_certs/*.crt; do
    extract_cert_info "$cert"
done
```

## Integration Examples

### Docker Container Setup
```dockerfile
# Dockerfile for certificate-enabled service
FROM alpine:latest

# Install dependencies
RUN apk add --no-cache openssl mosquitto-clients

# Copy certificate generation client
COPY mosquitto_cert_client /usr/local/bin/
COPY ca.crt /etc/ssl/certs/

# Generate service certificate
RUN mosquitto_cert_client client-specific \
    --cn service.container.local \
    --org "Containerized Service" \
    --days 365

# Start service with certificates
CMD ["service", "--cert=/app/generated_certs/client_specific_*.crt", \
     "--key=/app/generated_certs/client_specific_*.key"]
```

### Kubernetes Deployment
```yaml
# k8s-cert-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: certificate-generation
spec:
  template:
    spec:
      containers:
      - name: cert-generator
        image: cert-generator:latest
        command:
        - /bin/sh
        - -c
        - |
          ./mosquitto_cert_client client-specific \
            --cn ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local \
            --org "Kubernetes Service" \
            --days 365
          
          # Copy certificates to persistent volume
          cp generated_certs/*.crt /certs/
          cp generated_certs/*.key /certs/
        env:
        - name: SERVICE_NAME
          value: "api-service"
        - name: NAMESPACE
          value: "production"
        volumeMounts:
        - name: cert-storage
          mountPath: /certs
      volumes:
      - name: cert-storage
        persistentVolumeClaim:
          claimName: certificate-storage
      restartPolicy: OnFailure
```

### Terraform Integration
```hcl
# terraform/certificates.tf
resource "null_resource" "generate_certificates" {
  count = length(var.services)
  
  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/../tesing-clients/certif-generation
      ./mosquitto_cert_client client-specific \
        --cn ${var.services[count.index]}.${var.domain} \
        --org "${var.organization}" \
        --days ${var.cert_validity_days}
    EOT
  }
  
  triggers = {
    service_name = var.services[count.index]
    domain = var.domain
  }
}

variable "services" {
  description = "List of services requiring certificates"
  type = list(string)
  default = ["api", "auth", "payment", "user"]
}

variable "domain" {
  description = "Base domain for certificates"
  type = string
  default = "company.com"
}
```

## Monitoring and Maintenance

### Certificate Expiry Monitoring
```bash
#!/bin/bash
# cert_expiry_check.sh

CERT_DIR="generated_certs"
WARNING_DAYS=30

check_expiry() {
    local cert_file=$1
    local expiry_date=$(openssl x509 -noout -enddate -in "$cert_file" | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    if [ $days_until_expiry -lt $WARNING_DAYS ]; then
        echo "⚠️  Certificate $cert_file expires in $days_until_expiry days"
        return 1
    else
        echo "✓ Certificate $cert_file expires in $days_until_expiry days"
        return 0
    fi
}

# Check all certificates
for cert in $CERT_DIR/*.crt; do
    if [ -f "$cert" ]; then
        check_expiry "$cert"
    fi
done
```

### Automated Renewal
```bash
#!/bin/bash
# auto_renewal.sh

CERT_DIR="generated_certs"
RENEWAL_DAYS=30

renew_certificate() {
    local cert_file=$1
    local cert_name=$(basename "$cert_file" .crt)
    
    # Extract original parameters from certificate
    local common_name=$(openssl x509 -noout -subject -in "$cert_file" | \
                       sed -n 's/.*CN=\([^,]*\).*/\1/p')
    local org=$(openssl x509 -noout -subject -in "$cert_file" | \
                sed -n 's/.*O=\([^,]*\).*/\1/p')
    
    # Determine certificate type from filename
    local cert_type="generic"
    if [[ "$cert_name" == client_specific_* ]]; then
        cert_type="client-specific"
    fi
    
    echo "Renewing certificate: $common_name ($cert_type)"
    ./mosquitto_cert_client "$cert_type" \
        --cn "$common_name" \
        --org "$org" \
        --days 365
}

# Check and renew certificates
for cert in $CERT_DIR/*.crt; do
    if [ -f "$cert" ]; then
        expiry_date=$(openssl x509 -noout -enddate -in "$cert" | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry_date" +%s)
        current_epoch=$(date +%s)
        days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [ $days_until_expiry -lt $RENEWAL_DAYS ]; then
            renew_certificate "$cert"
        fi
    fi
done
```

This usage guide provides comprehensive examples for implementing the certificate generation API in various real-world scenarios, from development to production deployment.