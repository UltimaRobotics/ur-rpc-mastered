# Makefile for Enhanced Mosquitto MQTT Certificate Client with Certificate Manager
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
CFLAGS += $(shell pkg-config --cflags libmosquitto libcjson openssl)
LIBS = $(shell pkg-config --libs libmosquitto libcjson openssl) -lpthread

# Source files
SOURCES = mosquitto_cert_client.c cert_manager.c ssl_tls_main.c test_ssl_connection.c
OBJECTS = mosquitto_cert_client.o cert_manager.o ssl_tls_main.o test_ssl_connection.o
TARGET = mosquitto_cert_client
SSL_TLS_TARGET = ssl_tls_main
SSL_TEST_TARGET = test_ssl_connection
LEGACY_TARGET = main

# Default target
all: $(TARGET) $(SSL_TLS_TARGET) $(SSL_TEST_TARGET)

# Build mosquitto-based client
$(TARGET): mosquitto_cert_client.o cert_manager.o
	$(CC) $(CFLAGS) -o $(TARGET) mosquitto_cert_client.o cert_manager.o $(LIBS)

# Build SSL/TLS main client 
$(SSL_TLS_TARGET): ssl_tls_main.o cert_manager.o
	$(CC) $(CFLAGS) -o $(SSL_TLS_TARGET) ssl_tls_main.o cert_manager.o $(LIBS)

# Build SSL test client
$(SSL_TEST_TARGET): test_ssl_connection.o
	$(CC) $(CFLAGS) -o $(SSL_TEST_TARGET) test_ssl_connection.o $(LIBS)

# Build object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Legacy compatibility
$(LEGACY_TARGET): $(TARGET)
	cp $(TARGET) $(LEGACY_TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(SSL_TLS_TARGET) $(SSL_TEST_TARGET) $(LEGACY_TARGET) $(OBJECTS)

# Test certificate generation
test: $(TARGET)
	@echo "=== Testing Enhanced Mosquitto Certificate Client ==="
	./$(TARGET) --help
	@echo "=== Running certificate check ==="
	./$(TARGET) check-certs
	@echo "=== Running demo test ==="
	./$(TARGET) demo

# Development build with debug symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Check for existing certificates
check-existing: $(TARGET)
	./$(TARGET) check-certs

# Generate and connect with SSL
ssl-test: $(TARGET)
	./$(TARGET) generate-and-connect

# Run SSL/TLS main client
ssl-tls-test: $(SSL_TLS_TARGET)
	@echo "=== Running SSL/TLS Certificate Generation Client ==="
	./$(SSL_TLS_TARGET) --help
	@echo "=== Running SSL/TLS client ==="
	./$(SSL_TLS_TARGET) -v

# Test simple SSL connection
test-ssl: $(SSL_TEST_TARGET)
	@echo "=== Testing SSL Connection ==="
	./$(SSL_TEST_TARGET)

.PHONY: all clean test debug check-existing ssl-test ssl-tls-test test-ssl
