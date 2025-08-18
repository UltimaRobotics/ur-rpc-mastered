
# Makefile for Mosquitto SSL Demo Client

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LIBS = -lmosquitto -lssl -lcrypto -lpthread
TARGET = main
SOURCE = main.c

# Build target
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

# Clean target
clean:
	rm -f $(TARGET)

# Install dependencies (if needed)
deps:
	@echo "Installing mosquitto development libraries..."
	@echo "On Ubuntu/Debian: sudo apt-get install libmosquitto-dev libssl-dev"
	@echo "On CentOS/RHEL: sudo yum install mosquitto-devel openssl-devel"

# Test with example certificates
test: $(TARGET)
	@echo "Testing with example certificates..."
	@if [ -f "certs/ca.crt" ] && [ -f "certs/client1.crt" ] && [ -f "certs/client1.key" ]; then \
		./$(TARGET) --ca certs/ca.crt --cert certs/client1.crt --key certs/client1.key; \
	elif [ -f "ca.crt" ] && [ -f "client1.crt" ] && [ -f "client1.key" ]; then \
		./$(TARGET) --ca ca.crt --cert client1.crt --key client1.key; \
	else \
		echo "❌ No test certificates found. Please provide certificates manually."; \
		echo "Usage: ./$(TARGET) --ca <ca_file> --cert <cert_file> --key <key_file>"; \
	fi

# Help target
help:
	@echo "Available targets:"
	@echo "  $(TARGET)  - Build the SSL demo client"
	@echo "  clean     - Remove built files"
	@echo "  deps      - Show dependency installation commands"
	@echo "  test      - Test with example certificates"
	@echo "  help      - Show this help"

.PHONY: clean deps test help

