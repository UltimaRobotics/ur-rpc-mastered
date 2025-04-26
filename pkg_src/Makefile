# Default build directory
BUILD_DIR = build
CC ?= gcc
CXX ?= g++

# Default target
all: $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake CMAKE_C_COMPILER=$(CC) .. && make

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Install target
install: all
	cd $(BUILD_DIR) && make install

# Phony targets
.PHONY: all clean install
