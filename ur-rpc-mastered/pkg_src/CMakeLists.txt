cmake_minimum_required(VERSION 3.10)
project(mqtt_broker_isolated C)

# if(DEFINED ENV{STAGING_DIR})
#     # OpenWRT toolchain detection
#     set(CMAKE_SYSTEM_NAME Linux)
#     set(CMAKE_SYSTEM_PROCESSOR $ENV{ARCH})
#     set(TOOLCHAIN_PREFIX $ENV{TARGET_CROSS})
    
#     set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
#     set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)
#     set(CMAKE_FIND_ROOT_PATH $ENV{STAGING_DIR})
    
#     # OpenWRT-specific flags
#     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENWRT")
#     set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath-link,$ENV{STAGING_DIR}/usr/lib")
# endif()

if(DEFINED CMAKE_C_COMPILER)
    message(STATUS "Using custom C compiler: ${CMAKE_C_COMPILER}")
endif()

if(DEFINED CMAKE_CXX_COMPILER)
    message(STATUS "Using custom C++ compiler: ${CMAKE_CXX_COMPILER}")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE ON)

# Force static linking
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# Compiler flags for optimized static build
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -DNDEBUG -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

# Static linking flags (avoid full static linking which causes issues with pthread/math libs)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -Wl,--gc-sections")

# Dependencies directory
set(DEPS_DIR ${CMAKE_SOURCE_DIR}/deps)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${DEPS_DIR}/cjson)
include_directories(${DEPS_DIR}/mbedtls/include)
include_directories(${CMAKE_SOURCE_DIR}/../../ur-logger-api)

# Source files for MQTT broker
set(BROKER_SOURCES
    src/main.c
    src/mqtt_broker.c
    src/mqtt_protocol.c
    src/client_manager.c
    src/message_handler.c
    src/network.c
    src/config.c
    src/ssl_wrapper.c
    src/utils.c
    src/notification_manager.c
    src/cert_manager.c
    ${CMAKE_SOURCE_DIR}/../../ur-logger-api/logger.c
)
# Include external dependencies
include(${CMAKE_SOURCE_DIR}/cmake/cjson.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/mbed-tls.cmake)

# Create MQTT broker executable with SSL support
add_executable(mqtt_broker ${BROKER_SOURCES})
add_dependencies(mqtt_broker build_cjson build_mbedtls)

# Library paths
set(CJSON_LIB ${DEPS_DIR}/cjson/libcjson.a)
set(MBEDTLS_LIBS 
    ${DEPS_DIR}/mbedtls/library/libmbedtls.a
    ${DEPS_DIR}/mbedtls/library/libmbedx509.a
    ${DEPS_DIR}/mbedtls/library/libmbedcrypto.a
)

# Link libraries (static linking)
target_link_libraries(mqtt_broker 
    ${CJSON_LIB} 
    ${MBEDTLS_LIBS} 
    pthread 
    m
)

# Set static build properties
set_target_properties(mqtt_broker PROPERTIES
    LINK_FLAGS "-static-libgcc -Wl,--gc-sections"
    COMPILE_DEFINITIONS "STATIC_BUILD=1"
)

# Clean targets
add_custom_target(clean-deps
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPS_DIR}
    COMMENT "Cleaning all downloaded dependencies"
)

add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPS_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/build
    COMMENT "Cleaning all build files and dependencies"
)

# Installation
install(TARGETS mqtt_broker
    RUNTIME DESTINATION bin
)

# Print build information
message(STATUS "=== Isolated MQTT Broker Static Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C flags: ${CMAKE_C_FLAGS}")
message(STATUS "Linker flags: ${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "Static linking: Fully static executable")
message(STATUS "SSL/TLS Support: Enabled via mbedTLS")
message(STATUS "Configuration: JSON support via cJSON")
message(STATUS "Target: mqtt_broker (SSL-enabled)")
message(STATUS "=========================================================")
