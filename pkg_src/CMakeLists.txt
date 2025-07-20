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
)

# External dependency URLs
set(CJSON_URL "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.16.tar.gz")
set(MBEDTLS_URL "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.5.tar.gz")

# Custom target to download and build cJSON
add_custom_target(download_cjson
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPS_DIR}/cjson
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DEPS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DEPS_DIR}/cjson
    COMMAND curl -L ${CJSON_URL} -o ${DEPS_DIR}/cjson.tar.gz || wget -O ${DEPS_DIR}/cjson.tar.gz ${CJSON_URL}
    COMMAND tar -xzf ${DEPS_DIR}/cjson.tar.gz -C ${DEPS_DIR}/cjson --strip-components=1
    COMMAND ${CMAKE_COMMAND} -E remove ${DEPS_DIR}/cjson.tar.gz
    COMMENT "Cleaning and downloading cJSON..."
)

add_custom_target(build_cjson
    DEPENDS download_cjson
    COMMAND cd ${DEPS_DIR}/cjson && cmake -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER) -DCMAKE_CXX_COMPILER=$(CMAKE_CXX_COMPILER) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF -DENABLE_CJSON_UTILS=OFF -DCMAKE_C_FLAGS=-fPIC .
    COMMAND ${CMAKE_COMMAND} --build ${DEPS_DIR}/cjson
    BYPRODUCTS ${DEPS_DIR}/cjson/libcjson.a
    COMMENT "Building cJSON..."
)

# Custom target to download and build mbedTLS
add_custom_target(download_mbedtls
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPS_DIR}/mbedtls
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DEPS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DEPS_DIR}/mbedtls
    COMMAND curl -L ${MBEDTLS_URL} -o ${DEPS_DIR}/mbedtls.tar.gz || wget -O ${DEPS_DIR}/mbedtls.tar.gz ${MBEDTLS_URL}
    COMMAND tar -xzf ${DEPS_DIR}/mbedtls.tar.gz -C ${DEPS_DIR}/mbedtls --strip-components=1
    COMMAND ${CMAKE_COMMAND} -E remove ${DEPS_DIR}/mbedtls.tar.gz
    COMMENT "Cleaning and downloading mbedTLS..."
)

add_custom_target(build_mbedtls
    DEPENDS download_mbedtls
    COMMAND cd ${DEPS_DIR}/mbedtls && cmake -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER) -DCMAKE_CXX_COMPILER=$(CMAKE_CXX_COMPILER) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DCMAKE_C_FLAGS=-fPIC .
    COMMAND ${CMAKE_COMMAND} --build ${DEPS_DIR}/mbedtls
    BYPRODUCTS 
        ${DEPS_DIR}/mbedtls/library/libmbedtls.a
        ${DEPS_DIR}/mbedtls/library/libmbedx509.a
        ${DEPS_DIR}/mbedtls/library/libmbedcrypto.a
    COMMENT "Building mbedTLS..."
)

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
