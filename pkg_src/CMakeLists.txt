cmake_minimum_required(VERSION 3.10)
project(mqtt_broker C)


set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -pedantic -Wno-sign-compare -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable)


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()


set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -DDEBUG")


set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")


find_package(Threads REQUIRED)


set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)



set(BROKER_LIB_SOURCES
    src/mqtt_broker.c
    src/topic_tree.c
    src/session.c
    src/persistence.c
    src/config.c
    src/logger.c
    src/net.c
    src/utils.c
    src/auth.c
    src/json/cJSON.c 
    # src/mqtt_broker_disconnect.c - Will be reintegrated later
    src/session_heartbeat.c
    src/disconnect_handler.c
)

# Header files
set(BROKER_HEADERS
    src/mqtt_broker.h
    src/topic_tree.h
    src/session.h
    src/persistence.h
    src/config.h
    src/logger.h
    src/net.h
    src/utils.h
    src/auth.h
    src/json/cJSON.h
    src/disconnect_handler.h
)

# Create a static library from the broker sources
add_library(mqtt_broker_lib STATIC ${BROKER_LIB_SOURCES} ${BROKER_HEADERS})
target_include_directories(mqtt_broker_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mqtt_broker_lib PUBLIC Threads::Threads m)

# Add the broker executable
add_executable(mqtt_broker src/main.c)
target_link_libraries(mqtt_broker PRIVATE mqtt_broker_lib)

