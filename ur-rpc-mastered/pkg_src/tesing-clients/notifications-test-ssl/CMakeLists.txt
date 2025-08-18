cmake_minimum_required(VERSION 3.10)
project(mosquitto_notification_client C)

# Set compiler flags
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")

# Find Mosquitto library using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

# Add executable
add_executable(mosquitto_notification_client
    main.c
    notification_client.c
)

# Include directories
target_include_directories(mosquitto_notification_client PRIVATE
    ${MOSQUITTO_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(mosquitto_notification_client
    ${MOSQUITTO_LIBRARIES}
    pthread
)

# Install instructions for missing dependencies
if(NOT MOSQUITTO_FOUND)
    message(FATAL_ERROR "\n❌ Mosquitto development library not found. Install with:\n"
        "  Ubuntu/Debian: sudo apt-get install libmosquitto-dev\n"
        "  CentOS/RHEL:   sudo yum install mosquitto-devel\n"
        "  Or using pkg-config if available")
else()
    message(STATUS "✅ Mosquitto library found")
    message(STATUS "Include paths: ${MOSQUITTO_INCLUDE_DIRS}")
    message(STATUS "Libraries: ${MOSQUITTO_LIBRARIES}")
endif()

