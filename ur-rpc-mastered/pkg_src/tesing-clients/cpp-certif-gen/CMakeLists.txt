cmake_minimum_required(VERSION 3.10)
project(CertificateManager)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find mosquitto library
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MOSQUITTO_INCLUDE_DIRS}
)

# Source files
set(SOURCES
    CertificateClient.cpp
    CertificateManager.cpp
    cert_manager.c
    cJSON.c
)

# Headers (not strictly needed for building, but good for IDE integration)
set(HEADERS
    CertificateClient.hpp
    CertificateManager.hpp
    cert_manager.h
    cJSON.h
)

# Build the library
add_library(CertificateManagerLib STATIC ${SOURCES} ${HEADERS})
target_link_libraries(CertificateManagerLib PRIVATE ${MOSQUITTO_LIBRARIES})
target_include_directories(CertificateManagerLib PRIVATE ${MOSQUITTO_INCLUDE_DIRS})

# Build the CLI executable
add_executable(certificate_cli certificate_cli_cpp.cpp)
target_link_libraries(certificate_cli PRIVATE CertificateManagerLib)

# Installation (optional)
install(TARGETS CertificateManagerLib certificate_cli
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(FILES ${HEADERS} DESTINATION include)
