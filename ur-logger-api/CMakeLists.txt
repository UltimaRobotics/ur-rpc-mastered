
cmake_minimum_required(VERSION 3.10)

# Project configuration
project(ur-logger-api 
    VERSION 1.0.0
    DESCRIPTION "Universal Router Logger API Library"
    LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# Find required packages
find_package(Threads REQUIRED)

# Source files
set(LOGGER_SOURCES logger.c )

# Header files
set(LOGGER_HEADERS logger.h
)

# Create object library for shared code
add_library(logger_objects OBJECT ${LOGGER_SOURCES})
target_include_directories(logger_objects PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/attached_assets>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(logger_objects PUBLIC Threads::Threads)

# Static library
add_library(ur-logger-api-static STATIC $<TARGET_OBJECTS:logger_objects>)
set_target_properties(ur-logger-api-static PROPERTIES
    OUTPUT_NAME ur-logger-api
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_include_directories(ur-logger-api-static PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/attached_assets>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(ur-logger-api-static PUBLIC Threads::Threads)

# Shared library
add_library(ur-logger-api-shared SHARED $<TARGET_OBJECTS:logger_objects>)
set_target_properties(ur-logger-api-shared PROPERTIES
    OUTPUT_NAME ur-logger-api
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_include_directories(ur-logger-api-shared PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/attached_assets>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(ur-logger-api-shared PUBLIC Threads::Threads)

# Create aliases for consistent naming
add_library(ur-logger-api::static ALIAS ur-logger-api-static)
add_library(ur-logger-api::shared ALIAS ur-logger-api-shared)

# Installation configuration
include(GNUInstallDirs)

# Install libraries
install(TARGETS ur-logger-api-static ur-logger-api-shared
    EXPORT ur-logger-api-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(FILES ${LOGGER_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ur-logger-api
    RENAME logger.h
)

# Export targets
install(EXPORT ur-logger-api-targets
    FILE ur-logger-api-targets.cmake
    NAMESPACE ur-logger-api::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ur-logger-api
)

# Create package config file
include(CMakePackageConfigHelpers)

# Generate config file
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/ur-logger-api-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ur-logger-api-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ur-logger-api
)

# Generate version file
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ur-logger-api-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install config files
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ur-logger-api-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ur-logger-api-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ur-logger-api
)

# Package configuration
set(CPACK_PACKAGE_NAME "ur-logger-api")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Universal Router Logger API Library")
set(CPACK_PACKAGE_VENDOR "Universal Router Project")

include(CPack)

# Print build information
message(STATUS "ur-logger-api ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

