
# mbedTLS dependency management
# This file handles downloading, building, and configuring mbedTLS

# External dependency URL
set(MBEDTLS_URL "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.5.tar.gz")

# Custom target to download and build mbedTLS
add_custom_target(download_mbedtls
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${DEPS_DIR}/mbedtls"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPS_DIR}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPS_DIR}/mbedtls"
    COMMAND ${CMAKE_COMMAND} -E chdir "${DEPS_DIR}" curl -L "${MBEDTLS_URL}" -o mbedtls.tar.gz
    COMMAND ${CMAKE_COMMAND} -E chdir "${DEPS_DIR}" tar -xzf mbedtls.tar.gz -C mbedtls --strip-components=1
    COMMAND ${CMAKE_COMMAND} -E remove "${DEPS_DIR}/mbedtls.tar.gz"
    COMMENT "Cleaning and downloading mbedTLS..."
)

add_custom_target(build_mbedtls
    DEPENDS download_mbedtls
    COMMAND ${CMAKE_COMMAND} -E chdir "${DEPS_DIR}/mbedtls" ${CMAKE_COMMAND} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DCMAKE_C_FLAGS=-fPIC .
    COMMAND ${CMAKE_COMMAND} --build "${DEPS_DIR}/mbedtls"
    BYPRODUCTS 
        ${DEPS_DIR}/mbedtls/library/libmbedtls.a
        ${DEPS_DIR}/mbedtls/library/libmbedx509.a
        ${DEPS_DIR}/mbedtls/library/libmbedcrypto.a
    COMMENT "Building mbedTLS..."
)

# Set mbedTLS library paths
set(MBEDTLS_LIBS 
    ${DEPS_DIR}/mbedtls/library/libmbedtls.a
    ${DEPS_DIR}/mbedtls/library/libmbedx509.a
    ${DEPS_DIR}/mbedtls/library/libmbedcrypto.a
)

# Add mbedTLS include directory
include_directories(${DEPS_DIR}/mbedtls/include)

