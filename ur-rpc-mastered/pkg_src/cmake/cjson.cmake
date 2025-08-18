
# cJSON dependency management
# This file handles downloading, building, and configuring cJSON

# External dependency URL
set(CJSON_URL "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.16.tar.gz")

# Custom target to download and build cJSON
add_custom_target(download_cjson
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${DEPS_DIR}/cjson"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPS_DIR}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPS_DIR}/cjson"
    COMMAND ${CMAKE_COMMAND} -E chdir "${DEPS_DIR}" curl -L "${CJSON_URL}" -o cjson.tar.gz
    COMMAND ${CMAKE_COMMAND} -E chdir "${DEPS_DIR}" tar -xzf cjson.tar.gz -C cjson --strip-components=1
    COMMAND ${CMAKE_COMMAND} -E remove "${DEPS_DIR}/cjson.tar.gz"
    COMMENT "Cleaning and downloading cJSON..."
)

add_custom_target(build_cjson
    DEPENDS download_cjson
    COMMAND ${CMAKE_COMMAND} -E chdir "${DEPS_DIR}/cjson" ${CMAKE_COMMAND} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF -DENABLE_CJSON_UTILS=OFF -DCMAKE_C_FLAGS=-fPIC .
    COMMAND ${CMAKE_COMMAND} --build "${DEPS_DIR}/cjson"
    BYPRODUCTS ${DEPS_DIR}/cjson/libcjson.a
    COMMENT "Building cJSON..."
)

# Set cJSON library path
set(CJSON_LIB ${DEPS_DIR}/cjson/libcjson.a)

# Add cJSON include directory
include_directories(${DEPS_DIR}/cjson)

