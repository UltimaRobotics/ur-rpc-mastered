# x86-toolchain.cmake - Toolchain file for 32-bit x86 (i686) targets
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR i686)

# Cross-compiler prefix (adjust if using different toolchain)
set(TOOLCHAIN_PREFIX )

# Compilers
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)
set(CMAKE_ASM_COMPILER ${TOOLCHAIN_PREFIX}gcc)

# Binutils
set(CMAKE_AR ${TOOLCHAIN_PREFIX}ar)
set(CMAKE_RANLIB ${TOOLCHAIN_PREFIX}ranlib)
set(CMAKE_STRIP ${TOOLCHAIN_PREFIX}strip)
set(CMAKE_NM ${TOOLCHAIN_PREFIX}nm)

# Compiler flags for 32-bit x86
set(ARCH_FLAGS "-m32 -march=i686 -mtune=generic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARCH_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ARCH_FLAGS}")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${ARCH_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${ARCH_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${ARCH_FLAGS}")

# Sysroot (if needed)
# set(CMAKE_SYSROOT /path/to/x86-sysroot)

# Search behavior
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Additional settings for static linking (matches your CMakeLists.txt)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

message(STATUS "Configuring for x86 (32-bit) target")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER}")
