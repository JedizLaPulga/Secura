# ============================================================================
# Secura - Lightweight Encryption Tool
# ============================================================================
cmake_minimum_required(VERSION 3.25)

project(Secura
    VERSION 0.1.0
    DESCRIPTION "A lightweight encryption tool built with modern C++23"
    LANGUAGES CXX
)

# ============================================================================
# C++23 Standard Configuration
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# Compiler Warnings (Strict for quality code)
# ============================================================================
if(MSVC)
    add_compile_options(
        /W4           # High warning level
        /WX           # Treat warnings as errors
        /permissive-  # Strict conformance mode
        /Zc:__cplusplus  # Correct __cplusplus macro
        /utf-8        # UTF-8 source and execution charset
    )
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic  # Enable most warnings
        -Werror                    # Treat warnings as errors
    )
endif()

# ============================================================================
# Find Dependencies (via vcpkg)
# ============================================================================
find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

# ============================================================================
# Project Structure
# ============================================================================
# Source directories
set(SECURA_SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(SECURA_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SECURA_TEST_DIR ${CMAKE_SOURCE_DIR}/tests)

# ============================================================================
# Main Library (Core encryption functionality)
# ============================================================================
add_library(secura_core STATIC
    # Add source files here as you create them:
    # ${SECURA_SRC_DIR}/encryptor.cpp
    # ${SECURA_SRC_DIR}/decryptor.cpp
    # ${SECURA_SRC_DIR}/key_manager.cpp
    ${SECURA_SRC_DIR}/placeholder.cpp  # Temporary placeholder
)

target_include_directories(secura_core
    PUBLIC
        ${SECURA_INCLUDE_DIR}
    PRIVATE
        ${SECURA_SRC_DIR}
)

target_link_libraries(secura_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt
)

# ============================================================================
# Main Executable (CLI or GUI entry point)
# ============================================================================
add_executable(secura
    ${SECURA_SRC_DIR}/main.cpp
)

target_link_libraries(secura
    PRIVATE
        secura_core
)

# ============================================================================
# Tests
# ============================================================================
enable_testing()

add_executable(secura_tests
    # Add test files here as you create them:
    # ${SECURA_TEST_DIR}/test_encryptor.cpp
    # ${SECURA_TEST_DIR}/test_decryptor.cpp
    ${SECURA_TEST_DIR}/test_placeholder.cpp  # Temporary placeholder
)

target_link_libraries(secura_tests
    PRIVATE
        secura_core
        GTest::gtest
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(secura_tests)

# ============================================================================
# Installation (optional, for distribution)
# ============================================================================
install(TARGETS secura
    RUNTIME DESTINATION bin
)

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "=== Secura Configuration ===")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL:      ${OPENSSL_VERSION}")
message(STATUS "============================")
message(STATUS "")
