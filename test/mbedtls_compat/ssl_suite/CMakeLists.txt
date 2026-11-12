# The selected ssl suite against Mbed TLS itself: the patched clone's
# libraries and test helpers, with ssl_helpers_port.c. Built by
# make MBEDTLS_COMPAT=1 mbedtls-compat-suite-ref.
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# MBEDTLS_DIR: the clone. SUITE_C: the generated test_suite_ssl_public.c.

cmake_minimum_required(VERSION 3.10.2)
project(ssl_suite_ref C)

set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(ENABLE_TESTING ON CACHE BOOL "")
add_subdirectory(${MBEDTLS_DIR} mbedtls)

# The patched ssl_helpers.c includes ssl_helpers_port.h
target_include_directories(mbedtls_test_helpers
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# As Mbed TLS's own suites, see add_test_suite in its tests/CMakeLists.txt.
# The helpers' options: set_base_compile_options needs Mbed TLS's variables.
add_executable(test_suite_ssl_public ${SUITE_C} ssl_helpers_port.c
    $<TARGET_OBJECTS:mbedtls_test> $<TARGET_OBJECTS:mbedtls_test_helpers>)
target_compile_options(test_suite_ssl_public PRIVATE
    $<TARGET_PROPERTY:mbedtls_test_helpers,COMPILE_OPTIONS>)
target_include_directories(test_suite_ssl_public PRIVATE
    $<TARGET_PROPERTY:mbedtls_test_helpers,INCLUDE_DIRECTORIES>)
target_compile_definitions(test_suite_ssl_public
    PRIVATE _POSIX_C_SOURCE=200809L)
target_link_libraries(test_suite_ssl_public mbedtls)
set_target_properties(test_suite_ssl_public PROPERTIES C_STANDARD 11)
# The header's static functions include some for cases left out
set_source_files_properties(${SUITE_C}
    PROPERTIES COMPILE_OPTIONS -Wno-unused-function)
