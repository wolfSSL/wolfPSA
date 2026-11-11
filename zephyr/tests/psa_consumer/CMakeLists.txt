# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Builds Zephyr's provider-agnostic PSA crypto ztest unchanged, against wolfPSA
# instead of Mbed TLS.

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfpsa_psa_consumer)

# Reuse the in-tree test source verbatim (it only depends on <psa/crypto.h>).
if(EXISTS ${ZEPHYR_BASE}/tests/crypto/psa/src/main.c)
  target_sources(app PRIVATE ${ZEPHYR_BASE}/tests/crypto/psa/src/main.c)
else()
  target_sources(app PRIVATE ${ZEPHYR_BASE}/tests/crypto/mbedtls_psa/src/main.c)
endif()
