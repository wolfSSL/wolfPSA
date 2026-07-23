# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drop-in consumer test: builds Zephyr's own provider-agnostic PSA crypto
# ztest (tests/crypto/mbedtls_psa) UNCHANGED, but against the wolfPSA custom
# provider instead of Mbed TLS. Proves a real Zephyr PSA consumer works on
# wolfPSA and that the CONFIG_PSA_WANT_* -> PSA_WANT_* mapping resolves.

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfpsa_psa_consumer)

# Reuse the in-tree test source verbatim (it only depends on <psa/crypto.h>).
target_sources(app PRIVATE ${ZEPHYR_BASE}/tests/crypto/mbedtls_psa/src/main.c)
