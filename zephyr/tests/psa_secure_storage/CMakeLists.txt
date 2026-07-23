# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drop-in proof: Zephyr's own secure_storage PSA crypto ztest (persistent keys +
# ITS + PS coexistence), run against wolfPSA + its wolfCrypt custom transform.
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfpsa_psa_secure_storage)
target_sources(app PRIVATE
  ${ZEPHYR_BASE}/tests/subsys/secure_storage/psa/crypto/src/main.c)
