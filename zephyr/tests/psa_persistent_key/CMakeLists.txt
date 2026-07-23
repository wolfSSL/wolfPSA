# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drop-in proof: builds Zephyr's own samples/psa/persistent_key source verbatim,
# but against the wolfPSA custom PSA provider + wolfPSA's wolfCrypt ITS transform.
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfpsa_psa_persistent_key)
target_sources(app PRIVATE ${ZEPHYR_BASE}/samples/psa/persistent_key/src/main.c)
