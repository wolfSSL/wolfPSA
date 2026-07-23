# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drop-in proof: Zephyr's own PSA ITS sample source, run against wolfPSA's PSA
# ITS store backend + wolfCrypt custom transform.
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfpsa_psa_its)
target_sources(app PRIVATE ${ZEPHYR_BASE}/samples/psa/its/src/main.c)
