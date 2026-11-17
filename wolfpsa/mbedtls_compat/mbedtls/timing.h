/* timing.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef MBEDTLS_TIMING_H
#define MBEDTLS_TIMING_H

#include "mbedtls/build_info.h"

#include <stdint.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

struct mbedtls_timing_hr_time {
    int64_t ms;
};

typedef struct mbedtls_timing_delay_context {
    struct mbedtls_timing_hr_time timer;
    uint32_t int_ms;
    uint32_t fin_ms;
} mbedtls_timing_delay_context;

unsigned long long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time* val,
    int reset);
void mbedtls_timing_set_delay(void* data, uint32_t int_ms, uint32_t fin_ms);
int mbedtls_timing_get_delay(void* data);
uint32_t mbedtls_timing_get_final_delay(
    const mbedtls_timing_delay_context* data);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_TIMING_H */
