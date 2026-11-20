/* timing.c
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

/* Mbed TLS 4.x timers and mbedtls_ms_time() (MBEDTLS_COMPAT=1). */

/* clock_gettime() with -std=c99 */
#if defined(WOLFPSA_MBEDTLS_COMPAT) && !defined(_POSIX_C_SOURCE)
    #define _POSIX_C_SOURCE 200112L
#endif /* WOLFPSA_MBEDTLS_COMPAT && !_POSIX_C_SOURCE */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/logging.h>
#include <mbedtls/timing.h>

/* The generated config has them on Windows and Unix-like systems */
#if defined(MBEDTLS_HAVE_TIME) != \
        (defined(USE_WINDOWS_API) || defined(__unix__) || defined(__APPLE__))
    #error "MBEDTLS_HAVE_TIME does not match the platform"
#endif /* MBEDTLS_HAVE_TIME != (USE_WINDOWS_API || __unix__ || __APPLE__) */
#if defined(MBEDTLS_TIMING_C) != defined(MBEDTLS_HAVE_TIME)
    #error "MBEDTLS_TIMING_C does not match MBEDTLS_HAVE_TIME"
#endif /* MBEDTLS_TIMING_C != MBEDTLS_HAVE_TIME */

#if defined(MBEDTLS_HAVE_TIME)

#ifdef USE_WINDOWS_API
    #include <windows.h>
#else
    #include <time.h>
    /* As in Mbed TLS, on Linux the clock counts time suspended too */
    #if defined(__linux__) && defined(CLOCK_BOOTTIME)
        #define MBED_TIMING_CLOCK CLOCK_BOOTTIME
    #else
        #define MBED_TIMING_CLOCK CLOCK_MONOTONIC
    #endif /* __linux__ && CLOCK_BOOTTIME */
#endif /* USE_WINDOWS_API */

/* Falls back to time(), as Mbed TLS */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
#ifdef USE_WINDOWS_API
    return (mbedtls_ms_time_t)GetTickCount64();
#else
    struct timespec ts;

    if (clock_gettime(MBED_TIMING_CLOCK, &ts) != 0) {
        return (mbedtls_ms_time_t)time(NULL) * 1000;
    }
    return (mbedtls_ms_time_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif /* USE_WINDOWS_API */
}

#endif /* MBEDTLS_HAVE_TIME */

#if defined(MBEDTLS_TIMING_C)

unsigned long long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time* val,
    int reset)
{
    mbedtls_ms_time_t now;

    WOLFSSL_ENTER("mbedtls_timing_get_timer");

    if (val == NULL) {
        return 0;
    }
    now = mbedtls_ms_time();
    if (reset) {
        val->ms = now;
        return 0;
    }
    return (unsigned long long)(now - val->ms);
}

void mbedtls_timing_set_delay(void* data, uint32_t int_ms, uint32_t fin_ms)
{
    mbedtls_timing_delay_context* ctx = (mbedtls_timing_delay_context*)data;

    WOLFSSL_ENTER("mbedtls_timing_set_delay");

    if (ctx != NULL) {
        ctx->int_ms = int_ms;
        ctx->fin_ms = fin_ms;
        if (fin_ms != 0) {
            (void)mbedtls_timing_get_timer(&ctx->timer, 1);
        }
    }
}

/* Returns -1 when cancelled, else how many of the two delays have passed */
int mbedtls_timing_get_delay(void* data)
{
    mbedtls_timing_delay_context* ctx = (mbedtls_timing_delay_context*)data;
    unsigned long long elapsed;

    WOLFSSL_ENTER("mbedtls_timing_get_delay");

    if (ctx == NULL || ctx->fin_ms == 0) {
        return -1;
    }
    elapsed = mbedtls_timing_get_timer(&ctx->timer, 0);
    if (elapsed >= ctx->fin_ms) {
        return 2;
    }
    return (elapsed >= ctx->int_ms) ? 1 : 0;
}

uint32_t mbedtls_timing_get_final_delay(
    const mbedtls_timing_delay_context* data)
{
    WOLFSSL_ENTER("mbedtls_timing_get_final_delay");

    return (data == NULL) ? 0 : data->fin_ms;
}

#endif /* MBEDTLS_TIMING_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
