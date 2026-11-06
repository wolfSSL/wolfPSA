/* threading.h
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

/* TF-PSA-Crypto 1.x mutexes and condition variables, on pthreads. Built with
 * MBEDTLS_THREADING_C=1. */

#ifndef MBEDTLS_THREADING_H
#define MBEDTLS_THREADING_H

#include "tf-psa-crypto/build_info.h"

#if defined(MBEDTLS_THREADING_PTHREAD)
    #include <pthread.h>
#endif /* MBEDTLS_THREADING_PTHREAD */

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_THREADING_USAGE_ERROR -0x001E
#define MBEDTLS_ERR_THREADING_MUTEX_ERROR MBEDTLS_ERR_THREADING_USAGE_ERROR

#if defined(MBEDTLS_THREADING_C)

#if defined(MBEDTLS_THREADING_PTHREAD)
typedef pthread_mutex_t mbedtls_platform_mutex_t;
typedef pthread_cond_t mbedtls_platform_condition_variable_t;
#else
    #error "MBEDTLS_THREADING_C is supported with pthreads only"
#endif /* MBEDTLS_THREADING_PTHREAD */

typedef struct mbedtls_threading_mutex_t {
    mbedtls_platform_mutex_t mutex;
    char initialized;
} mbedtls_threading_mutex_t;

typedef struct mbedtls_threading_condition_variable_t {
    mbedtls_platform_condition_variable_t cond;
} mbedtls_threading_condition_variable_t;

void mbedtls_mutex_init(mbedtls_threading_mutex_t* mutex);
void mbedtls_mutex_free(mbedtls_threading_mutex_t* mutex);
int mbedtls_mutex_lock(mbedtls_threading_mutex_t* mutex);
int mbedtls_mutex_unlock(mbedtls_threading_mutex_t* mutex);

int mbedtls_condition_variable_init(
    mbedtls_threading_condition_variable_t* cond);
void mbedtls_condition_variable_free(
    mbedtls_threading_condition_variable_t* cond);
int mbedtls_condition_variable_signal(
    mbedtls_threading_condition_variable_t* cond);
int mbedtls_condition_variable_broadcast(
    mbedtls_threading_condition_variable_t* cond);
int mbedtls_condition_variable_wait(
    mbedtls_threading_condition_variable_t* cond,
    mbedtls_threading_mutex_t* mutex);

#endif /* MBEDTLS_THREADING_C */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_THREADING_H */
