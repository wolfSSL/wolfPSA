/* ctr_drbg.h
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

#ifndef MBEDTLS_CTR_DRBG_H
#define MBEDTLS_CTR_DRBG_H

#include "mbedtls/build_info.h"

#ifndef WOLFPSA_MBEDTLS_3
    #error "mbedtls/ctr_drbg.h is Mbed TLS 3.6 API: define WOLFPSA_MBEDTLS_3"
#endif /* !WOLFPSA_MBEDTLS_3 */

#include "mbedtls/entropy.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED -0x0034
#define MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG       -0x0036
#define MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG         -0x0038

/* As Mbed TLS: a second read at seed when the first is short of a nonce */
#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
    #define MBEDTLS_CTR_DRBG_ENTROPY_LEN       48
    #define MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN 0
#else
    #define MBEDTLS_CTR_DRBG_ENTROPY_LEN       32
    #define MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN 16
#endif /* MBEDTLS_ENTROPY_SHA512_ACCUMULATOR */
#define MBEDTLS_CTR_DRBG_RESEED_INTERVAL 10000
#define MBEDTLS_CTR_DRBG_MAX_REQUEST     1024
#define MBEDTLS_CTR_DRBG_MAX_SEED_INPUT  384
#define MBEDTLS_CTR_DRBG_PR_OFF          0
#define MBEDTLS_CTR_DRBG_PR_ON           1

/* wolfCrypt's DRBG, opaque to the application */
struct WC_RNG;

typedef struct mbedtls_ctr_drbg_context {
    struct WC_RNG* rng; /* NULL until seeded */
    int (*f_entropy)(void*, unsigned char*, size_t);
    void* p_entropy;
    int prediction_resistance;
    int reseed_counter; /* requests since the last seed */
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex; /* initialized when seeded */
#endif /* MBEDTLS_THREADING_C */
} mbedtls_ctr_drbg_context;

#if defined(MBEDTLS_CTR_DRBG_C)
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context* ctx);
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context* ctx);
int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context* ctx,
    int (*f_entropy)(void*, unsigned char*, size_t), void* p_entropy,
    const unsigned char* custom, size_t len);
void mbedtls_ctr_drbg_set_prediction_resistance(mbedtls_ctr_drbg_context* ctx,
    int resistance);
int mbedtls_ctr_drbg_reseed(mbedtls_ctr_drbg_context* ctx,
    const unsigned char* additional, size_t len);
int mbedtls_ctr_drbg_random(void* p_rng, unsigned char* output,
    size_t output_len);
#endif /* MBEDTLS_CTR_DRBG_C */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_CTR_DRBG_H */
