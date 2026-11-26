/* entropy.h
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

#ifndef MBEDTLS_ENTROPY_H
#define MBEDTLS_ENTROPY_H

#include "mbedtls/build_info.h"

#ifndef WOLFPSA_MBEDTLS_3
    #error "mbedtls/entropy.h is Mbed TLS 3.6 API: define WOLFPSA_MBEDTLS_3"
#endif /* !WOLFPSA_MBEDTLS_3 */

#if defined(MBEDTLS_THREADING_C)
    #include "mbedtls/threading.h"
#endif /* MBEDTLS_THREADING_C */

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#if defined(PSA_WANT_ALG_SHA_512)
    #define MBEDTLS_ENTROPY_SHA512_ACCUMULATOR
    #define MBEDTLS_ENTROPY_BLOCK_SIZE 64
#else
    #define MBEDTLS_ENTROPY_SHA256_ACCUMULATOR
    #define MBEDTLS_ENTROPY_BLOCK_SIZE 32
#endif /* PSA_WANT_ALG_SHA_512 */

#define MBEDTLS_ERR_ENTROPY_SOURCE_FAILED      -0x003C
#define MBEDTLS_ERR_ENTROPY_MAX_SOURCES        -0x003E
#define MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED -0x0040

#define MBEDTLS_ENTROPY_MAX_SOURCES   20
#define MBEDTLS_ENTROPY_MAX_GATHER    128
#define MBEDTLS_ENTROPY_SOURCE_STRONG 1
#define MBEDTLS_ENTROPY_SOURCE_WEAK   0

typedef int (*mbedtls_entropy_f_source_ptr)(void* data, unsigned char* output,
    size_t len, size_t* olen);

typedef struct mbedtls_entropy_source_state {
    mbedtls_entropy_f_source_ptr f_source;
    void* p_source;
    size_t size; /* gathered since the last output */
    size_t threshold;
    int strong;
} mbedtls_entropy_source_state;

typedef struct mbedtls_entropy_context {
    int source_count;
    mbedtls_entropy_source_state source[MBEDTLS_ENTROPY_MAX_SOURCES];
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
#endif /* MBEDTLS_THREADING_C */
} mbedtls_entropy_context;

#if defined(MBEDTLS_ENTROPY_C)
void mbedtls_entropy_init(mbedtls_entropy_context* ctx);
void mbedtls_entropy_free(mbedtls_entropy_context* ctx);
int mbedtls_entropy_add_source(mbedtls_entropy_context* ctx,
    mbedtls_entropy_f_source_ptr f_source, void* p_source, size_t threshold,
    int strong);
int mbedtls_entropy_func(void* data, unsigned char* output, size_t len);
#endif /* MBEDTLS_ENTROPY_C */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_ENTROPY_H */
