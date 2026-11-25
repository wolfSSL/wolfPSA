/* rsa.h
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

/* The Mbed TLS 3.6 RSA key of mbedtls_pk_rsa(), with WOLFPSA_MBEDTLS_3 */

#ifndef MBEDTLS_RSA_H
#define MBEDTLS_RSA_H

#include "mbedtls/build_info.h"
#include "psa/crypto.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA PSA_ERROR_INVALID_ARGUMENT
#define MBEDTLS_ERR_RSA_KEY_GEN_FAILED -0x4180

#ifndef MBEDTLS_RSA_GEN_KEY_MIN_BITS
    #define MBEDTLS_RSA_GEN_KEY_MIN_BITS 1024
#endif /* !MBEDTLS_RSA_GEN_KEY_MIN_BITS */

/* Opaque: only mbedtls_pk_rsa() returns one */
typedef struct mbedtls_rsa_context mbedtls_rsa_context;

size_t mbedtls_rsa_get_len(const mbedtls_rsa_context* ctx);
int mbedtls_rsa_gen_key(mbedtls_rsa_context* ctx,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng,
    unsigned int nbits, int exponent);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_RSA_H */
