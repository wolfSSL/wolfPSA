/* pk.h
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

#ifndef MBEDTLS_PK_H
#define MBEDTLS_PK_H

#include "tf-psa-crypto/build_info.h"
#include "psa/crypto.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

/* TF-PSA-Crypto returns PSA_ERROR_INVALID_ARGUMENT and
 * PSA_ERROR_INSUFFICIENT_MEMORY for bad input and allocation failures */
#define MBEDTLS_ERR_PK_TYPE_MISMATCH       -0x3F00
#define MBEDTLS_ERR_PK_FILE_IO_ERROR       -0x3E00
#define MBEDTLS_ERR_PK_KEY_INVALID_VERSION -0x3D80
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80
#define MBEDTLS_ERR_PK_PASSWORD_REQUIRED   -0x3C00
#define MBEDTLS_ERR_PK_PASSWORD_MISMATCH   -0x3B80
#define MBEDTLS_ERR_PK_INVALID_PUBKEY      -0x3B00
#define MBEDTLS_ERR_PK_INVALID_ALG         -0x3A80
#define MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00
#define MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980

#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
    #define MBEDTLS_PK_ALG_ECDSA(hash_alg) PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)
#else
    #define MBEDTLS_PK_ALG_ECDSA(hash_alg) PSA_ALG_ECDSA(hash_alg)
#endif /* PSA_WANT_ALG_DETERMINISTIC_ECDSA */

/* An RSA or EC private key, DER */
typedef struct mbedtls_pk_context {
    unsigned char* der;
    size_t der_len;
} mbedtls_pk_context;

void mbedtls_pk_init(mbedtls_pk_context* ctx);
void mbedtls_pk_free(mbedtls_pk_context* ctx);
int mbedtls_pk_parse_key(mbedtls_pk_context* ctx, const unsigned char* key,
    size_t keylen, const unsigned char* pwd, size_t pwdlen);
int mbedtls_pk_can_do_psa(const mbedtls_pk_context* pk, psa_algorithm_t alg,
    psa_key_usage_t usage);
#if defined(MBEDTLS_FS_IO)
int mbedtls_pk_parse_keyfile(mbedtls_pk_context* ctx, const char* path,
    const char* password);
#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_PK_H */
