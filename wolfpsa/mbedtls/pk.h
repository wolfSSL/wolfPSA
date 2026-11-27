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
#if defined(WOLFPSA_MBEDTLS_3)
#include "mbedtls/ecp.h"
#include "mbedtls/rsa.h"
#endif /* WOLFPSA_MBEDTLS_3 */

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

/* der has a private key's DER, or pub a public key's SubjectPublicKeyInfo */
typedef struct mbedtls_pk_context {
    unsigned char* der;
    size_t der_len;
    unsigned char* pub;
    size_t pub_len;
    size_t bits;
    int type;
} mbedtls_pk_context;

/* The supported subset of MBEDTLS_PK_C and MBEDTLS_PK_PARSE_C */
void mbedtls_pk_init(mbedtls_pk_context* ctx);
void mbedtls_pk_free(mbedtls_pk_context* ctx);
size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context* ctx);
int mbedtls_pk_parse_key(mbedtls_pk_context* ctx, const unsigned char* key,
    size_t keylen, const unsigned char* pwd, size_t pwdlen);
int mbedtls_pk_parse_public_key(mbedtls_pk_context* ctx,
    const unsigned char* key, size_t keylen);
int mbedtls_pk_can_do_psa(const mbedtls_pk_context* pk, psa_algorithm_t alg,
    psa_key_usage_t usage);
#if defined(MBEDTLS_FS_IO)
int mbedtls_pk_parse_keyfile(mbedtls_pk_context* ctx, const char* path,
    const char* password);
int mbedtls_pk_parse_public_keyfile(mbedtls_pk_context* ctx,
    const char* path);
#endif /* MBEDTLS_FS_IO */

#if defined(WOLFPSA_MBEDTLS_3)
#define MBEDTLS_ERR_PK_ALLOC_FAILED   PSA_ERROR_INSUFFICIENT_MEMORY
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA PSA_ERROR_INVALID_ARGUMENT

typedef enum {
    MBEDTLS_PK_NONE = 0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE
} mbedtls_pk_type_t;

typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;

/* Has MBEDTLS_PK_RSA and MBEDTLS_PK_ECKEY */
const mbedtls_pk_info_t* mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type);
int mbedtls_pk_setup(mbedtls_pk_context* ctx, const mbedtls_pk_info_t* info);
mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context* ctx);

/* The key is the context. As in 3.6, a const context's key can change. */
static inline mbedtls_ecp_keypair* wolfPSA_MbedPkEc(
    const mbedtls_pk_context* pk)
{
    return (mbedtls_pk_get_type(pk) == MBEDTLS_PK_ECKEY) ?
        (mbedtls_ecp_keypair*)(uintptr_t)pk : NULL;
}

static inline mbedtls_rsa_context* wolfPSA_MbedPkRsa(
    const mbedtls_pk_context* pk)
{
    return (mbedtls_pk_get_type(pk) == MBEDTLS_PK_RSA) ?
        (mbedtls_rsa_context*)(uintptr_t)pk : NULL;
}

/* 3.6 takes the context by value: here pk must be an lvalue */
#define mbedtls_pk_ec(pk)  wolfPSA_MbedPkEc(&(pk))
#define mbedtls_pk_rsa(pk) wolfPSA_MbedPkRsa(&(pk))
#endif /* WOLFPSA_MBEDTLS_3 */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_PK_H */
