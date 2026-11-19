/* md.h
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

/* The public TF-PSA-Crypto md API, on psa_hash_*. HMAC is psa_mac_* only. */

#ifndef MBEDTLS_MD_H
#define MBEDTLS_MD_H

#include "tf-psa-crypto/build_info.h"
#include "psa/crypto.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE -0x5080
#define MBEDTLS_ERR_MD_BAD_INPUT_DATA      PSA_ERROR_INVALID_ARGUMENT
#define MBEDTLS_ERR_MD_ALLOC_FAILED        PSA_ERROR_INSUFFICIENT_MEMORY

/* The values of the PSA_ALG_ hash algorithms */
typedef enum {
    MBEDTLS_MD_NONE = 0,
    MBEDTLS_MD_MD5 = 0x03,
    MBEDTLS_MD_RIPEMD160 = 0x04,
    MBEDTLS_MD_SHA1 = 0x05,
    MBEDTLS_MD_SHA224 = 0x08,
    MBEDTLS_MD_SHA256 = 0x09,
    MBEDTLS_MD_SHA384 = 0x0a,
    MBEDTLS_MD_SHA512 = 0x0b,
    MBEDTLS_MD_SHA3_224 = 0x10,
    MBEDTLS_MD_SHA3_256 = 0x11,
    MBEDTLS_MD_SHA3_384 = 0x12,
    MBEDTLS_MD_SHA3_512 = 0x13
} mbedtls_md_type_t;

#if defined(PSA_WANT_ALG_SHA_512) || defined(PSA_WANT_ALG_SHA3_512)
    #define MBEDTLS_MD_MAX_SIZE 64
#elif defined(PSA_WANT_ALG_SHA_384) || defined(PSA_WANT_ALG_SHA3_384)
    #define MBEDTLS_MD_MAX_SIZE 48
#elif defined(PSA_WANT_ALG_SHA_256) || defined(PSA_WANT_ALG_SHA3_256)
    #define MBEDTLS_MD_MAX_SIZE 32
#elif defined(PSA_WANT_ALG_SHA_224) || defined(PSA_WANT_ALG_SHA3_224)
    #define MBEDTLS_MD_MAX_SIZE 28
#else
    #define MBEDTLS_MD_MAX_SIZE 20
#endif /* MBEDTLS_MD_MAX_SIZE */

typedef struct mbedtls_md_info_t mbedtls_md_info_t;

/* md_ctx is a psa_hash_operation_t */
typedef struct mbedtls_md_context_t {
    const mbedtls_md_info_t* md_info;
    void* md_ctx;
} mbedtls_md_context_t;

#if defined(MBEDTLS_MD_C)
const mbedtls_md_info_t* mbedtls_md_info_from_type(mbedtls_md_type_t md_type);
void mbedtls_md_init(mbedtls_md_context_t* ctx);
void mbedtls_md_free(mbedtls_md_context_t* ctx);
int mbedtls_md_setup(mbedtls_md_context_t* ctx,
    const mbedtls_md_info_t* md_info, int hmac);
int mbedtls_md_clone(mbedtls_md_context_t* dst,
    const mbedtls_md_context_t* src);
unsigned char mbedtls_md_get_size(const mbedtls_md_info_t* md_info);
mbedtls_md_type_t mbedtls_md_get_type(const mbedtls_md_info_t* md_info);
int mbedtls_md_starts(mbedtls_md_context_t* ctx);
int mbedtls_md_update(mbedtls_md_context_t* ctx, const unsigned char* input,
    size_t ilen);
int mbedtls_md_finish(mbedtls_md_context_t* ctx, unsigned char* output);
int mbedtls_md(const mbedtls_md_info_t* md_info, const unsigned char* input,
    size_t ilen, unsigned char* output);

static inline unsigned char mbedtls_md_get_size_from_type(
    mbedtls_md_type_t md_type)
{
    return mbedtls_md_get_size(mbedtls_md_info_from_type(md_type));
}
#endif /* MBEDTLS_MD_C */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_MD_H */
