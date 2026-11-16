/* pem.h
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

/* PEM decoding, without encrypted PEM. No MBEDTLS_PEM_WRITE_C yet. */

#ifndef MBEDTLS_PEM_H
#define MBEDTLS_PEM_H

#include "tf-psa-crypto/build_info.h"
#include "psa/crypto.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT -0x1080
#define MBEDTLS_ERR_PEM_INVALID_DATA             -0x1100
#define MBEDTLS_ERR_PEM_INVALID_ENC_IV           -0x1200
#define MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG          -0x1280
#define MBEDTLS_ERR_PEM_PASSWORD_REQUIRED        -0x1300
#define MBEDTLS_ERR_PEM_PASSWORD_MISMATCH        -0x1380
#define MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE      -0x1400
#define MBEDTLS_ERR_PEM_BAD_INPUT_DATA           PSA_ERROR_INVALID_ARGUMENT
#define MBEDTLS_ERR_PEM_ALLOC_FAILED             PSA_ERROR_INSUFFICIENT_MEMORY

#if defined(MBEDTLS_PEM_PARSE_C)
typedef struct mbedtls_pem_context {
    unsigned char* buf; /* the decoded data */
    size_t buflen;
} mbedtls_pem_context;

void mbedtls_pem_init(mbedtls_pem_context* ctx);
int mbedtls_pem_read_buffer(mbedtls_pem_context* ctx, const char* header,
    const char* footer, const unsigned char* data, const unsigned char* pwd,
    size_t pwdlen, size_t* use_len);
void mbedtls_pem_free(mbedtls_pem_context* ctx);

static inline const unsigned char* mbedtls_pem_get_buffer(
    mbedtls_pem_context* ctx, size_t* buflen)
{
    *buflen = ctx->buflen;
    return ctx->buf;
}
#endif /* MBEDTLS_PEM_PARSE_C */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_PEM_H */
