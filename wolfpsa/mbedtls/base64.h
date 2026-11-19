/* base64.h
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

#ifndef MBEDTLS_BASE64_H
#define MBEDTLS_BASE64_H

#include "tf-psa-crypto/build_info.h"
#include "psa/crypto.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER -0x002C
#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL  PSA_ERROR_BUFFER_TOO_SMALL

#if defined(MBEDTLS_BASE64_C)
int mbedtls_base64_encode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen);
int mbedtls_base64_decode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen);
#endif /* MBEDTLS_BASE64_C */

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_BASE64_H */
