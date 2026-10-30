/* build_info.h
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

/* TF-PSA-Crypto feature macros that applications test, derived from the
 * PSA_WANT_ surface. A macro for a TF-PSA-Crypto module (such as MBEDTLS_MD_C
 * for mbedtls/md.h) is defined only when wolfPSA provides that module. */

#ifndef TF_PSA_CRYPTO_BUILD_INFO_H
#define TF_PSA_CRYPTO_BUILD_INFO_H

#include "psa/crypto_config.h"

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CLIENT
/* The PSA RNG, wolfCrypt's DRBG. No public API in TF-PSA-Crypto 1.x. */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

#if defined(PSA_WANT_KEY_TYPE_AES)
    #define MBEDTLS_AES_C
#endif /* PSA_WANT_KEY_TYPE_AES */
#if defined(PSA_WANT_ALG_CCM)
    #define MBEDTLS_CCM_C
#endif /* PSA_WANT_ALG_CCM */
#if defined(PSA_WANT_ALG_GCM)
    #define MBEDTLS_GCM_C
#endif /* PSA_WANT_ALG_GCM */
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
    #define MBEDTLS_CHACHAPOLY_C
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */
#if defined(PSA_WANT_ALG_CBC_NO_PADDING) || defined(PSA_WANT_ALG_CBC_PKCS7)
    #define MBEDTLS_CIPHER_MODE_CBC
#endif /* PSA_WANT_ALG_CBC_NO_PADDING || PSA_WANT_ALG_CBC_PKCS7 */
#if defined(PSA_WANT_ALG_CBC_PKCS7)
    #define MBEDTLS_CIPHER_MODE_WITH_PADDING
#endif /* PSA_WANT_ALG_CBC_PKCS7 */
#if defined(PSA_WANT_ALG_CTR)
    #define MBEDTLS_CIPHER_MODE_CTR
#endif /* PSA_WANT_ALG_CTR */

#endif /* TF_PSA_CRYPTO_BUILD_INFO_H */
