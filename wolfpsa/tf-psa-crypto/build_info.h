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

/* The TF-PSA-Crypto API version wolfPSA follows, from Mbed TLS 4.2.0 */
#define TF_PSA_CRYPTO_VERSION_MAJOR  1
#define TF_PSA_CRYPTO_VERSION_MINOR  2
#define TF_PSA_CRYPTO_VERSION_PATCH  0
#define TF_PSA_CRYPTO_VERSION_NUMBER         0x01020000
#define TF_PSA_CRYPTO_VERSION_STRING         "1.2.0"
#define TF_PSA_CRYPTO_VERSION_STRING_FULL    "TF-PSA-Crypto 1.2.0"

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CLIENT
/* MBEDTLS_ENTROPY_C and MBEDTLS_CTR_DRBG_C come from crypto_config.h */
/* mbedtls/pk.h: private keys, PEM or DER */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

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

/* Signature algorithms with the key types they need */
#if defined(PSA_WANT_ALG_ECDSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
    #define PSA_HAVE_ALG_SOME_ECDSA
#endif /* PSA_WANT_ALG_ECDSA || PSA_WANT_ALG_DETERMINISTIC_ECDSA */
#if defined(PSA_HAVE_ALG_SOME_ECDSA) && \
        defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
    #define PSA_HAVE_ALG_ECDSA_SIGN
#endif /* PSA_HAVE_ALG_SOME_ECDSA && PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC */
#if defined(PSA_HAVE_ALG_SOME_ECDSA) && \
        defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
    #define PSA_HAVE_ALG_ECDSA_VERIFY
#endif /* PSA_HAVE_ALG_SOME_ECDSA && PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && \
        defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
    #define PSA_HAVE_ALG_RSA_PKCS1V15_SIGN
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_SIGN &&
        * PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
#if defined(PSA_WANT_ALG_RSA_PSS) && \
        defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
    #define PSA_HAVE_ALG_RSA_PSS_SIGN
#endif /* PSA_WANT_ALG_RSA_PSS && PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
#if defined(PSA_HAVE_ALG_RSA_PKCS1V15_SIGN) || \
        defined(PSA_HAVE_ALG_RSA_PSS_SIGN)
    #define PSA_HAVE_ALG_SOME_RSA_SIGN
#endif /* PSA_HAVE_ALG_RSA_PKCS1V15_SIGN || PSA_HAVE_ALG_RSA_PSS_SIGN */
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && \
        defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
    #define PSA_HAVE_ALG_RSA_PKCS1V15_VERIFY
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_SIGN && PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */
#if defined(PSA_WANT_ALG_RSA_PSS) && defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
    #define PSA_HAVE_ALG_RSA_PSS_VERIFY
#endif /* PSA_WANT_ALG_RSA_PSS && PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */
#if defined(PSA_HAVE_ALG_RSA_PKCS1V15_VERIFY) || \
        defined(PSA_HAVE_ALG_RSA_PSS_VERIFY)
    #define PSA_HAVE_ALG_SOME_RSA_VERIFY
#endif /* PSA_HAVE_ALG_RSA_PKCS1V15_VERIFY || PSA_HAVE_ALG_RSA_PSS_VERIFY */
#if defined(PSA_HAVE_ALG_SOME_RSA_SIGN) || \
        defined(PSA_HAVE_ALG_SOME_RSA_VERIFY)
    #define PSA_HAVE_ALG_SOME_RSA_SIGN_OR_VERIFY
#endif /* PSA_HAVE_ALG_SOME_RSA_SIGN || PSA_HAVE_ALG_SOME_RSA_VERIFY */

/* pthreads, the one implementation of MBEDTLS_THREADING_C */
#if defined(MBEDTLS_THREADING_C) && !defined(MBEDTLS_THREADING_PTHREAD) && \
        !defined(__ZEPHYR__)
    #define MBEDTLS_THREADING_PTHREAD
#endif /* MBEDTLS_THREADING_C && !MBEDTLS_THREADING_PTHREAD && !__ZEPHYR__ */

#endif /* TF_PSA_CRYPTO_BUILD_INFO_H */
