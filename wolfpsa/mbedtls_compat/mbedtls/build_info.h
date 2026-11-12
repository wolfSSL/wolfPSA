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

/* Mbed TLS feature macros for the compatibility layer, built with
 * MBEDTLS_COMPAT=1. */

#ifndef MBEDTLS_BUILD_INFO_H
#define MBEDTLS_BUILD_INFO_H

#include "tf-psa-crypto/build_info.h"

/* The Mbed TLS API version this layer follows */
#define MBEDTLS_VERSION_MAJOR  4
#define MBEDTLS_VERSION_MINOR  2
#define MBEDTLS_VERSION_PATCH  0
#define MBEDTLS_VERSION_NUMBER         0x04020000
#define MBEDTLS_VERSION_STRING         "4.2.0"
#define MBEDTLS_VERSION_STRING_FULL    "Mbed TLS 4.2.0"

/* MBEDTLS_X509_CRT_PARSE_C and MBEDTLS_SSL_* are in the generated config */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    #define MBEDTLS_X509_USE_C
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) && defined(PSA_WANT_ALG_RSA_PSS)
    #define MBEDTLS_X509_RSASSA_PSS_SUPPORT
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY && PSA_WANT_ALG_RSA_PSS */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(PSA_WANT_ALG_ECDH)
    #define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && PSA_WANT_ALG_ECDH */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(PSA_WANT_ALG_ECDH)
#if defined(PSA_HAVE_ALG_RSA_PKCS1V15_SIGN)
    #define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#endif /* PSA_HAVE_ALG_RSA_PKCS1V15_SIGN */
#if defined(PSA_HAVE_ALG_ECDSA_SIGN)
    #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#endif /* PSA_HAVE_ALG_ECDSA_SIGN */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 && PSA_WANT_ALG_ECDH */
/* No mbedtls_x509_crt_info() and friends yet */
#ifndef MBEDTLS_X509_REMOVE_INFO
    #define MBEDTLS_X509_REMOVE_INFO
#endif /* !MBEDTLS_X509_REMOVE_INFO */

#endif /* MBEDTLS_BUILD_INFO_H */
