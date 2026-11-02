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

#define MBEDTLS_NET_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_X509_CRT_PARSE_C
/* PEM certificates only, no mbedtls/pem.h */
#define MBEDTLS_PEM_PARSE_C
/* No mbedtls_x509_crt_info() and friends yet */
#define MBEDTLS_X509_REMOVE_INFO

#endif /* MBEDTLS_BUILD_INFO_H */
