/* ssl_ciphersuites.h
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

#ifndef MBEDTLS_SSL_CIPHERSUITES_H
#define MBEDTLS_SSL_CIPHERSUITES_H

#include "mbedtls/build_info.h"

/* Not all are offered, see mbedtls_ssl_list_ciphersuites() */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          0xC009
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          0xC00A
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            0xC013
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            0xC014
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       0xC023
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       0xC024
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         0xC027
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384         0xC028
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       0xC02B
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       0xC02C
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         0xC02F
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         0xC030
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM              0xC0AC
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM              0xC0AD
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            0xC0AE
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            0xC0AF
#define MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA8
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA9

#define MBEDTLS_TLS1_3_AES_128_GCM_SHA256                     0x1301
#define MBEDTLS_TLS1_3_AES_256_GCM_SHA384                     0x1302
#define MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256               0x1303
#define MBEDTLS_TLS1_3_AES_128_CCM_SHA256                     0x1304
#define MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256                   0x1305

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
        defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    #define MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
        * MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) || \
        defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    #define MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED ||
        * MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

#endif /* MBEDTLS_SSL_CIPHERSUITES_H */
