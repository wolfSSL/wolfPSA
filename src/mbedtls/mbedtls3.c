/* mbedtls3.c
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

/* Mbed TLS 3.6 names that 4.x removed (MBEDTLS_COMPAT=1), for applications
 * built with WOLFPSA_MBEDTLS_3. Defined here before any include, so the 3.6
 * declarations are checked against these functions. */

#ifndef WOLFPSA_MBEDTLS_3
    #define WOLFPSA_MBEDTLS_3
#endif /* !WOLFPSA_MBEDTLS_3 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/logging.h>
#include <mbedtls/ssl.h>

#if defined(MBEDTLS_SSL_TLS_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
/* By the bytes of the TLS version */
void mbedtls_ssl_conf_min_version(mbedtls_ssl_config* conf, int major,
    int minor)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_min_version");

    mbedtls_ssl_conf_min_tls_version(conf,
        (mbedtls_ssl_protocol_version)((major << 8) | minor));
}

void mbedtls_ssl_conf_max_version(mbedtls_ssl_config* conf, int major,
    int minor)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_max_version");

    mbedtls_ssl_conf_max_tls_version(conf,
        (mbedtls_ssl_protocol_version)((major << 8) | minor));
}
#endif /* MBEDTLS_SSL_TLS_C && !MBEDTLS_DEPRECATED_REMOVED */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
