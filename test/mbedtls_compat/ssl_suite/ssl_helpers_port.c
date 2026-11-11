/* ssl_helpers_port.c
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

/* Replacements for the ssl test helpers that use Mbed TLS internals */

#include "ssl_helpers_port.h"

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
int mbedtls_test_move_handshake_to_state(mbedtls_ssl_context *ssl,
    mbedtls_ssl_context *second_ssl, int state)
{
    (void)ssl;
    (void)second_ssl;
    (void)state;
    NOT_PORTED("handshake state");
    return -1;
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
int mbedtls_test_ssl_tls12_populate_session(mbedtls_ssl_session *session,
    int ticket_len, int endpoint_type, const char *crt_file)
{
    (void)session;
    (void)ticket_len;
    (void)endpoint_type;
    (void)crt_file;
    NOT_PORTED("session fields");
    return -1;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_test_ssl_tls13_populate_session(mbedtls_ssl_session *session,
    int ticket_len, int endpoint_type)
{
    (void)session;
    (void)ticket_len;
    (void)endpoint_type;
    NOT_PORTED("session fields");
    return -1;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_SSL_TLS_C */
