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

#include <string.h>

#if defined(MBEDTLS_SSL_TLS_C) && \
    defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

static int Waiting(int ret)
{
    return ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE;
}

/* The handshake state is not public. HANDSHAKE_OVER runs both handshakes
 * until mbedtls_ssl_handshake() on ssl returns 0; an earlier state stops
 * after one round. */
int mbedtls_test_move_handshake_to_state(mbedtls_ssl_context *ssl,
    mbedtls_ssl_context *second_ssl, int state)
{
    int rounds = (state == MBEDTLS_SSL_HANDSHAKE_OVER) ? 1000 : 1;
    int ret;

    if (ssl == NULL || second_ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    do {
        if (!mbedtls_ssl_is_handshake_over(second_ssl)) {
            ret = mbedtls_ssl_handshake(second_ssl);
            if (ret != 0 && !Waiting(ret)) {
                return ret;
            }
        }
        ret = mbedtls_ssl_handshake(ssl);
        if (ret != 0 && !Waiting(ret)) {
            return ret;
        }
    } while (ret != 0 && --rounds > 0);

    if (state == MBEDTLS_SSL_HANDSHAKE_OVER && ret != 0) {
        return -1;
    }
    return ret;
}

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
typedef struct {
    mbedtls_ssl_session *session; /* gets the server's session, then NULL */
    size_t ticketLen;
    int ret;
} TicketParam;

/* No public copy: a save and a load */
static int CopySession(mbedtls_ssl_session *dst,
    const mbedtls_ssl_session *src)
{
    unsigned char *buf = NULL;
    size_t len = 0;
    int ret = mbedtls_ssl_session_save(src, NULL, 0, &len);

    if (ret == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
        buf = mbedtls_calloc(1, len);
        ret = (buf == NULL) ? MBEDTLS_ERR_SSL_ALLOC_FAILED :
            mbedtls_ssl_session_save(src, buf, len, &len);
    }
    if (ret == 0) {
        ret = mbedtls_ssl_session_load(dst, buf, len);
    }
    mbedtls_free(buf);
    return ret;
}

/* A ticket of ticketLen bytes, filled as Mbed TLS's helper filled it */
static int TicketWrite(void *p_ticket, const mbedtls_ssl_session *session,
    unsigned char *start, const unsigned char *end, size_t *tlen,
    uint32_t *lifetime)
{
    TicketParam *param = (TicketParam *)p_ticket;

    if (param->session != NULL) {
        param->ret = CopySession(param->session, session);
        param->session = NULL;
    }
    if ((size_t)(end - start) < param->ticketLen) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    memset(start, 33, param->ticketLen);
    *tlen = param->ticketLen;
    *lifetime = 86401;
    return 0;
}
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
static int ReadTicket(mbedtls_ssl_context *ssl)
{
    unsigned char buf[1];
    int ret = MBEDTLS_ERR_SSL_WANT_READ;
    int i;

    for (i = 0; i < 10 && ret == MBEDTLS_ERR_SSL_WANT_READ; i++) {
        ret = mbedtls_ssl_read(ssl, buf, sizeof(buf));
    }
    return (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) ? 0 : ret;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_SESSION_TICKETS */

/* A session from a handshake on the mock transport, where Mbed TLS sets the
 * session's fields. The server's comes from the ticket callback, as
 * mbedtls_ssl_get_session() is client only. Without withCert, a PSK
 * handshake: no peer certificate. */
static int PopulateSession(mbedtls_ssl_session *session,
    mbedtls_ssl_protocol_version version, int endpoint_type,
    size_t ticketLen, int withCert)
{
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
    static uint8_t pskKey[] = "populate_session";
    data_t psk = { pskKey, sizeof(pskKey) - 1 };
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    TicketParam param = { NULL, 0, 0 };
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
    mbedtls_test_handshake_test_options options;
    mbedtls_test_ssl_endpoint client;
    mbedtls_test_ssl_endpoint server;
    int ok = 0;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    mbedtls_test_init_handshake_options(&options);
    options.client_min_version = version;
    options.client_max_version = version;
    options.server_min_version = version;
    options.server_max_version = version;
    options.expected_negotiated_version = version;
    /* server5.crt, the crt_file of the cases with a certificate */
    options.pk_alg = MBEDTLS_PK_ECDSA;
    /* The server's certificate only, and no data */
    options.srv_auth_mode = MBEDTLS_SSL_VERIFY_NONE;
    options.cli_msg_len = 0;
    options.srv_msg_len = 0;

    TEST_ASSERT(endpoint_type == MBEDTLS_SSL_IS_CLIENT ||
                endpoint_type == MBEDTLS_SSL_IS_SERVER);
    if (!withCert) {
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
        options.psk_str = &psk;
        options.cipher = "TLS-PSK-WITH-AES-128-GCM-SHA256";
#else
        TEST_FAIL("a session without a certificate needs PSK");
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */
    }

    TEST_EQUAL(mbedtls_test_ssl_endpoint_init(&client, MBEDTLS_SSL_IS_CLIENT,
                                              &options), 0);
    TEST_EQUAL(mbedtls_test_ssl_endpoint_init(&server, MBEDTLS_SSL_IS_SERVER,
                                              &options), 0);

    if (ticketLen > 0 || endpoint_type == MBEDTLS_SSL_IS_SERVER) {
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
        param.ticketLen = ticketLen;
        if (endpoint_type == MBEDTLS_SSL_IS_SERVER) {
            param.session = session;
        }
        mbedtls_ssl_conf_session_tickets_cb(&server.conf, TicketWrite,
                                            mbedtls_test_ticket_parse,
                                            &param);
#else
        TEST_FAIL("needs session tickets");
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
    }

    TEST_ASSERT(mbedtls_test_ssl_perform_connection(&options, &client,
                                                    &server));

    if (endpoint_type == MBEDTLS_SSL_IS_SERVER) {
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
        TEST_ASSERT(param.session == NULL);
        TEST_EQUAL(param.ret, 0);
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
    }
    else {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
        if (version == MBEDTLS_SSL_VERSION_TLS1_3) {
            TEST_EQUAL(ReadTicket(&client.ssl), 0);
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_SESSION_TICKETS */
        TEST_EQUAL(mbedtls_ssl_get_session(&client.ssl, session), 0);
    }
    ok = 1;

exit:
    mbedtls_test_ssl_endpoint_free(&client);
    mbedtls_test_ssl_endpoint_free(&server);
    mbedtls_test_free_handshake_options(&options);
    return ok ? 0 : -1;
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
/* crt_file is empty, NULL or server5.crt */
int mbedtls_test_ssl_tls12_populate_session(mbedtls_ssl_session *session,
    int ticket_len, int endpoint_type, const char *crt_file)
{
    return PopulateSession(session, MBEDTLS_SSL_VERSION_TLS1_2, endpoint_type,
        (size_t)ticket_len, crt_file != NULL && crt_file[0] != '\0');
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
/* A TLS 1.3 session is a ticket, so never an empty one */
int mbedtls_test_ssl_tls13_populate_session(mbedtls_ssl_session *session,
    int ticket_len, int endpoint_type)
{
    return PopulateSession(session, MBEDTLS_SSL_VERSION_TLS1_3, endpoint_type,
        (ticket_len > 0) ? (size_t)ticket_len : 1, 1);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
