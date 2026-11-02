/* ssl_test.c
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

/* Return codes and verify results through the Mbed TLS 4.x API, with a
 * client and a server in one process, connected by memory buffers. Run from
 * framework/data_files in an Mbed TLS checkout. */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <psa/crypto.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#define CA_FILE   "test-ca2.crt"
#define CERT_FILE "server5.crt"
#define KEY_FILE  "server5.key"
/* The CN of server5.crt */
#define HOST_NAME "localhost"
/* Handshake steps for each side */
#define MAX_STEPS 20

/* Data in one direction. closed is set by the writer. */
typedef struct {
    unsigned char buf[32768];
    size_t len;
    int closed;
} Pipe;

typedef struct {
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    Pipe* rx;
    Pipe* tx;
} Peer;

static mbedtls_x509_crt ca;
static mbedtls_x509_crt cert;
static mbedtls_pk_context key;
static Pipe toClient;
static Pipe toServer;
static Peer cli;
static Peer srv;

static int PipeSend(void* ctx, const unsigned char* buf, size_t len)
{
    Pipe* p = ((Peer*)ctx)->tx;

    if (len > sizeof(p->buf) - p->len) {
        len = sizeof(p->buf) - p->len;
    }
    if (len == 0) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    memcpy(p->buf + p->len, buf, len);
    p->len += len;
    return (int)len;
}

static int PipeRecv(void* ctx, unsigned char* buf, size_t len)
{
    Pipe* p = ((Peer*)ctx)->rx;

    if (p->len == 0) {
        return p->closed ? 0 : MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (len > p->len) {
        len = p->len;
    }
    memcpy(buf, p->buf, len);
    memmove(p->buf, p->buf + len, p->len - len);
    p->len -= len;
    return (int)len;
}

/* A client sets host, NULL included, unless setHost is 0 */
static int PeerNew(Peer* p, int endpoint, int authmode, int setHost,
    const char* host)
{
    int ret;

    mbedtls_ssl_config_init(&p->conf);
    mbedtls_ssl_init(&p->ssl);
    p->rx = (endpoint == MBEDTLS_SSL_IS_CLIENT) ? &toClient : &toServer;
    p->tx = (endpoint == MBEDTLS_SSL_IS_CLIENT) ? &toServer : &toClient;
    memset(p->tx, 0, sizeof(*p->tx));

    ret = mbedtls_ssl_config_defaults(&p->conf, endpoint,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret == 0) {
        mbedtls_ssl_conf_authmode(&p->conf, authmode);
        mbedtls_ssl_conf_ca_chain(&p->conf, &ca, NULL);
        if (endpoint == MBEDTLS_SSL_IS_SERVER) {
            ret = mbedtls_ssl_conf_own_cert(&p->conf, &cert, &key);
        }
    }
    if (ret == 0) {
        ret = mbedtls_ssl_setup(&p->ssl, &p->conf);
    }
    if (ret == 0 && setHost) {
        ret = mbedtls_ssl_set_hostname(&p->ssl, host);
    }
    mbedtls_ssl_set_bio(&p->ssl, p, PipeSend, PipeRecv, NULL);
    return ret;
}

static void PeerFree(Peer* p)
{
    mbedtls_ssl_free(&p->ssl);
    mbedtls_ssl_config_free(&p->conf);
}

static int Waiting(int ret)
{
    return ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE;
}

/* The client's result. *srvRet gets the server's. */
static int Handshake(int* srvRet)
{
    int c = MBEDTLS_ERR_SSL_WANT_READ;
    int s = MBEDTLS_ERR_SSL_WANT_READ;
    int i;

    for (i = 0; i < MAX_STEPS && (Waiting(c) || Waiting(s)); i++) {
        if (Waiting(c)) {
            c = mbedtls_ssl_handshake(&cli.ssl);
        }
        if (Waiting(s)) {
            s = mbedtls_ssl_handshake(&srv.ssl);
        }
    }
    *srvRet = s;
    return c;
}

/* Connects a client with VERIFY_REQUIRED and HOST_NAME */
static int Connect(int srvAuthmode)
{
    int s;

    if (PeerNew(&cli, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_VERIFY_REQUIRED, 1,
            HOST_NAME) != 0 ||
            PeerNew(&srv, MBEDTLS_SSL_IS_SERVER, srvAuthmode, 0, NULL) != 0) {
        return -1;
    }
    return (Handshake(&s) == 0 && s == 0) ? 0 : -1;
}

static int NoClientCertOptional(void)
{
    int ok = Connect(MBEDTLS_SSL_VERIFY_OPTIONAL) == 0 &&
        mbedtls_ssl_get_verify_result(&cli.ssl) == 0 &&
        mbedtls_ssl_get_verify_result(&srv.ssl) ==
            MBEDTLS_X509_BADCERT_MISSING;

    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

static int NoClientCertRequired(void)
{
    int s = 0;
    int ok = PeerNew(&cli, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_VERIFY_REQUIRED,
            1, HOST_NAME) == 0 &&
        PeerNew(&srv, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_VERIFY_REQUIRED, 0,
            NULL) == 0;

    if (ok) {
        (void)Handshake(&s);
        ok = s == MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
    }
    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

/* setHost 0 leaves the host name unset */
static int ClientHost(int setHost, const char* first, const char* host,
    int want)
{
    int s;
    int ok = PeerNew(&cli, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_VERIFY_REQUIRED,
            setHost, first) == 0 &&
        PeerNew(&srv, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_VERIFY_NONE, 0,
            NULL) == 0;

    if (ok && setHost) {
        ok = mbedtls_ssl_set_hostname(&cli.ssl, host) == 0;
    }
    if (ok) {
        ok = Handshake(&s) == want;
    }
    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

static int HostNotSet(void)
{
    return ClientHost(0, NULL, NULL,
        MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME);
}

static int HostCleared(void)
{
    return ClientHost(1, "wrong.example.org", NULL, 0);
}

static int HostReplaced(void)
{
    return ClientHost(1, "wrong.example.org", HOST_NAME, 0);
}

static int HostWrong(void)
{
    return ClientHost(1, HOST_NAME, "wrong.example.org",
        MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
}

static int ReadWrite(void)
{
    unsigned char buf[16];
    int ok = Connect(MBEDTLS_SSL_VERIFY_NONE) == 0 &&
        mbedtls_ssl_write(&cli.ssl, (const unsigned char*)"hello", 5) == 5 &&
        mbedtls_ssl_read(&srv.ssl, buf, sizeof(buf)) == 5 &&
        memcmp(buf, "hello", 5) == 0;

    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

static int WriteZero(void)
{
    int ok = Connect(MBEDTLS_SSL_VERIFY_NONE) == 0 &&
        mbedtls_ssl_write(&cli.ssl, (const unsigned char*)"", 0) == 0;

    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

/* The transport ends without close_notify */
static int ReadEof(void)
{
    unsigned char buf[16];
    int ok = Connect(MBEDTLS_SSL_VERIFY_NONE) == 0;

    if (ok) {
        toClient.closed = 1;
        ok = mbedtls_ssl_read(&cli.ssl, buf, sizeof(buf)) == 0;
    }
    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

static int ReadCloseNotify(void)
{
    unsigned char buf[16];
    int ok = Connect(MBEDTLS_SSL_VERIFY_NONE) == 0 &&
        mbedtls_ssl_close_notify(&srv.ssl) == 0 &&
        mbedtls_ssl_read(&cli.ssl, buf, sizeof(buf)) ==
            MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;

    PeerFree(&cli);
    PeerFree(&srv);
    return ok;
}

/* A conf_* failure after mbedtls_ssl_setup */
static int ResetConfError(void)
{
    /* Not read: any CRL is refused */
    mbedtls_x509_crl* crl = (mbedtls_x509_crl*)&ca;
    int ok = PeerNew(&srv, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_VERIFY_NONE, 0,
        NULL) == 0;

    if (ok) {
        mbedtls_ssl_conf_ca_chain(&srv.conf, &ca, crl);
        ok = mbedtls_ssl_session_reset(&srv.ssl) ==
            MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    PeerFree(&srv);
    return ok;
}

/* wolfSSL's own code for a key it refuses is not returned */
static int OwnKeyTooSmall(void)
{
    mbedtls_pk_context small;
    int ok;

    mbedtls_pk_init(&small);
    mbedtls_ssl_config_init(&srv.conf);
    ok = mbedtls_pk_parse_keyfile(&small, "rsa_pkcs1_768_clear.der",
            NULL) == 0 &&
        mbedtls_ssl_config_defaults(&srv.conf, MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
        mbedtls_ssl_conf_own_cert(&srv.conf, &cert, &small) ==
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    mbedtls_ssl_config_free(&srv.conf);
    mbedtls_pk_free(&small);
    return ok;
}

static int AcceptWouldBlock(void)
{
    mbedtls_net_context bound;
    mbedtls_net_context client;
    int ok;

    mbedtls_net_init(&bound);
    mbedtls_net_init(&client);
    ok = mbedtls_net_bind(&bound, "127.0.0.1", "0",
            MBEDTLS_NET_PROTO_TCP) == 0 &&
        fcntl(bound.fd, F_SETFL, fcntl(bound.fd, F_GETFL) | O_NONBLOCK) ==
            0 &&
        mbedtls_net_accept(&bound, &client, NULL, 0, NULL) ==
            MBEDTLS_ERR_SSL_WANT_READ;
    mbedtls_net_free(&client);
    mbedtls_net_free(&bound);
    return ok;
}

static const struct {
    const char* name;
    int (*test)(void);
} cases[] = {
    { "no client certificate, OPTIONAL", NoClientCertOptional },
    { "no client certificate, REQUIRED", NoClientCertRequired },
    { "host name not set", HostNotSet },
    { "host name cleared", HostCleared },
    { "host name replaced", HostReplaced },
    { "wrong host name", HostWrong },
    { "write and read", ReadWrite },
    { "zero-length write", WriteZero },
    { "EOF without close_notify", ReadEof },
    { "close_notify", ReadCloseNotify },
    { "session reset after a conf error", ResetConfError },
    { "own key too small", OwnKeyTooSmall },
    { "accept would block", AcceptWouldBlock }
};

int main(void)
{
    size_t i;
    int fails = 0;

    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);
    if (psa_crypto_init() != PSA_SUCCESS ||
            mbedtls_x509_crt_parse_file(&ca, CA_FILE) != 0 ||
            mbedtls_x509_crt_parse_file(&cert, CERT_FILE) != 0 ||
            mbedtls_pk_parse_keyfile(&key, KEY_FILE, NULL) != 0) {
        printf("FAIL: loading %s, %s and %s\n", CA_FILE, CERT_FILE, KEY_FILE);
        return 1;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].test()) {
            printf("PASS: %s\n", cases[i].name);
        }
        else {
            printf("FAIL: %s\n", cases[i].name);
            fails++;
        }
    }
    mbedtls_pk_free(&key);
    mbedtls_x509_crt_free(&cert);
    mbedtls_x509_crt_free(&ca);
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
