/* mbedtls_compat.c
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

/* Mbed TLS 4.x TLS, X.509 and network API on wolfSSL (MBEDTLS_COMPAT=1). */

/* getaddrinfo() with -std=c99 */
#if defined(WOLFPSA_MBEDTLS_COMPAT) && !defined(_POSIX_C_SOURCE)
    #define _POSIX_C_SOURCE 200112L
#endif /* WOLFPSA_MBEDTLS_COMPAT && !_POSIX_C_SOURCE */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#if defined(USE_WOLFSSL_IO) && !defined(USE_WINDOWS_API)
    #include <netdb.h>
    #include <signal.h>
    #include <sys/select.h>
#endif /* USE_WOLFSSL_IO && !USE_WINDOWS_API */

#if defined(WOLFCRYPT_ONLY) || !defined(HAVE_SNI)
    #error "wolfPSA: MBEDTLS_COMPAT needs wolfSSL TLS with SNI"
#endif /* WOLFCRYPT_ONLY || !HAVE_SNI */

enum {
    MBED_IO_RECV = 0,
    MBED_IO_SEND = 1
};

/* Unknown codes map to the last entry */
static int MbedIoErr(int code, int dir, int toWolf)
{
    static const struct {
        int wolf;
        int mbed[2];
    } map[] = {
        { WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_READ),
            { MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE } },
        { WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_CONN_RST),
            { MBEDTLS_ERR_NET_CONN_RESET, MBEDTLS_ERR_NET_CONN_RESET } },
        /* A receive of 0 bytes is EOF */
        { WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_CONN_CLOSE),
            { 0, MBEDTLS_ERR_NET_CONN_RESET } },
        { WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_TIMEOUT),
            { MBEDTLS_ERR_SSL_TIMEOUT, MBEDTLS_ERR_SSL_TIMEOUT } },
        { WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_ISR),
            { MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE } },
        { WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_GENERAL),
            { MBEDTLS_ERR_NET_RECV_FAILED, MBEDTLS_ERR_NET_SEND_FAILED } }
    };
    const size_t last = XELEM_CNT(map) - 1;
    size_t i;

    if (toWolf) {
        /* Translate Mbed TLS error to wolfSSL error */
        for (i = 0; i < last; i++) {
            if (map[i].mbed[dir] == code) {
                break;
            }
        }
        return map[i].wolf;
    }

    /* wolfSSL error to Mbed TLS */
    for (i = 0; i < last; i++) {
        if (map[i].wolf == code) {
            break;
        }
    }
    return map[i].mbed[dir];
}

/* Map the wolfSSL error behind a failed call to an Mbed TLS return code */
static int MbedSslErr(const mbedtls_ssl_context* ssl, int ret)
{
    static const struct {
        int wolf;
        int mbed;
    } map[] = {
        { WOLFSSL_ERROR_WANT_READ, MBEDTLS_ERR_SSL_WANT_READ },
        { WOLFSSL_ERROR_WANT_WRITE, MBEDTLS_ERR_SSL_WANT_WRITE },
        { WOLFSSL_ERROR_ZERO_RETURN, MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY },
        { WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E), MBEDTLS_ERR_SSL_CONN_EOF }
    };
    int err = wolfSSL_get_error(ssl->ssl, ret);
    size_t i;

    /* A failed verify with VERIFY_REQUIRED is what ended the handshake */
    if (ssl->verify_flags != 0 &&
            ssl->authmode == MBEDTLS_SSL_VERIFY_REQUIRED) {
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    }
    for (i = 0; i < XELEM_CNT(map); i++) {
        if (map[i].wolf == err) {
            return map[i].mbed;
        }
    }
    /* A positive code would read as a byte count */
    return (err < 0) ? err : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/* WOLFSSL_SUCCESS becomes 0, wolfSSL error codes are kept */
static int MbedRet(int ret, int fallback)
{
    if (ret == WOLFSSL_SUCCESS) {
        return 0;
    }
    return (ret < 0) ? ret : fallback;
}

static void MbedConfErr(mbedtls_ssl_config* conf, int err)
{
    if (conf->err == 0) {
        conf->err = err;
    }
}

static int MbedRecvCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)ctx;
    int ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

    (void)ssl;
    if (s->f_recv_timeout != NULL) {
        ret = s->f_recv_timeout(s->p_bio, (unsigned char*)buf, (size_t)sz, 0);
    }
    else if (s->f_recv != NULL) {
        ret = s->f_recv(s->p_bio, (unsigned char*)buf, (size_t)sz);
    }
    if (ret > 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_RECV, 1);
}

static int MbedSendCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)ctx;
    int ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

    (void)ssl;
    if (s->f_send != NULL) {
        ret = s->f_send(s->p_bio, (const unsigned char*)buf, (size_t)sz);
    }
    if (ret > 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_SEND, 1);
}

/* Unknown codes map to the last entry */
static uint32_t MbedVerifyFlag(int err)
{
    static const struct {
        int wolf;
        uint32_t mbed;
    } map[] = {
        { WC_NO_ERR_TRACE(ASN_AFTER_DATE_E), MBEDTLS_X509_BADCERT_EXPIRED },
        { WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E), MBEDTLS_X509_BADCERT_FUTURE },
        { WC_NO_ERR_TRACE(ASN_NO_SIGNER_E), MBEDTLS_X509_BADCERT_NOT_TRUSTED },
        { WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E),
            MBEDTLS_X509_BADCERT_NOT_TRUSTED },
        { WC_NO_ERR_TRACE(DOMAIN_NAME_MISMATCH),
            MBEDTLS_X509_BADCERT_CN_MISMATCH },
        { WC_NO_ERR_TRACE(IPADDR_MISMATCH), MBEDTLS_X509_BADCERT_CN_MISMATCH },
        { WC_NO_ERR_TRACE(CRL_CERT_REVOKED), MBEDTLS_X509_BADCERT_REVOKED },
        { WC_NO_ERR_TRACE(OCSP_CERT_REVOKED), MBEDTLS_X509_BADCERT_REVOKED },
        { WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR), MBEDTLS_X509_BADCRL_EXPIRED },
        { WC_NO_ERR_TRACE(KEYUSE_SIGNATURE_E),
            MBEDTLS_X509_BADCERT_KEY_USAGE },
        { WC_NO_ERR_TRACE(KEYUSE_ENCIPHER_E), MBEDTLS_X509_BADCERT_KEY_USAGE },
        { WC_NO_ERR_TRACE(EXTKEYUSE_AUTH_E),
            MBEDTLS_X509_BADCERT_EXT_KEY_USAGE },
        { WC_NO_ERR_TRACE(RSA_KEY_SIZE_E), MBEDTLS_X509_BADCERT_BAD_KEY },
        { WC_NO_ERR_TRACE(ECC_KEY_SIZE_E), MBEDTLS_X509_BADCERT_BAD_KEY },
        { 0, MBEDTLS_X509_BADCERT_OTHER }
    };
    const size_t last = XELEM_CNT(map) - 1;
    size_t i;

    for (i = 0; i < last; i++) {
        if (map[i].wolf == err) {
            break;
        }
    }
    return map[i].mbed;
}

/* Records each failure; VERIFY_OPTIONAL then continues the handshake */
static int MbedVerifyCb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)store->userCtx;

    if (!preverify) {
        s->verify_flags |= MbedVerifyFlag(store->error);
    }
    return preverify || s->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL;
}

static int MbedCrtErr(int ret)
{
    return (ret == WC_NO_ERR_TRACE(MEMORY_E)) ? MBEDTLS_ERR_X509_ALLOC_FAILED :
        MBEDTLS_ERR_X509_INVALID_FORMAT;
}

/* No signature or date checks. *len becomes the length without any data
 * that follows the certificate. */
static int MbedCrtCheck(const unsigned char* buf, size_t* len)
{
    DecodedCert* cert;
    word32 idx = 0;
    int seqLen;
    int ret;

    if (GetSequence(buf, &idx, &seqLen, (word32)*len) < 0) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    *len = idx + (word32)seqLen;
    cert = (DecodedCert*)XMALLOC(sizeof(*cert), NULL, DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    wc_InitDecodedCert(cert, buf, (word32)*len, NULL);
    ret = wc_ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL);
    wc_FreeDecodedCert(cert);
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);

    return (ret == 0) ? 0 : MbedCrtErr(ret);
}

void mbedtls_net_init(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_init");

    if (ctx != NULL) {
        ctx->fd = -1;
    }
}

#ifdef USE_WOLFSSL_IO
static int MbedNetBind(int fd, const struct addrinfo* ai, int proto)
{
    int on = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on,
            (XSOCKLENT)sizeof(on)) != 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
    if (bind(fd, ai->ai_addr, (XSOCKLENT)ai->ai_addrlen) != 0) {
        return MBEDTLS_ERR_NET_BIND_FAILED;
    }
    if (proto == MBEDTLS_NET_PROTO_TCP &&
            listen(fd, MBEDTLS_NET_LISTEN_BACKLOG) != 0) {
        return MBEDTLS_ERR_NET_LISTEN_FAILED;
    }
    return 0;
}

/* Connects to host, or binds to it when server is set. A server with no
 * host binds to every address. */
static int MbedNetOpen(mbedtls_net_context* ctx, const char* host,
    const char* port, int proto, int server)
{
    struct addrinfo hints;
    struct addrinfo* list = NULL;
    struct addrinfo* ai;
    int ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;

    if (ctx == NULL || (host == NULL && !server) || port == NULL) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    XMEMSET(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (proto == MBEDTLS_NET_PROTO_UDP) {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else {
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }
    if (host == NULL) {
        hints.ai_flags = AI_PASSIVE;
    }

#ifndef USE_WINDOWS_API
    /* As in Mbed TLS: a send to a closed peer fails instead of ending the
     * process */
    (void)signal(SIGPIPE, SIG_IGN);
#endif /* !USE_WINDOWS_API */

    if (getaddrinfo(host, port, &hints, &list) != 0) {
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;
    }

    for (ai = list; ai != NULL; ai = ai->ai_next) {
        ctx->fd = (int)socket(ai->ai_family, ai->ai_socktype,
            ai->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }
        if (server) {
            ret = MbedNetBind(ctx->fd, ai, proto);
        }
        else if (connect(ctx->fd, ai->ai_addr,
                (XSOCKLENT)ai->ai_addrlen) == 0) {
            ret = 0;
        }
        else {
            ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
        }
        if (ret == 0) {
            break;
        }
        CloseSocket(ctx->fd);
        ctx->fd = -1;
    }

    freeaddrinfo(list);
    return ret;
}

int mbedtls_net_connect(mbedtls_net_context* ctx, const char* host,
    const char* port, int proto)
{
    WOLFSSL_ENTER("mbedtls_net_connect");

    return MbedNetOpen(ctx, host, port, proto, 0);
}

int mbedtls_net_bind(mbedtls_net_context* ctx, const char* bind_ip,
    const char* port, int proto)
{
    WOLFSSL_ENTER("mbedtls_net_bind");

    return MbedNetOpen(ctx, bind_ip, port, proto, 1);
}

/* TCP only. client_ip gets the 4 or 16 bytes of the client's address. */
int mbedtls_net_accept(mbedtls_net_context* bind_ctx,
    mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size,
    size_t* cip_len)
{
    struct sockaddr_storage addr;
    XSOCKLENT addrLen = (XSOCKLENT)sizeof(addr);
    const void* ip;
    size_t ipLen;

    WOLFSSL_ENTER("mbedtls_net_accept");

    if (bind_ctx == NULL || client_ctx == NULL || bind_ctx->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    client_ctx->fd = (int)accept(bind_ctx->fd, (struct sockaddr*)&addr,
        &addrLen);
    if (client_ctx->fd < 0) {
        return MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }
    if (client_ip == NULL) {
        return 0;
    }

    if (addr.ss_family == AF_INET) {
        ip = &((struct sockaddr_in*)&addr)->sin_addr;
        ipLen = sizeof(struct in_addr);
    }
    else {
        ip = &((struct sockaddr_in6*)&addr)->sin6_addr;
        ipLen = sizeof(struct in6_addr);
    }
    *cip_len = ipLen;
    if (buf_size < ipLen) {
        return MBEDTLS_ERR_NET_BUFFER_TOO_SMALL;
    }
    XMEMCPY(client_ip, ip, ipLen);
    return 0;
}

void mbedtls_net_usleep(unsigned long usec)
{
    WOLFSSL_ENTER("mbedtls_net_usleep");

#ifdef USE_WINDOWS_API
    Sleep((DWORD)((usec + 999) / 1000));
#else
    struct timeval tv;

    tv.tv_sec = (time_t)(usec / 1000000);
    tv.tv_usec = (suseconds_t)(usec % 1000000);
    (void)select(0, NULL, NULL, NULL, &tv);
#endif /* USE_WINDOWS_API */
}

void mbedtls_net_close(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_close");

    if (ctx != NULL && ctx->fd >= 0) {
        CloseSocket(ctx->fd);
        ctx->fd = -1;
    }
}

/* Also ends the connection for a forked process that shares the socket */
void mbedtls_net_free(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_free");

    if (ctx != NULL && ctx->fd >= 0) {
        (void)shutdown(ctx->fd, 2);
    }
    mbedtls_net_close(ctx);
}

int mbedtls_net_recv(void* ctx, unsigned char* buf, size_t len)
{
    mbedtls_net_context* net = (mbedtls_net_context*)ctx;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_recv");

    if (net == NULL || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    ret = wolfIO_Recv(net->fd, (char*)buf, (int)len, 0);
    if (ret >= 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_RECV, 0);
}

int mbedtls_net_send(void* ctx, const unsigned char* buf, size_t len)
{
    mbedtls_net_context* net = (mbedtls_net_context*)ctx;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_send");

    if (net == NULL || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    ret = wolfIO_Send(net->fd, (char*)(wc_ptr_t)buf, (int)len, 0);
    if (ret >= 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_SEND, 0);
}
#endif /* USE_WOLFSSL_IO */

void mbedtls_x509_crt_init(mbedtls_x509_crt* crt)
{
    WOLFSSL_ENTER("mbedtls_x509_crt_init");

    if (crt != NULL) {
        XMEMSET(crt, 0, sizeof(*crt));
    }
}

void mbedtls_x509_crt_free(mbedtls_x509_crt* crt)
{
    mbedtls_x509_crt* cur = crt;
    mbedtls_x509_crt* next;

    WOLFSSL_ENTER("mbedtls_x509_crt_free");

    while (cur != NULL) {
        next = cur->next;
        XFREE(cur->raw.p, NULL, DYNAMIC_TYPE_CERT);
        if (cur != crt) {
            XFREE(cur, NULL, DYNAMIC_TYPE_X509);
        }
        cur = next;
    }
    if (crt != NULL) {
        XMEMSET(crt, 0, sizeof(*crt));
    }
}

/* The number that failed if any parsed, else an error. Input without a PEM
 * header is DER, and PEM need not end with a NUL. */
int mbedtls_x509_crt_parse(mbedtls_x509_crt* chain,
    const unsigned char* buf, size_t buflen)
{
    const unsigned char* pem = buf;
    size_t len = buflen;
    EncryptedInfo info;
    DerBuffer* der;
    int parsed = 0;
    int failed = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse");

    if (chain == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    while (len > 0) {
        der = NULL;
        XMEMSET(&info, 0, sizeof(info));
        ret = wc_PemToDer(pem, (long)len, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
            break;
        }
        if (ret == 0) {
            ret = mbedtls_x509_crt_parse_der(chain, der->buffer,
                der->length);
        }
        else {
            ret = MbedCrtErr(ret);
        }
        wc_FreeDer(&der);
        if (ret == MBEDTLS_ERR_X509_ALLOC_FAILED) {
            return ret;
        }
        if (ret == 0) {
            parsed++;
        }
        else {
            failed++;
        }
        /* Set once the footer is found, also when the block does not decode */
        if (info.consumed <= 0 || (size_t)info.consumed > len) {
            break;
        }
        pem += info.consumed;
        len -= (size_t)info.consumed;
    }

    if (parsed > 0) {
        ret = failed;
    }
    else if (failed > 0) {
        ret = MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    else {
        ret = mbedtls_x509_crt_parse_der(chain, buf, buflen);
    }
    return ret;
}

int mbedtls_x509_crt_parse_der(mbedtls_x509_crt* chain,
    const unsigned char* buf, size_t buflen)
{
    mbedtls_x509_crt* crt = chain;
    unsigned char* copy;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_der");

    if (chain == NULL || buf == NULL || (word32)buflen != buflen) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    ret = MbedCrtCheck(buf, &buflen);
    if (ret != 0) {
        return ret;
    }

    copy = (unsigned char*)XMALLOC(buflen, NULL, DYNAMIC_TYPE_CERT);
    if (copy == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    XMEMCPY(copy, buf, buflen);

    while (crt->next != NULL) {
        crt = crt->next;
    }

    if (crt->raw.p != NULL) {
        crt->next = (mbedtls_x509_crt*)XMALLOC(sizeof(*crt), NULL,
            DYNAMIC_TYPE_X509);
        if (crt->next == NULL) {
            XFREE(copy, NULL, DYNAMIC_TYPE_CERT);
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
        crt = crt->next;
        XMEMSET(crt, 0, sizeof(*crt));
    }

    crt->raw.p = copy;
    crt->raw.len = buflen;
    return 0;
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_x509_crt_parse_file(mbedtls_x509_crt* chain, const char* path)
{
    byte* buf = NULL;
    size_t len = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_file");

    if (wc_FileLoad(path, &buf, &len, NULL) != 0) {
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
    ret = mbedtls_x509_crt_parse(chain, buf, len);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* MBEDTLS_FS_IO */

void mbedtls_ssl_config_init(mbedtls_ssl_config* conf)
{
    WOLFSSL_ENTER("mbedtls_ssl_config_init");

    if (conf != NULL) {
        XMEMSET(conf, 0, sizeof(*conf));
    }
}

void mbedtls_ssl_config_free(mbedtls_ssl_config* conf)
{
    WOLFSSL_ENTER("mbedtls_ssl_config_free");

    if (conf != NULL) {
        wolfSSL_CTX_free(conf->ctx);
        XMEMSET(conf, 0, sizeof(*conf));
    }
}

void mbedtls_ssl_conf_authmode(mbedtls_ssl_config* conf, int authmode)
{
    static const int modes[] = {
        WOLFSSL_VERIFY_NONE,
        WOLFSSL_VERIFY_PEER,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
    };

    WOLFSSL_ENTER("mbedtls_ssl_conf_authmode");

    if (conf == NULL) {
        return;
    }
    if (conf->ctx == NULL || authmode < MBEDTLS_SSL_VERIFY_NONE ||
            authmode > MBEDTLS_SSL_VERIFY_REQUIRED) {
        MbedConfErr(conf, MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        return;
    }
    conf->authmode = authmode;
    wolfSSL_CTX_set_verify(conf->ctx, modes[authmode], MbedVerifyCb);
}

int mbedtls_ssl_config_defaults(mbedtls_ssl_config* conf,
    int endpoint, int transport, int preset)
{
    static const struct {
        int endpoint;
        int transport;
        WOLFSSL_METHOD* (*method)(void);
    } methods[] = {
    #ifndef NO_WOLFSSL_CLIENT
        { MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
            wolfTLS_client_method },
    #endif /* !NO_WOLFSSL_CLIENT */
    #ifndef NO_WOLFSSL_SERVER
        { MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
            wolfTLS_server_method },
    #endif /* !NO_WOLFSSL_SERVER */
    #if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT)
        { MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
            wolfDTLS_client_method },
    #endif /* WOLFSSL_DTLS && !NO_WOLFSSL_CLIENT */
    #if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
        { MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
            wolfDTLS_server_method },
    #endif /* WOLFSSL_DTLS && !NO_WOLFSSL_SERVER */
    };
    size_t i;

    WOLFSSL_ENTER("mbedtls_ssl_config_defaults");

    if (conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    for (i = 0; i < XELEM_CNT(methods); i++) {
        if (methods[i].endpoint == endpoint &&
                methods[i].transport == transport) {
            break;
        }
    }
    if (i == XELEM_CNT(methods) || preset != MBEDTLS_SSL_PRESET_DEFAULT) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    wolfSSL_CTX_free(conf->ctx);
    conf->err = 0;
    conf->ctx = wolfSSL_CTX_new(methods[i].method());
    if (conf->ctx == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    mbedtls_ssl_conf_authmode(conf,
        (endpoint == MBEDTLS_SSL_IS_CLIENT) ? MBEDTLS_SSL_VERIFY_REQUIRED :
        MBEDTLS_SSL_VERIFY_NONE);
    return 0;
}

void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config* conf,
    mbedtls_x509_crt* ca_chain, mbedtls_x509_crl* ca_crl)
{
    int ret = (ca_crl == NULL) ? 0 : MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    WOLFSSL_ENTER("mbedtls_ssl_conf_ca_chain");

    if (conf == NULL) {
        return;
    }

    if (ret == 0) {
        ret = MbedRet(wolfSSL_CTX_UnloadCAs(conf->ctx),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }

    /* Mbed TLS checks a CA only when it is used, so a CA that wolfSSL
     * rejects on load, such as an expired one, is left out */
    for (; ret == 0 && ca_chain != NULL; ca_chain = ca_chain->next) {
        if (ca_chain->raw.p != NULL &&
                wolfSSL_CTX_load_verify_buffer(conf->ctx, ca_chain->raw.p,
                    (long)ca_chain->raw.len, WOLFSSL_FILETYPE_ASN1) ==
                WC_NO_ERR_TRACE(MEMORY_E)) {
            ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
    }

    if (ret != 0) {
        MbedConfErr(conf, ret);
    }
}

/* Mbed TLS sends every certificate in own_cert. A second call replaces the
 * first, where Mbed TLS keeps both and picks one per handshake. */
int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config* conf,
    mbedtls_x509_crt* own_cert, mbedtls_pk_context* pk_key)
{
    const mbedtls_x509_crt* crt;
    unsigned char* chain;
    size_t len = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_conf_own_cert");

    if (conf == NULL || conf->ctx == NULL || own_cert == NULL ||
            own_cert->raw.p == NULL || pk_key == NULL || pk_key->der == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    for (crt = own_cert; crt != NULL; crt = crt->next) {
        len += crt->raw.len;
    }
    chain = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (chain == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    len = 0;
    for (crt = own_cert; crt != NULL; crt = crt->next) {
        XMEMCPY(chain + len, crt->raw.p, crt->raw.len);
        len += crt->raw.len;
    }

    ret = MbedRet(wolfSSL_CTX_use_certificate_chain_buffer_format(conf->ctx,
        chain, (long)len, WOLFSSL_FILETYPE_ASN1),
        MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    XFREE(chain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret == 0) {
        ret = MbedRet(wolfSSL_CTX_use_PrivateKey_buffer(conf->ctx,
            pk_key->der, (long)pk_key->der_len, WOLFSSL_FILETYPE_ASN1),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    return ret;
}

/* Without MBEDTLS_DEBUG_C, Mbed TLS never calls f_dbg either */
void mbedtls_ssl_conf_dbg(mbedtls_ssl_config* conf,
    void (*f_dbg)(void*, int, const char*, int, const char*), void* p_dbg)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_dbg");

    (void)conf;
    (void)f_dbg;
    (void)p_dbg;
}

void mbedtls_ssl_init(mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_init");

    if (ssl != NULL) {
        XMEMSET(ssl, 0, sizeof(*ssl));
    }
}

void mbedtls_ssl_free(mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_free");

    if (ssl != NULL) {
        wolfSSL_free(ssl->ssl);
        XFREE(ssl->hostname, NULL, DYNAMIC_TYPE_DOMAIN);
        XMEMSET(ssl, 0, sizeof(*ssl));
    }
}

static int MbedSetHostname(WOLFSSL* ssl, const char* hostname)
{
    int ret = 0;

    if (hostname == NULL) {
        return 0;
    }
#ifdef HAVE_SNI
    ret = MbedRet(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, hostname,
        (word16)XSTRLEN(hostname)), MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
#endif /* HAVE_SNI */
    if (ret == 0) {
        ret = MbedRet(wolfSSL_check_domain_name(ssl, hostname),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    return ret;
}

/* A new WOLFSSL from the config, with this context's callbacks and host
 * name */
static int MbedSslNew(mbedtls_ssl_context* ssl)
{
    ssl->ssl = wolfSSL_new(ssl->conf->ctx);
    if (ssl->ssl == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    ssl->authmode = ssl->conf->authmode;
    ssl->verify_flags = 0;
    wolfSSL_SSLSetIORecv(ssl->ssl, MbedRecvCb);
    wolfSSL_SSLSetIOSend(ssl->ssl, MbedSendCb);
    wolfSSL_SetIOReadCtx(ssl->ssl, ssl);
    wolfSSL_SetIOWriteCtx(ssl->ssl, ssl);
    wolfSSL_SetCertCbCtx(ssl->ssl, ssl);
    return MbedSetHostname(ssl->ssl, ssl->hostname);
}

int mbedtls_ssl_setup(mbedtls_ssl_context* ssl, const mbedtls_ssl_config* conf)
{
    WOLFSSL_ENTER("mbedtls_ssl_setup");

    if (ssl == NULL || conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (conf->err != 0) {
        return conf->err;
    }
    if (conf->ctx == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->conf = conf;
    return MbedSslNew(ssl);
}

/* conf_* calls made since mbedtls_ssl_setup take effect here */
int mbedtls_ssl_session_reset(mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_session_reset");

    if (ssl == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    wolfSSL_free(ssl->ssl);
    return MbedSslNew(ssl);
}

void mbedtls_ssl_set_bio(mbedtls_ssl_context* ssl, void* p_bio,
    mbedtls_ssl_send_t* f_send, mbedtls_ssl_recv_t* f_recv,
    mbedtls_ssl_recv_timeout_t* f_recv_timeout)
{
    WOLFSSL_ENTER("mbedtls_ssl_set_bio");

    if (ssl != NULL) {
        ssl->p_bio = p_bio;
        ssl->f_send = f_send;
        ssl->f_recv = f_recv;
        ssl->f_recv_timeout = f_recv_timeout;
    }
}

/* Before mbedtls_ssl_setup too, as in Mbed TLS */
int mbedtls_ssl_set_hostname(mbedtls_ssl_context* ssl, const char* hostname)
{
    char* copy = NULL;
    size_t len;
    int ret = 0;

    WOLFSSL_ENTER("mbedtls_ssl_set_hostname");

    if (ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (hostname != NULL) {
        len = XSTRLEN(hostname);
        if (len > MBEDTLS_SSL_MAX_HOST_NAME_LEN) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (ssl->ssl != NULL) {
            ret = MbedSetHostname(ssl->ssl, hostname);
        }
        if (ret == 0) {
            copy = (char*)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_DOMAIN);
            if (copy == NULL) {
                ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }
        }
        if (ret == 0) {
            XMEMCPY(copy, hostname, len + 1);
        }
    }
    if (ret == 0) {
        XFREE(ssl->hostname, NULL, DYNAMIC_TYPE_DOMAIN);
        ssl->hostname = copy;
    }
    return ret;
}

int mbedtls_ssl_handshake(mbedtls_ssl_context* ssl)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_handshake");

    if (ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = wolfSSL_negotiate(ssl->ssl);
    return (ret == WOLFSSL_SUCCESS) ? 0 : MbedSslErr(ssl, ret);
}

/* All ones while no result is available, as in Mbed TLS */
uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_get_verify_result");

    if (ssl == NULL || ssl->ssl == NULL) {
        return 0xFFFFFFFF;
    }
    if (ssl->verify_flags != 0) {
        return ssl->verify_flags;
    }
    if (!wolfSSL_is_init_finished(ssl->ssl)) {
        return 0xFFFFFFFF;
    }
    return (ssl->authmode == MBEDTLS_SSL_VERIFY_NONE) ?
        MBEDTLS_X509_BADCERT_SKIP_VERIFY : 0;
}

/* The IANA name, such as TLS_AES_128_GCM_SHA256, where Mbed TLS has its own,
 * TLS1-3-AES-128-GCM-SHA256 */
const char* mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_get_ciphersuite");

    if (ssl == NULL || ssl->ssl == NULL) {
        return NULL;
    }
    return wolfSSL_get_cipher(ssl->ssl);
}

int mbedtls_ssl_read(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_read");

    if (ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = wolfSSL_read(ssl->ssl, buf, (int)len);
    return (ret > 0) ? ret : MbedSslErr(ssl, ret);
}

int mbedtls_ssl_write(mbedtls_ssl_context* ssl,
    const unsigned char* buf, size_t len)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_write");

    if (ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = wolfSSL_write(ssl->ssl, buf, (int)len);
    return (ret > 0) ? ret : MbedSslErr(ssl, ret);
}

/* Mbed TLS sends close_notify without waiting for the peer's reply */
int mbedtls_ssl_close_notify(mbedtls_ssl_context* ssl)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_close_notify");

    if (ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = wolfSSL_shutdown(ssl->ssl);
    if (ret == WOLFSSL_SUCCESS ||
            ret == WC_NO_ERR_TRACE(WOLFSSL_SHUTDOWN_NOT_DONE)) {
        return 0;
    }
    return MbedSslErr(ssl, ret);
}

#endif /* WOLFPSA_MBEDTLS_COMPAT */
