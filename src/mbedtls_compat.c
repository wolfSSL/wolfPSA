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
#include "mbedtls_compat_internal.h"

#if defined(WOLFCRYPT_ONLY) || !defined(HAVE_SNI)
    #error "wolfPSA: MBEDTLS_COMPAT needs wolfSSL TLS with SNI"
#endif /* WOLFCRYPT_ONLY || !HAVE_SNI */
/* For MBEDTLS_X509_BADCERT_MISSING, see MbedVerifyCb() */
#ifndef WOLFSSL_ALWAYS_VERIFY_CB
    #error "wolfPSA: MBEDTLS_COMPAT needs WOLFSSL_ALWAYS_VERIFY_CB"
#endif /* !WOLFSSL_ALWAYS_VERIFY_CB */

/* Unknown codes map to the last entry */
int MbedIoErr(int code, int dir, int toWolf)
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
        /* A zero-length read or write */
        { WOLFSSL_ERROR_NONE, 0 },
        { WOLFSSL_ERROR_WANT_READ, MBEDTLS_ERR_SSL_WANT_READ },
        { WOLFSSL_ERROR_WANT_WRITE, MBEDTLS_ERR_SSL_WANT_WRITE },
        { WOLFSSL_ERROR_ZERO_RETURN, MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY },
        { WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E), MBEDTLS_ERR_SSL_CONN_EOF },
        { WC_NO_ERR_TRACE(NO_PEER_CERT), MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE }
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
    /* wolfSSL codes overlap Mbed TLS and PSA codes */
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/* WOLFSSL_SUCCESS becomes 0. wolfSSL codes overlap Mbed TLS and PSA codes,
 * so other failures become fallback. */
static int MbedRet(int ret, int fallback)
{
    if (ret == WOLFSSL_SUCCESS) {
        return 0;
    }
    return (ret == WC_NO_ERR_TRACE(MEMORY_E)) ? MBEDTLS_ERR_SSL_ALLOC_FAILED :
        fallback;
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

/* Runs for the peer's certificate, also when it sent none, and for each
 * failure. VERIFY_OPTIONAL continues the handshake after a failure. */
static int MbedVerifyCb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)store->userCtx;

    if (store->totalCerts > 0) {
        s->peer_cert = 1;
    }
    if (!preverify) {
        s->verify_flags |= MbedVerifyFlag(store->error);
    }
    return preverify || s->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL;
}

static int MbedCertErr(int ret)
{
    return (ret == WC_NO_ERR_TRACE(MEMORY_E)) ? MBEDTLS_ERR_X509_ALLOC_FAILED :
        MBEDTLS_ERR_X509_INVALID_FORMAT;
}

/* Checks buf decodes as a certificate, without verifying it. Sets *len to
 * the certificate's length, dropping any trailing data. */
static int MbedCertCheck(const unsigned char* buf, size_t* len)
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

    return (ret == 0) ? 0 : MbedCertErr(ret);
}

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

/* Returns 0 if all certificates parse, the number that failed if some parse,
 * else an error. Input without a PEM header is DER. Unlike Mbed TLS, PEM
 * need not be NUL terminated. */
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
            ret = MbedCertErr(ret);
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

    ret = MbedCertCheck(buf, &buflen);
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
    wolfSSL_CTX_set_verify(conf->ctx, modes[authmode],
        (authmode == MBEDTLS_SSL_VERIFY_NONE) ? NULL : MbedVerifyCb);
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
    conf->endpoint = endpoint;
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

/* Replaces the WOLFSSL with a new one from the config, with this context's
 * callbacks and host name */
static int MbedSslNew(mbedtls_ssl_context* ssl)
{
    if (ssl->conf->err != 0) {
        return ssl->conf->err;
    }
    if (ssl->conf->ctx == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    wolfSSL_free(ssl->ssl);
    ssl->ssl = wolfSSL_new(ssl->conf->ctx);
    if (ssl->ssl == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    ssl->authmode = ssl->conf->authmode;
    ssl->verify_flags = 0;
    ssl->peer_cert = 0;
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

/* Before mbedtls_ssl_setup too, as in Mbed TLS. NULL skips the name check. */
int mbedtls_ssl_set_hostname(mbedtls_ssl_context* ssl, const char* hostname)
{
    char* copy = NULL;
    size_t len;

    WOLFSSL_ENTER("mbedtls_ssl_set_hostname");

    if (ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (hostname != NULL) {
        len = XSTRLEN(hostname);
        if (len > MBEDTLS_SSL_MAX_HOST_NAME_LEN) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        copy = (char*)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_DOMAIN);
        if (copy == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        XMEMCPY(copy, hostname, len + 1);
    }
    XFREE(ssl->hostname, NULL, DYNAMIC_TYPE_DOMAIN);
    ssl->hostname = copy;
    ssl->hostname_set = 1;

    if (ssl->ssl == NULL) {
        return 0;
    }
    /* wolfSSL cannot remove a host name, so NULL needs a new WOLFSSL */
    return (copy != NULL) ? MbedSetHostname(ssl->ssl, copy) :
        MbedSslNew(ssl);
}

/* As in Mbed TLS 4.x, a client that verifies the server needs
 * mbedtls_ssl_set_hostname() first */
static int MbedSslCheck(const mbedtls_ssl_context* ssl)
{
    if (ssl == NULL || ssl->conf == NULL || ssl->ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
            ssl->authmode == MBEDTLS_SSL_VERIFY_REQUIRED &&
            !ssl->hostname_set) {
        return MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME;
    }
    return 0;
}

int mbedtls_ssl_handshake(mbedtls_ssl_context* ssl)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_handshake");

    ret = MbedSslCheck(ssl);
    if (ret != 0) {
        return ret;
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
    if (ssl->authmode == MBEDTLS_SSL_VERIFY_NONE) {
        return MBEDTLS_X509_BADCERT_SKIP_VERIFY;
    }
    return ssl->peer_cert ? 0 : MBEDTLS_X509_BADCERT_MISSING;
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

    ret = MbedSslCheck(ssl);
    if (ret != 0) {
        return ret;
    }
    ret = wolfSSL_read(ssl->ssl, buf, (int)len);
    if (ret > 0) {
        return ret;
    }
    ret = MbedSslErr(ssl, ret);
    /* As in Mbed TLS, EOF without close_notify reads 0 */
    return (ret == MBEDTLS_ERR_SSL_CONN_EOF) ? 0 : ret;
}

int mbedtls_ssl_write(mbedtls_ssl_context* ssl,
    const unsigned char* buf, size_t len)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_write");

    ret = MbedSslCheck(ssl);
    if (ret != 0) {
        return ret;
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
