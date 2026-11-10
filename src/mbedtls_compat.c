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

#include <limits.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include "mbedtls_compat_internal.h"

#if defined(WOLFCRYPT_ONLY) || !defined(HAVE_SNI)
    #error "wolfPSA: MBEDTLS_COMPAT needs wolfSSL TLS with SNI"
#endif /* WOLFCRYPT_ONLY || !HAVE_SNI */
/* MbedVerifyCb() needs the call for the peer's certificate when it passes */
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

int MbedIoLen(size_t len, int max)
{
    return (len > (size_t)max) ? max : (int)len;
}

/* Mbed TLS checks these of the peer's certificate after the verify callback,
 * which does not see them */
#define MBED_USAGE_FLAGS \
    (MBEDTLS_X509_BADCERT_KEY_USAGE | MBEDTLS_X509_BADCERT_EXT_KEY_USAGE)

static void MbedChainDropCAs(mbedtls_ssl_context* ssl);

/* Map the wolfSSL error behind a failed call to an Mbed TLS return code */
static int MbedSslErr(mbedtls_ssl_context* ssl, int ret)
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

    /* The handshake may have ended before the verify callback ran */
    MbedChainDropCAs(ssl);
    if (ssl->verify_ret != 0) {
        return ssl->verify_ret;
    }
    /* A failed verify with VERIFY_REQUIRED is what ended the handshake */
    if (ssl->verify_flags != 0 &&
            ssl->authmode == MBEDTLS_SSL_VERIFY_REQUIRED) {
        return ((ssl->verify_flags & ~MBED_USAGE_FLAGS) != 0) ?
            MBEDTLS_ERR_X509_CERT_VERIFY_FAILED :
            MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
    }
    /* wolfSSL's error for any failed BIO call */
    if (err == WC_NO_ERR_TRACE(SOCKET_ERROR_E) && ssl->io_err != 0) {
        return ssl->io_err;
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

/* The BIO call's result for wolfSSL. Keeps an error for MbedSslErr(). */
static int MbedIoRet(mbedtls_ssl_context* s, int ret, int dir)
{
    s->io_err = (ret < 0) ? ret : 0;
    return (ret > 0) ? ret : MbedIoErr(ret, dir, 1);
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
    return MbedIoRet(s, ret, MBED_IO_RECV);
}

static int MbedSendCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)ctx;
    int ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

    (void)ssl;
    if (s->f_send != NULL) {
        ret = s->f_send(s->p_bio, (const unsigned char*)buf, (size_t)sz);
    }
    return MbedIoRet(s, ret, MBED_IO_SEND);
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

/* Decodes der without verifying it. Free cert with wc_FreeDecodedCert()
 * whatever the result. */
static int MbedCertDecode(DecodedCert* cert, const byte* der, word32 len)
{
    wc_InitDecodedCert(cert, der, len, NULL);
    return wc_ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL);
}

/* The ID wolfSSL's CA cache finds a CA by */
static const byte* MbedCertId(const DecodedCert* cert)
{
#ifndef NO_SKID
    return cert->extSubjKeyId;
#else
    return cert->subjectHash;
#endif /* !NO_SKID */
}

/* The peer's chain while wolfSSL checks it */
struct MbedChain {
    uint32_t* flags; /* MBEDTLS_X509_BADCERT_* of each certificate */
    byte* caIds; /* KEYID_SIZE each: the chain's CAs, to drop from the cache */
    int count;
    int caCount;
};

static int MbedChainNew(mbedtls_ssl_context* ssl, int count)
{
    size_t sz = sizeof(*ssl->chain) + (size_t)count * sizeof(uint32_t);

    ssl->chain = (struct MbedChain*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ssl->chain == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    XMEMSET(ssl->chain, 0, sz);
    ssl->chain->flags = (uint32_t*)(ssl->chain + 1);
    ssl->chain->count = count;
    return 0;
}

/* wolfSSL caches each CA of a chain it accepts, also one accepted despite an
 * error. Notes their IDs so that MbedChainDropCAs() removes them. */
static int MbedChainNoteCAs(struct MbedChain* chain,
    const WOLFSSL_X509_STORE_CTX* store)
{
    DecodedCert* cert;
    int i;

    if (chain->caIds != NULL) {
        return 0;
    }
    chain->caIds = (byte*)XMALLOC((size_t)(chain->count - 1) * KEYID_SIZE,
        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    cert = (DecodedCert*)XMALLOC(sizeof(*cert), NULL, DYNAMIC_TYPE_DCERT);
    for (i = 1; chain->caIds != NULL && cert != NULL && i < chain->count;
            i++) {
        if (MbedCertDecode(cert, store->certs[i].buffer,
                store->certs[i].length) == 0) {
            XMEMCPY(chain->caIds + chain->caCount * KEYID_SIZE,
                MbedCertId(cert), KEYID_SIZE);
            chain->caCount++;
        }
        wc_FreeDecodedCert(cert);
    }
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
    return (chain->caIds != NULL && cert != NULL) ? 0 :
        MBEDTLS_ERR_X509_ALLOC_FAILED;
}

static void MbedChainDropCAs(mbedtls_ssl_context* ssl)
{
    int i;

    if (ssl->chain == NULL || ssl->ssl == NULL) {
        return;
    }
    for (i = 0; i < ssl->chain->caCount; i++) {
        (void)RemoveCA(SSL_CM(ssl->ssl), ssl->chain->caIds + i * KEYID_SIZE,
            WOLFSSL_CHAIN_CA);
    }
    ssl->chain->caCount = 0;
}

/* Call before wolfSSL_free(): MbedChainDropCAs() needs the WOLFSSL */
static void MbedChainFree(mbedtls_ssl_context* ssl)
{
    if (ssl->chain != NULL) {
        MbedChainDropCAs(ssl);
        XFREE(ssl->chain->caIds, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(ssl->chain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ssl->chain = NULL;
    }
}

/* Sets *ca to the CA of ca_chain that issued top, the last certificate the
 * peer sent, matched as wolfSSL finds a signer. NULL when top is one of
 * them. */
static int MbedChainCA(mbedtls_x509_crt* ca_chain,
    const WOLFSSL_BUFFER_INFO* top, mbedtls_x509_crt** ca)
{
    DecodedCert* cert;
    DecodedCert* issuer;
    mbedtls_x509_crt* crt;
    int ret = 0;

    *ca = NULL;
    for (crt = ca_chain; crt != NULL; crt = crt->next) {
        if (crt->raw.len == top->length &&
                XMEMCMP(crt->raw.p, top->buffer, top->length) == 0) {
            return 0;
        }
    }

    cert = (DecodedCert*)XMALLOC(sizeof(*cert), NULL, DYNAMIC_TYPE_DCERT);
    issuer = (DecodedCert*)XMALLOC(sizeof(*issuer), NULL, DYNAMIC_TYPE_DCERT);
    if (cert == NULL || issuer == NULL) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    if (ret == 0 && MbedCertDecode(cert, top->buffer, top->length) == 0) {
        for (crt = ca_chain; *ca == NULL && crt != NULL; crt = crt->next) {
            if (MbedCertDecode(issuer, crt->raw.p, (word32)crt->raw.len) == 0 &&
                    XMEMCMP(issuer->subjectHash, cert->issuerHash,
                        KEYID_SIZE) == 0 &&
                    (!cert->extAuthKeyIdSet ||
                     XMEMCMP(issuer->extSubjKeyId, cert->extAuthKeyId,
                        KEYID_SIZE) == 0)) {
                *ca = crt;
            }
            wc_FreeDecodedCert(issuer);
        }
    }
    if (ret == 0) {
        wc_FreeDecodedCert(cert);
    }
    XFREE(issuer, NULL, DYNAMIC_TYPE_DCERT);
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
    return ret;
}

/* As Mbed TLS does once it has checked the chain: calls the verify callback
 * for each certificate from the top down, with its flags and the certificates
 * the peer sent after it, the CA from the CA list first */
static int MbedVerifyChain(mbedtls_ssl_context* ssl,
    const WOLFSSL_X509_STORE_CTX* store)
{
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*) = ssl->f_vrfy;
    void* p_vrfy = ssl->p_vrfy;
    const struct MbedChain* chain = ssl->chain;
    const int top = chain->count - 1;
    mbedtls_x509_crt peer;
    mbedtls_x509_crt* ca = NULL;
    mbedtls_x509_crt* crt;
    uint32_t flags = 0;
    uint32_t usage;
    int depth;
    int i;
    int ret = 0;

    if (f_vrfy == NULL) {
        f_vrfy = ssl->conf->f_vrfy;
        p_vrfy = ssl->conf->p_vrfy;
    }
    mbedtls_x509_crt_init(&peer);
    for (i = 0; f_vrfy != NULL && ret == 0 && i <= top; i++) {
        ret = mbedtls_x509_crt_parse_der(&peer, store->certs[i].buffer,
            store->certs[i].length);
    }
    if (f_vrfy != NULL && ret == 0 &&
            (chain->flags[top] & MBEDTLS_X509_BADCERT_NOT_TRUSTED) == 0) {
        ret = MbedChainCA(ssl->conf->ca_chain, &store->certs[top], &ca);
    }
    if (ret == 0 && ca != NULL) {
        ret = f_vrfy(p_vrfy, ca, top + 1, &flags);
    }
    ssl->verify_flags = flags;

    for (depth = top; ret == 0 && depth >= 0; depth--) {
        usage = (depth == 0) ? (chain->flags[0] & MBED_USAGE_FLAGS) : 0;
        flags = chain->flags[depth] & ~usage;
        if (f_vrfy != NULL) {
            for (crt = &peer, i = 0; i < depth; i++) {
                crt = crt->next;
            }
            ret = f_vrfy(p_vrfy, crt, depth, &flags);
        }
        ssl->verify_flags |= flags | usage;
    }
    mbedtls_x509_crt_free(&peer);

    /* As in Mbed TLS, so it does not read as a failed verify */
    return (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) ?
        MBEDTLS_ERR_X509_FATAL_ERROR : ret;
}

/* wolfSSL calls this for each failed check of the peer's chain, top down,
 * and last for the peer's certificate once all of its checks are done. Until
 * then the handshake goes on, so that the callback and the verdict see the
 * flags of the whole chain, as in Mbed TLS. */
static int MbedVerifyCb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)store->userCtx;
    const int depth = store->error_depth;
    int ret = 0;

    if (store->totalCerts <= 0) {
        if (!preverify) {
            s->verify_flags |= MbedVerifyFlag(store->error);
        }
        return preverify || s->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL;
    }
    s->peer_cert = 1;
    if (s->chain == NULL) {
        ret = MbedChainNew(s, store->totalCerts);
    }
    if (ret == 0 && (s->chain->count != store->totalCerts || depth < 0 ||
            depth >= s->chain->count)) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    if (ret == 0 && !preverify) {
        s->chain->flags[depth] |= MbedVerifyFlag(store->error);
        if (depth > 0) {
            ret = MbedChainNoteCAs(s->chain, store);
        }
    }
    if (ret == 0 && (depth > 0 ||
            s->ssl->options.asyncState != TLS_ASYNC_FINALIZE)) {
        return 1;
    }

    if (ret == 0) {
        ret = MbedVerifyChain(s, store);
    }
    MbedChainFree(s);
    if (ret != 0) {
        s->verify_ret = ret;
        s->verify_flags = 0xFFFFFFFF;
    }
    return ret == 0 && (s->verify_flags == 0 ||
        s->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL);
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

    ret = MbedCertDecode(cert, buf, (word32)*len);
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

/* As in Mbed TLS, a file that does not parse counts as one failure */
int mbedtls_x509_crt_parse_path(mbedtls_x509_crt* chain, const char* path)
{
#ifndef NO_WOLFSSL_DIR
    ReadDirCtx* dir;
    char* name = NULL;
    int failed = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_path");

    if (chain == NULL || path == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    dir = (ReadDirCtx*)XMALLOC(sizeof(*dir), NULL, DYNAMIC_TYPE_DIRCTX);
    if (dir == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    ret = wc_ReadDirFirst(dir, path, &name);
    while (ret == 0) {
        ret = mbedtls_x509_crt_parse_file(chain, name);
        failed += (ret < 0) ? 1 : ret;
        ret = wc_ReadDirNext(dir, path, &name);
    }
    wc_ReadDirClose(dir);
    XFREE(dir, NULL, DYNAMIC_TYPE_DIRCTX);

    return (ret == WC_READDIR_NOFILE) ? failed : MBEDTLS_ERR_X509_FILE_IO_ERROR;
#else
    (void)chain;
    (void)path;
    return MBEDTLS_ERR_X509_FILE_IO_ERROR;
#endif /* !NO_WOLFSSL_DIR */
}
#endif /* MBEDTLS_FS_IO */

struct mbedtls_x509_crt_profile {
    uint32_t rsa_min_bitlen;
};

const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default = { 2048 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next = { 2048 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb = { 0 };

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
    conf->changes++;
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
    conf->changes++;
    conf->err = 0;
    conf->endpoint = endpoint;
    conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
    conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
    conf->ciphersuites = NULL;
    conf->ca_chain = NULL;
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
    const mbedtls_x509_crt* crt;
    int ret = (ca_crl == NULL) ? 0 : MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    WOLFSSL_ENTER("mbedtls_ssl_conf_ca_chain");

    if (conf == NULL) {
        return;
    }
    conf->changes++;

    if (ret == 0) {
        ret = MbedRet(wolfSSL_CTX_UnloadCAs(conf->ctx),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }

    /* Mbed TLS checks a CA only when it is used, so a CA that wolfSSL
     * rejects on load, such as an expired one, is left out */
    for (crt = ca_chain; ret == 0 && crt != NULL; crt = crt->next) {
        if (crt->raw.p != NULL &&
                wolfSSL_CTX_load_verify_buffer(conf->ctx, crt->raw.p,
                    (long)crt->raw.len, WOLFSSL_FILETYPE_ASN1) ==
                WC_NO_ERR_TRACE(MEMORY_E)) {
            ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
    }

    conf->ca_chain = (ret == 0) ? ca_chain : NULL;
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
    conf->changes++;

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

void mbedtls_ssl_conf_min_tls_version(mbedtls_ssl_config* conf,
    mbedtls_ssl_protocol_version tls_version)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_min_tls_version");

    if (conf != NULL) {
        conf->min_tls_version = tls_version;
        conf->changes++;
    }
}

void mbedtls_ssl_conf_max_tls_version(mbedtls_ssl_config* conf,
    mbedtls_ssl_protocol_version tls_version)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_max_tls_version");

    if (conf != NULL) {
        conf->max_tls_version = tls_version;
        conf->changes++;
    }
}

/* Not copied: the list must stay valid while conf is in use */
void mbedtls_ssl_conf_ciphersuites(mbedtls_ssl_config* conf,
    const int* ciphersuites)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_ciphersuites");

    if (conf != NULL) {
        conf->ciphersuites = ciphersuites;
        conf->changes++;
    }
}

void mbedtls_ssl_conf_verify(mbedtls_ssl_config* conf,
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void* p_vrfy)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_verify");

    if (conf != NULL) {
        conf->f_vrfy = f_vrfy;
        conf->p_vrfy = p_vrfy;
        conf->changes++;
    }
}

void mbedtls_ssl_conf_cert_profile(mbedtls_ssl_config* conf,
    const mbedtls_x509_crt_profile* profile)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_cert_profile");

    (void)conf;
    (void)profile;
}

#define MBED_SUITES_MAX     (WOLFSSL_MAX_SUITE_SZ / 2)
#define MBED_SUITE_NAME_SZ  64

static int mbedSuiteIds[MBED_SUITES_MAX + 1];
static char mbedSuiteNames[MBED_SUITES_MAX][MBED_SUITE_NAME_SZ];
static int mbedSuitesSet = 0;
static const int mbedNoSuites[1] = { 0 };

/* MBEDTLS_THREADING_C is on pthreads, which have a static initializer */
#ifdef MBEDTLS_THREADING_C
static wolfSSL_Mutex mbedSuitesMutex =
    WOLFSSL_MUTEX_INITIALIZER(mbedSuitesMutex);
#define MBED_SUITES_LOCK()   (void)wc_LockMutex(&mbedSuitesMutex)
#define MBED_SUITES_UNLOCK() (void)wc_UnLockMutex(&mbedSuitesMutex)
#else
#define MBED_SUITES_LOCK()   WC_DO_NOTHING
#define MBED_SUITES_UNLOCK() WC_DO_NOTHING
#endif /* MBEDTLS_THREADING_C */

/* TLS1-3-AES-128-GCM-SHA256 for TLS_AES_128_GCM_SHA256, else the IANA name
 * with dashes */
static void MbedSuiteName(byte cs0, byte cs, char* name, size_t sz)
{
    const char* iana = wolfSSL_get_cipher_name_iana_from_suite(cs0, cs);
    size_t i = 0;

    if (iana == NULL) {
        iana = "unknown";
    }
    if (cs0 == TLS13_BYTE && XSTRNCMP(iana, "TLS_", 4) == 0) {
        XMEMCPY(name, "TLS1-3", 6);
        i = 6;
        iana += 3;
    }
    for (; i + 1 < sz && *iana != '\0'; i++, iana++) {
        name[i] = (*iana == '_') ? '-' : *iana;
    }
    name[i] = '\0';
}

/* Fills the list with wolfSSL's default client suites, most preferred first.
 * Returns 1 when filled. */
static int MbedSuitesFill(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    const Suites* suites = NULL;
    size_t n = 0;
    word16 i;
    byte cs0;
    byte cs;

    ctx = wolfSSL_CTX_new(wolfTLS_client_method());
    if (ctx != NULL) {
        ssl = wolfSSL_new(ctx);
    }
    if (ssl != NULL) {
        suites = WOLFSSL_SUITES(ssl);
    }
    for (i = 0; suites != NULL && i + 1 < suites->suiteSz &&
            n < MBED_SUITES_MAX; i += 2) {
        cs0 = suites->suites[i];
        cs = suites->suites[i + 1];
        if (cs0 == CIPHER_BYTE && cs == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            continue;
        }
        mbedSuiteIds[n] = (cs0 << 8) | cs;
        MbedSuiteName(cs0, cs, mbedSuiteNames[n], sizeof(mbedSuiteNames[n]));
        n++;
    }
    mbedSuiteIds[n] = 0;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return suites != NULL;
}

/* Filled on first use, as Mbed TLS does */
const int* mbedtls_ssl_list_ciphersuites(void)
{
    const int* ids;

    WOLFSSL_ENTER("mbedtls_ssl_list_ciphersuites");

    MBED_SUITES_LOCK();
    if (!mbedSuitesSet) {
        mbedSuitesSet = MbedSuitesFill();
    }
    ids = mbedSuitesSet ? mbedSuiteIds : mbedNoSuites;
    MBED_SUITES_UNLOCK();
    return ids;
}

const char* mbedtls_ssl_get_ciphersuite_name(const int ciphersuite_id)
{
    const int* ids = mbedtls_ssl_list_ciphersuites();
    size_t i;

    WOLFSSL_ENTER("mbedtls_ssl_get_ciphersuite_name");

    for (i = 0; ids[i] != 0; i++) {
        if (ids[i] == ciphersuite_id) {
            return mbedSuiteNames[i];
        }
    }
    return "unknown";
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
        MbedChainFree(ssl);
        wolfSSL_free(ssl->ssl);
        XFREE(ssl->hostname, NULL, DYNAMIC_TYPE_DOMAIN);
        XMEMSET(ssl, 0, sizeof(*ssl));
    }
}

/* Eight groups of four hex digits, seven colons and the NUL */
#define MBED_IP_TEXT_SZ 40

/* The IP address in host as wolfSSL prints a certificate's IP addresses for
 * its name check: dotted decimal, or eight groups of four hex digits.
 * Returns 0 when host is not an IP address. */
static int MbedIpText(const char* host, char* text, size_t sz)
{
    byte ip[16];
    int len = 0;
    int i;

#ifdef AF_INET6
    if (XINET_PTON(AF_INET, host, ip) == 1) {
        len = XSNPRINTF(text, sz, "%u.%u.%u.%u", (unsigned)ip[0],
            (unsigned)ip[1], (unsigned)ip[2], (unsigned)ip[3]);
    }
    else if (XINET_PTON(AF_INET6, host, ip) == 1) {
        for (i = 0; i < 8; i++) {
            len += XSNPRINTF(text + len, sz - (size_t)len, "%02X%02X%s",
                (unsigned)ip[2 * i], (unsigned)ip[2 * i + 1],
                (i < 7) ? ":" : "");
        }
    }
#else
    (void)host;
    (void)text;
    (void)sz;
    (void)ip;
    (void)i;
#endif /* AF_INET6 */
    return len;
}

/* As in Mbed TLS, an IP address is also sent as the server name */
static int MbedSetHostname(WOLFSSL* ssl, const char* hostname)
{
    char ip[MBED_IP_TEXT_SZ];
    int ret = 0;

    if (hostname == NULL) {
        return 0;
    }
#ifdef HAVE_SNI
    ret = MbedRet(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, hostname,
        (word16)XSTRLEN(hostname)), MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
#endif /* HAVE_SNI */
    if (ret == 0 && MbedIpText(hostname, ip, sizeof(ip)) > 0) {
        ret = MbedRet(wolfSSL_check_ip_address(ssl, ip),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    else if (ret == 0) {
        ret = MbedRet(wolfSSL_check_domain_name(ssl, hostname),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    return ret;
}

/* wolfSSL takes one version, or the whole range when min and max differ */
static int MbedSetVersion(WOLFSSL* ssl, const mbedtls_ssl_config* conf)
{
    static const struct {
        mbedtls_ssl_protocol_version mbed;
        int wolf;
    } map[] = {
        { MBEDTLS_SSL_VERSION_TLS1_2, WOLFSSL_TLSV1_2 },
        { MBEDTLS_SSL_VERSION_TLS1_3, WOLFSSL_TLSV1_3 }
    };
    size_t i;

    if (conf->min_tls_version > conf->max_tls_version) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (conf->min_tls_version != conf->max_tls_version) {
        return 0;
    }
    for (i = 0; i < XELEM_CNT(map); i++) {
        if (map[i].mbed == conf->max_tls_version) {
            return MbedRet(wolfSSL_SetVersion(ssl, map[i].wolf),
                MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        }
    }
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
}

/* After MbedSetVersion, which resets the suites */
static int MbedSetSuites(WOLFSSL* ssl, const int* ids)
{
    byte suites[WOLFSSL_MAX_SUITE_SZ];
    int len = 0;

    if (ids == NULL) {
        return 0;
    }
    for (; *ids != 0 && len + 2 <= (int)sizeof(suites); ids++) {
        suites[len++] = (byte)(*ids >> 8);
        suites[len++] = (byte)*ids;
    }
    return MbedRet(wolfSSL_set_cipher_list_bytes(ssl, suites, len),
        MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
}

/* Replaces the WOLFSSL with a new one from the config, with this context's
 * callbacks, host name and session */
static int MbedSslNew(mbedtls_ssl_context* ssl)
{
    WOLFSSL_SESSION* session = NULL;
    int ret;

    if (ssl->conf->err != 0) {
        return ssl->conf->err;
    }
    if (ssl->conf->ctx == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->session_set) {
        session = wolfSSL_get1_session(ssl->ssl);
    }
    MbedChainFree(ssl);
    wolfSSL_free(ssl->ssl);
    ssl->ssl = wolfSSL_new(ssl->conf->ctx);
    if (ssl->ssl == NULL) {
        wolfSSL_SESSION_free(session);
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    ssl->started = 0;
    ssl->authmode = ssl->conf->authmode;
    ssl->verify_flags = 0;
    ssl->verify_ret = 0;
    ssl->peer_cert = 0;
    ssl->io_err = 0;
    wolfSSL_SSLSetIORecv(ssl->ssl, MbedRecvCb);
    wolfSSL_SSLSetIOSend(ssl->ssl, MbedSendCb);
    wolfSSL_SetIOReadCtx(ssl->ssl, ssl);
    wolfSSL_SetIOWriteCtx(ssl->ssl, ssl);
    wolfSSL_SetCertCbCtx(ssl->ssl, ssl);
    ret = MbedSetVersion(ssl->ssl, ssl->conf);
    if (ret == 0) {
        ret = MbedSetSuites(ssl->ssl, ssl->conf->ciphersuites);
    }
    if (ret == 0) {
        ret = MbedSetHostname(ssl->ssl, ssl->hostname);
    }
    if (ret == 0 && session != NULL) {
        /* One that expired since gets a full handshake, as in Mbed TLS */
        (void)wolfSSL_set_session(ssl->ssl, session);
    }
    wolfSSL_SESSION_free(session);
    if (ret == 0) {
        ssl->conf_changes = ssl->conf->changes;
    }
    return ret;
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

int mbedtls_ssl_session_reset(mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_session_reset");

    if (ssl == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* As in Mbed TLS, the session set before is not used again */
    ssl->session_set = 0;
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

void mbedtls_ssl_set_verify(mbedtls_ssl_context* ssl,
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void* p_vrfy)
{
    WOLFSSL_ENTER("mbedtls_ssl_set_verify");

    if (ssl != NULL) {
        ssl->f_vrfy = f_vrfy;
        ssl->p_vrfy = p_vrfy;
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

/* Mbed TLS reads the config during the handshake, so conf_* calls made before
 * it starts apply to it. As in Mbed TLS 4.x, a client that verifies the
 * server needs mbedtls_ssl_set_hostname() first. */
static int MbedSslStart(mbedtls_ssl_context* ssl)
{
    int ret = 0;

    if (ssl == NULL || ssl->conf == NULL || ssl->ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (!ssl->started && ssl->conf_changes != ssl->conf->changes) {
        ret = MbedSslNew(ssl);
    }
    if (ret == 0 && ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
            ssl->authmode == MBEDTLS_SSL_VERIFY_REQUIRED &&
            !ssl->hostname_set) {
        ret = MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME;
    }
    if (ret == 0) {
        ssl->started = 1;
    }
    return ret;
}

int mbedtls_ssl_handshake(mbedtls_ssl_context* ssl)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_handshake");

    ret = MbedSslStart(ssl);
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
    if (ssl->session_set && wolfSSL_session_reused(ssl->ssl)) {
        return ssl->session_verify;
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

int mbedtls_ssl_get_ciphersuite_id_from_ssl(const mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_get_ciphersuite_id_from_ssl");

    if (ssl == NULL || ssl->ssl == NULL) {
        return 0;
    }
    return wolfSSL_get_current_cipher_suite(ssl->ssl);
}

const char* mbedtls_ssl_get_version(const mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_get_version");

    if (ssl == NULL || ssl->ssl == NULL) {
        return "unknown";
    }
    return wolfSSL_get_version(ssl->ssl);
}

/* wolfSSL_version() returns the same IETF values */
mbedtls_ssl_protocol_version mbedtls_ssl_get_version_number(
    const mbedtls_ssl_context* ssl)
{
    int version;

    WOLFSSL_ENTER("mbedtls_ssl_get_version_number");

    if (ssl == NULL || ssl->ssl == NULL) {
        return MBEDTLS_SSL_VERSION_UNKNOWN;
    }
    version = wolfSSL_version(ssl->ssl);
    if (version != MBEDTLS_SSL_VERSION_TLS1_2 &&
            version != MBEDTLS_SSL_VERSION_TLS1_3) {
        return MBEDTLS_SSL_VERSION_UNKNOWN;
    }
    return (mbedtls_ssl_protocol_version)version;
}

size_t mbedtls_ssl_get_bytes_avail(const mbedtls_ssl_context* ssl)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_get_bytes_avail");

    if (ssl == NULL || ssl->ssl == NULL) {
        return 0;
    }
    ret = wolfSSL_pending(ssl->ssl);
    return (ret > 0) ? (size_t)ret : 0;
}

int mbedtls_ssl_read(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_read");

    ret = MbedSslStart(ssl);
    if (ret != 0) {
        return ret;
    }
    ret = wolfSSL_read(ssl->ssl, buf, MbedIoLen(len, INT_MAX));
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

    ret = MbedSslStart(ssl);
    if (ret != 0) {
        return ret;
    }
    /* As in Mbed TLS, at most one record */
    ret = wolfSSL_write(ssl->ssl, buf, MbedIoLen(len, MAX_RECORD_SIZE));
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

void mbedtls_ssl_session_init(mbedtls_ssl_session* session)
{
    WOLFSSL_ENTER("mbedtls_ssl_session_init");

    if (session != NULL) {
        XMEMSET(session, 0, sizeof(*session));
    }
}

void mbedtls_ssl_session_free(mbedtls_ssl_session* session)
{
    WOLFSSL_ENTER("mbedtls_ssl_session_free");

    if (session != NULL) {
        wolfSSL_SESSION_free(session->session);
        XMEMSET(session, 0, sizeof(*session));
    }
}

int mbedtls_ssl_get_session(const mbedtls_ssl_context* ssl,
    mbedtls_ssl_session* session)
{
    WOLFSSL_ENTER("mbedtls_ssl_get_session");

    if (ssl == NULL || ssl->ssl == NULL || session == NULL ||
            session->session != NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->session = wolfSSL_get1_session(ssl->ssl);
    session->verify_result = mbedtls_ssl_get_verify_result(ssl);
    return (session->session != NULL) ? 0 : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
}

int mbedtls_ssl_set_session(mbedtls_ssl_context* ssl,
    const mbedtls_ssl_session* session)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ssl_set_session");

    if (ssl == NULL || ssl->ssl == NULL || session == NULL ||
            session->session == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = MbedRet(wolfSSL_set_session(ssl->ssl, session->session),
        MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    if (ret == 0) {
        ssl->session_set = 1;
        ssl->session_verify = session->verify_result;
    }
    return ret;
}

/* Serializing a session needs HAVE_EXT_CACHE */
int mbedtls_ssl_session_save(const mbedtls_ssl_session* session,
    unsigned char* buf, size_t buf_len, size_t* olen)
{
    WOLFSSL_ENTER("mbedtls_ssl_session_save");

    (void)session;
    (void)buf;
    (void)buf_len;
    if (olen != NULL) {
        *olen = 0;
    }
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}

int mbedtls_ssl_session_load(mbedtls_ssl_session* session,
    const unsigned char* buf, size_t len)
{
    WOLFSSL_ENTER("mbedtls_ssl_session_load");

    (void)session;
    (void)buf;
    (void)len;
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}

#endif /* WOLFPSA_MBEDTLS_COMPAT */
