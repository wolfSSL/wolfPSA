/* ssl.c
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

/* Mbed TLS 4.x TLS API on wolfSSL (MBEDTLS_COMPAT=1). */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <mbedtls/ssl.h>

/* The generated config has MBEDTLS_SSL_TLS_C with wolfSSL's TLS and SNI, and
 * MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_SSL_TLS_C) != (defined(MBEDTLS_X509_CRT_PARSE_C) && \
        !defined(WOLFCRYPT_ONLY) && defined(HAVE_SNI))
    #error "MBEDTLS_SSL_TLS_C does not match WOLFCRYPT_ONLY and HAVE_SNI"
#endif /* MBEDTLS_SSL_TLS_C != (X509_CRT_PARSE_C && TLS && SNI) */

#if defined(MBEDTLS_SSL_TLS_C)

#include <limits.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/error-ssl.h>
#include <wolfpsa/psa_engine.h>
#include <mbedtls/net_sockets.h>
#include "mbedtls_compat_internal.h"
#include "psa_tf_psa_internal.h"

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
        for (i = 0; i < last; i++) {
            if (map[i].mbed[dir] == code) {
                break;
            }
        }
        return map[i].wolf;
    }

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

/* Mbed TLS checks these apart from the chain and fails with
 * MBEDTLS_ERR_SSL_BAD_CERTIFICATE */
#define MBED_USAGE_FLAGS \
    (MBEDTLS_X509_BADCERT_KEY_USAGE | MBEDTLS_X509_BADCERT_EXT_KEY_USAGE)

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

    /* A failed verify is what ended the handshake */
    if (ssl->verify_flags != 0) {
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

/* WOLFSSL_SUCCESS becomes 0. WOLFSSL_FAILURE is 0, a success for
 * wolfPSA_MbedRet(). */
static int MbedRet(int ret, int fallback)
{
    if (ret == WOLFSSL_SUCCESS) {
        return 0;
    }
    return (ret == WOLFSSL_FAILURE) ? fallback :
        wolfPSA_MbedRet(ret, fallback);
}

/* conf->err index of each kind of conf call. Each call sets its own, 0 on
 * success, apart from a method change, which only config_defaults clears. */
enum {
    MBED_CONF_ERR_METHOD,
    MBED_CONF_ERR_AUTHMODE,
    MBED_CONF_ERR_CA,
    MBED_CONF_ERR_OWN_CERT,
    MBED_CONF_ERR_KINDS
};
wc_static_assert(MBED_CONF_ERR_KINDS ==
    XELEM_CNT(((mbedtls_ssl_config*)0)->err));

static int MbedConfErr(const mbedtls_ssl_config* conf)
{
    size_t i;

    for (i = 0; i < XELEM_CNT(conf->err); i++) {
        if (conf->err[i] != 0) {
            return conf->err[i];
        }
    }
    return 0;
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

/* wolfSSL calls this for a failed check of the peer's chain. Keeps the
 * check's flag for mbedtls_ssl_get_verify_result() and lets the handshake
 * fail. */
static int MbedVerifyCb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    mbedtls_ssl_context* s = (mbedtls_ssl_context*)store->userCtx;

    if (!preverify) {
        s->verify_flags |= MbedVerifyFlag(store->error);
    }
    return preverify;
}

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
    WOLFSSL_ENTER("mbedtls_ssl_conf_authmode");

    if (conf == NULL) {
        return;
    }
    conf->changes++;
    if (authmode != MBEDTLS_SSL_VERIFY_NONE &&
            authmode != MBEDTLS_SSL_VERIFY_REQUIRED) {
        conf->err[MBED_CONF_ERR_AUTHMODE] = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        return;
    }
    conf->err[MBED_CONF_ERR_AUTHMODE] = 0;
    conf->authmode = authmode;
    if (conf->ctx == NULL) {
        return;
    }
    if (authmode == MBEDTLS_SSL_VERIFY_NONE) {
        wolfSSL_CTX_set_verify(conf->ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    else {
        wolfSSL_CTX_set_verify(conf->ctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            MbedVerifyCb);
    }
}

/* Loads conf->ca_chain into the WOLFSSL_CTX. Mbed TLS checks a CA only when
 * it is used, so a CA that wolfSSL rejects on load, such as an expired one,
 * is left out. */
static void MbedConfCAs(mbedtls_ssl_config* conf)
{
    const mbedtls_x509_crt* crt;
    int ret = (conf->ca_crl == NULL) ? 0 : MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    if (ret == 0) {
        ret = MbedRet(wolfSSL_CTX_UnloadCAs(conf->ctx),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    for (crt = conf->ca_chain; ret == 0 && crt != NULL; crt = crt->next) {
        if (crt->raw.p != NULL &&
                wolfSSL_CTX_load_verify_buffer(conf->ctx, crt->raw.p,
                    (long)crt->raw.len, WOLFSSL_FILETYPE_ASN1) ==
                WC_NO_ERR_TRACE(MEMORY_E)) {
            ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
    }
    conf->err[MBED_CONF_ERR_CA] = ret;
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
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }

    wolfSSL_CTX_free(conf->ctx);
    conf->changes++;
    XMEMSET(conf->err, 0, sizeof(conf->err));
    /* wolfSSL_new() fails for a server without a certificate and key */
    if (endpoint == MBEDTLS_SSL_IS_SERVER) {
        conf->err[MBED_CONF_ERR_OWN_CERT] = MBEDTLS_ERR_SSL_BAD_CONFIG;
    }
    conf->endpoint = endpoint;
    conf->transport = transport;
#ifdef MBEDTLS_SSL_PROTO_TLS1_2
    conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
#else
    conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#else
    conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
    conf->ciphersuites = NULL;
    conf->ctx = wolfSSL_CTX_new(methods[i].method());
    if (conf->ctx == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    mbedtls_ssl_conf_authmode(conf,
        (endpoint == MBEDTLS_SSL_IS_CLIENT) ? MBEDTLS_SSL_VERIFY_REQUIRED :
        MBEDTLS_SSL_VERIFY_NONE);
    /* As in Mbed TLS, the CAs set before are kept */
    MbedConfCAs(conf);
    return 0;
}

/* The WOLFSSL_CTX keeps the endpoint and transport of config_defaults */
static void MbedConfMethod(mbedtls_ssl_config* conf, int* field, int value)
{
    if (conf->ctx != NULL && *field != value) {
        conf->err[MBED_CONF_ERR_METHOD] = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    *field = value;
    conf->changes++;
}

void mbedtls_ssl_conf_endpoint(mbedtls_ssl_config* conf, int endpoint)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_endpoint");

    if (conf != NULL) {
        MbedConfMethod(conf, &conf->endpoint, endpoint);
    }
}

void mbedtls_ssl_conf_transport(mbedtls_ssl_config* conf, int transport)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_transport");

    if (conf != NULL) {
        MbedConfMethod(conf, &conf->transport, transport);
    }
}

int mbedtls_ssl_conf_get_endpoint(const mbedtls_ssl_config* conf)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_get_endpoint");

    return (conf != NULL) ? conf->endpoint : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
}

void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config* conf,
    mbedtls_x509_crt* ca_chain, mbedtls_x509_crl* ca_crl)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_ca_chain");

    if (conf == NULL) {
        return;
    }
    conf->changes++;
    conf->ca_chain = ca_chain;
    conf->ca_crl = ca_crl;
    if (conf->ctx != NULL) {
        MbedConfCAs(conf);
    }
}

/* Mbed TLS sends every certificate in own_cert. A second call replaces the
 * first, where Mbed TLS keeps both and picks one per handshake. wolfSSL
 * replaces each before checking it, so setup returns a failed load's error. */
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
    conf->err[MBED_CONF_ERR_OWN_CERT] = ret;
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

/* wolfSSL's default client suites, most preferred first. No WOLFSSL_CTX, so
 * it works for either side and before psa_crypto_init(). */
static void MbedSuitesFill(void)
{
    Suites suites;
#ifdef WOLFSSL_TLS13
    const ProtocolVersion pv = MakeTLSv1_3();
#else
    const ProtocolVersion pv = MakeTLSv1_2();
#endif /* WOLFSSL_TLS13 */
    size_t n = 0;
    word16 i;
    byte cs0;
    byte cs;

    XMEMSET(&suites, 0, sizeof(suites));
    /* Every key type, without PSK and anonymous suites */
    InitSuites(&suites, pv, 0, TRUE, FALSE, TRUE, TRUE, TRUE, TRUE, TRUE,
        FALSE, TRUE, TRUE, TRUE, TRUE, WOLFSSL_CLIENT_END);
    for (i = 0; i + 1 < suites.suiteSz && n < MBED_SUITES_MAX; i += 2) {
        cs0 = suites.suites[i];
        cs = suites.suites[i + 1];
        if (cs0 == CIPHER_BYTE && cs == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            continue;
        }
        mbedSuiteIds[n] = (cs0 << 8) | cs;
        MbedSuiteName(cs0, cs, mbedSuiteNames[n], sizeof(mbedSuiteNames[n]));
        n++;
    }
    mbedSuiteIds[n] = 0;
}

/* Filled on first use, as Mbed TLS does */
const int* mbedtls_ssl_list_ciphersuites(void)
{
    WOLFSSL_ENTER("mbedtls_ssl_list_ciphersuites");

    MBED_SUITES_LOCK();
    if (!mbedSuitesSet) {
        MbedSuitesFill();
        mbedSuitesSet = 1;
    }
    MBED_SUITES_UNLOCK();
    return mbedSuiteIds;
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

int mbedtls_ssl_get_ciphersuite_id(const char* ciphersuite_name)
{
    const int* ids = mbedtls_ssl_list_ciphersuites();
    size_t i;

    WOLFSSL_ENTER("mbedtls_ssl_get_ciphersuite_id");

    for (i = 0; ciphersuite_name != NULL && ids[i] != 0; i++) {
        if (XSTRCMP(mbedSuiteNames[i], ciphersuite_name) == 0) {
            return ids[i];
        }
    }
    return 0;
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

/* Eight groups of four hex digits, seven colons and the NUL */
#define MBED_IP_TEXT_SZ 40

/* The IP address in host as wolfSSL prints a certificate's IP addresses for
 * its name check: dotted decimal, or eight groups of four hex digits.
 * Returns 0 when host is not an IP address. */
static int MbedIpText(const char* host, char* text, size_t sz)
{
    byte ip[16];
    int len = 0;

    (void)host;
    (void)text;
    (void)sz;
    (void)ip;
#ifdef AF_INET
    if (XINET_PTON(AF_INET, host, ip) == 1) {
        len = XSNPRINTF(text, sz, "%u.%u.%u.%u", (unsigned)ip[0],
            (unsigned)ip[1], (unsigned)ip[2], (unsigned)ip[3]);
    }
#endif /* AF_INET */
#ifdef AF_INET6
    if (len == 0 && XINET_PTON(AF_INET6, host, ip) == 1) {
        int i;

        for (i = 0; i < 8; i++) {
            len += XSNPRINTF(text + len, sz - (size_t)len, "%02X%02X%s",
                (unsigned)ip[2 * i], (unsigned)ip[2 * i + 1],
                (i < 7) ? ":" : "");
        }
    }
#endif /* AF_INET6 */
    return len;
}

/* RFC 6066 has no IP addresses in server_name, which Mbed TLS sends anyway */
static int MbedSetHostname(WOLFSSL* ssl, const char* hostname)
{
    char ip[MBED_IP_TEXT_SZ];
    int ret;

    if (hostname == NULL) {
        return 0;
    }
    if (MbedIpText(hostname, ip, sizeof(ip)) > 0) {
        return MbedRet(wolfSSL_check_ip_address(ssl, ip),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    ret = MbedRet(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, hostname,
        (word16)XSTRLEN(hostname)), MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    if (ret == 0) {
        ret = MbedRet(wolfSSL_check_domain_name(ssl, hostname),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    return ret;
}

/* TLS 1.2, TLS 1.3, or both. With a minimum set, wolfSSL_SetVersion() sets
 * the top of the range. */
static int MbedSetVersion(WOLFSSL* ssl, const mbedtls_ssl_config* conf)
{
    static const struct {
        mbedtls_ssl_protocol_version mbed;
        int wolf;
    } map[] = {
        { MBEDTLS_SSL_VERSION_TLS1_2, WOLFSSL_TLSV1_2 },
        { MBEDTLS_SSL_VERSION_TLS1_3, WOLFSSL_TLSV1_3 }
    };
    int minVer = -1;
    int maxVer = -1;
    int ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    size_t i;

    for (i = 0; i < XELEM_CNT(map); i++) {
        if (map[i].mbed == conf->min_tls_version) {
            minVer = map[i].wolf;
        }
        if (map[i].mbed == conf->max_tls_version) {
            maxVer = map[i].wolf;
        }
    }
    if (minVer >= 0 && minVer <= maxVer) {
        ret = MbedRet(wolfSSL_SetMinVersion(ssl, minVer),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    if (ret == 0) {
        ret = MbedRet(wolfSSL_SetVersion(ssl, maxVer),
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    return ret;
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
 * callbacks, host name and session. Leaves none on failure. */
static int MbedSslNew(mbedtls_ssl_context* ssl)
{
    WOLFSSL_SESSION* session = NULL;
    int ret = MbedConfErr(ssl->conf);

    if (ret == 0 && ssl->conf->ctx == NULL) {
        ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ret == 0 && ssl->session_set) {
        session = wolfSSL_get1_session(ssl->ssl);
    }
    wolfSSL_free(ssl->ssl);
    ssl->ssl = NULL;
    if (ret == 0) {
        ssl->ssl = wolfSSL_new(ssl->conf->ctx);
        if (ssl->ssl == NULL) {
            ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
    }
    if (ret == 0) {
        ssl->started = 0;
        ssl->authmode = ssl->conf->authmode;
        ssl->verify_flags = 0;
        ssl->io_err = 0;
        wolfSSL_SSLSetIORecv(ssl->ssl, MbedRecvCb);
        wolfSSL_SSLSetIOSend(ssl->ssl, MbedSendCb);
        wolfSSL_SetIOReadCtx(ssl->ssl, ssl);
        wolfSSL_SetIOWriteCtx(ssl->ssl, ssl);
        wolfSSL_SetCertCbCtx(ssl->ssl, ssl);
        ret = MbedSetVersion(ssl->ssl, ssl->conf);
    }
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
        ssl->hostname_changed = 0;
    }
    else {
        wolfSSL_free(ssl->ssl);
        ssl->ssl = NULL;
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

const mbedtls_ssl_config* mbedtls_ssl_context_get_config(
    const mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_context_get_config");

    return (ssl != NULL) ? ssl->conf : NULL;
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

/* Before mbedtls_ssl_setup too, as in Mbed TLS. NULL skips the name check. */
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
        if (!wolfPSA_CryptoReady()) {
            return PSA_ERROR_BAD_STATE;
        }
        copy = (char*)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_DOMAIN);
        if (copy == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        XMEMCPY(copy, hostname, len + 1);
    }

    /* Once the handshake starts, the name applies from the next reset */
    if (ssl->ssl != NULL && !ssl->started) {
        ret = MbedSetHostname(ssl->ssl, hostname);
        /* wolfSSL cannot remove a name: MbedSslStart() makes a new WOLFSSL */
        if (ret != 0 || ssl->hostname != NULL) {
            ssl->hostname_changed = 1;
        }
    }
    if (ret == 0) {
        XFREE(ssl->hostname, NULL, DYNAMIC_TYPE_DOMAIN);
        ssl->hostname = copy;
        ssl->hostname_set = 1;
    }
    else {
        XFREE(copy, NULL, DYNAMIC_TYPE_DOMAIN);
    }
    return ret;
}

/* Mbed TLS reads the config during the handshake, so conf_* calls and a host
 * name set before it starts apply to it. As in Mbed TLS 4.x, a client that
 * verifies the server needs mbedtls_ssl_set_hostname() first. */
static int MbedSslStart(mbedtls_ssl_context* ssl)
{
    int ret = 0;

    if (ssl == NULL || ssl->conf == NULL || ssl->ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (!ssl->started && (ssl->conf_changes != ssl->conf->changes ||
            ssl->hostname_changed)) {
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

int mbedtls_ssl_is_handshake_over(mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_is_handshake_over");

    return ssl != NULL && ssl->ssl != NULL &&
        wolfSSL_is_init_finished(ssl->ssl);
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
    /* A server keeps no verify result with a session it resumes */
    return wolfSSL_session_reused(ssl->ssl) ? MBEDTLS_X509_BADCERT_MISSING :
        0;
}

const char* mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context* ssl)
{
    WOLFSSL_ENTER("mbedtls_ssl_get_ciphersuite");

    if (ssl == NULL || ssl->ssl == NULL) {
        return NULL;
    }
    return mbedtls_ssl_get_ciphersuite_name(
        mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl));
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

    if (ssl == NULL || ssl->ssl == NULL) {
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

#endif /* MBEDTLS_SSL_TLS_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
