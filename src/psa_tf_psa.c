/* psa_tf_psa.c
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

/* TF-PSA-Crypto functions outside the PSA Crypto API. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE)

#include <limits.h>

#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfpsa/psa_engine.h>
#include "psa_lock.h"
#include "psa_tf_psa_internal.h"

/* The generated crypto config must match the build's NO_FILESYSTEM */
#if defined(MBEDTLS_FS_IO) == defined(NO_FILESYSTEM)
    #error "MBEDTLS_FS_IO must be defined exactly when NO_FILESYSTEM is not"
#endif /* defined(MBEDTLS_FS_IO) == defined(NO_FILESYSTEM) */

/* MBEDTLS_THREADING_C promises a key store safe to use from any thread */
#if defined(MBEDTLS_THREADING_C) && \
        (!defined(WOLFPSA_THREAD_SAFE) || defined(SINGLE_THREADED))
    #error "MBEDTLS_THREADING_C needs WOLFPSA_THREAD_SAFE, not SINGLE_THREADED"
#endif /* MBEDTLS_THREADING_C && (!WOLFPSA_THREAD_SAFE || SINGLE_THREADED) */

void mbedtls_psa_crypto_free(void)
{
    wolfPSA_CryptoCleanup();
}

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    if (buf != NULL && len > 0) {
        wc_ForceZero(buf, len);
    }
}

void mbedtls_pk_init(mbedtls_pk_context* ctx)
{
    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
}

void mbedtls_pk_free(mbedtls_pk_context* ctx)
{
    if (ctx != NULL) {
        mbedtls_platform_zeroize(ctx->der, ctx->der_len);
        XFREE(ctx->der, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XFREE(ctx->pub, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
}

size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context* ctx)
{
    return (ctx == NULL) ? 0 : ctx->bits;
}

enum {
    PK_TYPE_NONE = 0,
    PK_TYPE_RSA = 1,
    PK_TYPE_ECC = 2,
    PK_TYPE_RSA_PUBLIC = 3,
    PK_TYPE_ECC_PUBLIC = 4,
    PK_TYPE_MONTGOMERY_PUBLIC = 5
};

int wolfPSA_MbedRet(int wcRet, int err)
{
    if (wcRet == 0) {
        return 0;
    }
    return (wcRet == WC_NO_ERR_TRACE(MEMORY_E)) ?
        PSA_ERROR_INSUFFICIENT_MEMORY : err;
}

#ifndef NO_ASN
/* A decoded key must fill the buffer */
static int PkDecodeRet(int wcRet, word32 idx, word32 len)
{
    if (wcRet == 0 && idx != len) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    return wolfPSA_MbedRet(wcRet, MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
}

#ifdef HAVE_ECC
extern size_t wc_psa_get_ecc_curve_bits(int curve_id);

/* The size of the key's curve, if the PSA engine has the curve */
static int PkEccBits(const ecc_key* ecc, size_t* bits)
{
    *bits = wc_psa_get_ecc_curve_bits(ecc->dp->id);
    return (*bits == 0) ? MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE : 0;
}
#endif /* HAVE_ECC */

/* An RSA or EC private key, traditional or PKCS #8 */
static int PkCheckKey(mbedtls_pk_context* ctx)
{
    const byte* der = ctx->der;
    word32 len = (word32)ctx->der_len;
    int ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    word32 idx;
#ifndef NO_RSA
    RsaKey* rsa;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    ecc_key* ecc;
#endif /* HAVE_ECC */

#ifndef NO_RSA
    rsa = wc_NewRsaKey(NULL, INVALID_DEVID, NULL);
    if (rsa == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    idx = 0;
    ret = wc_RsaPrivateKeyDecode(der, &idx, rsa, len);
    ret = PkDecodeRet(ret, idx, len);
    if (ret == 0) {
        ctx->type = PK_TYPE_RSA;
        ctx->bits = (size_t)mp_count_bits(&rsa->n);
    }
    wc_DeleteRsaKey(rsa, &rsa);
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    if (ret == MBEDTLS_ERR_PK_KEY_INVALID_FORMAT) {
        ecc = wc_ecc_key_new(NULL);
        if (ecc == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        idx = 0;
        ret = wc_EccPrivateKeyDecode(der, &idx, ecc, len);
        ret = PkDecodeRet(ret, idx, len);
        if (ret == 0) {
            ret = PkEccBits(ecc, &ctx->bits);
        }
        if (ret == 0) {
            ctx->type = PK_TYPE_ECC;
        }
        wc_ecc_key_free(ecc);
    }
#endif /* HAVE_ECC */
    (void)der;
    (void)len;
    (void)idx;
    return ret;
}

#ifndef NO_RSA
/* A SubjectPublicKeyInfo of id-RSASSA-PSS, which Mbed TLS does not parse */
static int PkRsaIsPss(const byte* der, word32 len)
{
    word32 idx = 0;
    word32 oid = 0;
    int seqLen;

    return GetSequence(der, &idx, &seqLen, len) >= 0 &&
        GetSequence(der, &idx, &seqLen, len) >= 0 &&
        GetObjectId(der, &idx, &oid, oidKeyType, len) == 0 &&
        oid == RSAPSSk;
}

/* Replaces pub, which can be PKCS #1, with the key's SubjectPublicKeyInfo */
static int PkRsaSetSpki(mbedtls_pk_context* ctx, RsaKey* rsa)
{
    unsigned char* spki;
    int len;
    int ret;

    len = wc_RsaKeyToPublicDer(rsa, NULL, 0);
    if (len < 0) {
        return wolfPSA_MbedRet(len, MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
    }
    spki = (unsigned char*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if (spki == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    ret = wc_RsaKeyToPublicDer(rsa, spki, (word32)len);
    if (ret != len) {
        XFREE(spki, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        return wolfPSA_MbedRet(ret, MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
    }
    XFREE(ctx->pub, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->pub = spki;
    ctx->pub_len = (size_t)len;
    return 0;
}
#endif /* !NO_RSA */

/* A public key, SubjectPublicKeyInfo or, for RSA, also PKCS #1 */
static int PkCheckPublicKey(mbedtls_pk_context* ctx)
{
    const byte* der = ctx->pub;
    word32 len = (word32)ctx->pub_len;
    int ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    word32 idx;
#ifndef NO_RSA
    RsaKey* rsa;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    ecc_key* ecc;
#endif /* HAVE_ECC */
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    curve25519_key* x25519;
#endif /* HAVE_CURVE25519 && HAVE_CURVE25519_KEY_IMPORT */
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
    curve448_key* x448;
#endif /* HAVE_CURVE448 && HAVE_CURVE448_KEY_IMPORT */

#ifndef NO_RSA
    rsa = wc_NewRsaKey(NULL, INVALID_DEVID, NULL);
    if (rsa == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    idx = 0;
    ret = wc_RsaPublicKeyDecode(der, &idx, rsa, len);
    ret = PkDecodeRet(ret, idx, len);
    if (ret == 0 && PkRsaIsPss(der, len)) {
        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }
    if (ret == 0) {
        ret = PkRsaSetSpki(ctx, rsa);
    }
    if (ret == 0) {
        ctx->type = PK_TYPE_RSA_PUBLIC;
        ctx->bits = (size_t)mp_count_bits(&rsa->n);
    }
    wc_DeleteRsaKey(rsa, &rsa);
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    if (ret == MBEDTLS_ERR_PK_KEY_INVALID_FORMAT) {
        ecc = wc_ecc_key_new(NULL);
        if (ecc == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        idx = 0;
        ret = wc_EccPublicKeyDecode(der, &idx, ecc, len);
        ret = PkDecodeRet(ret, idx, len);
        if (ret == 0) {
            ret = PkEccBits(ecc, &ctx->bits);
        }
        if (ret == 0) {
            ctx->type = PK_TYPE_ECC_PUBLIC;
        }
        wc_ecc_key_free(ecc);
    }
#endif /* HAVE_ECC */
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    if (ret == MBEDTLS_ERR_PK_KEY_INVALID_FORMAT) {
        x25519 = wc_curve25519_new(NULL, INVALID_DEVID, NULL);
        if (x25519 == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        idx = 0;
        ret = wc_Curve25519PublicKeyDecode(der, &idx, x25519, len);
        ret = PkDecodeRet(ret, idx, len);
        if (ret == 0) {
            ctx->type = PK_TYPE_MONTGOMERY_PUBLIC;
            ctx->bits = 255;
        }
        wc_curve25519_delete(x25519, &x25519);
    }
#endif /* HAVE_CURVE25519 && HAVE_CURVE25519_KEY_IMPORT */
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
    if (ret == MBEDTLS_ERR_PK_KEY_INVALID_FORMAT) {
        x448 = wc_curve448_new(NULL, INVALID_DEVID, NULL);
        if (x448 == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        idx = 0;
        ret = wc_Curve448PublicKeyDecode(der, &idx, x448, len);
        ret = PkDecodeRet(ret, idx, len);
        if (ret == 0) {
            ctx->type = PK_TYPE_MONTGOMERY_PUBLIC;
            ctx->bits = 448;
        }
        wc_curve448_delete(x448, &x448);
    }
#endif /* HAVE_CURVE448 && HAVE_CURVE448_KEY_IMPORT */
    (void)der;
    (void)len;
    (void)idx;
    return ret;
}

/* A PEM key encrypted with a password, PKCS #8 or traditional */
static int PkIsEncrypted(const unsigned char* key, size_t keylen)
{
    static const char* const marks[] = {
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "Proc-Type: 4,ENCRYPTED"
    };
    size_t markLen;
    size_t i;
    size_t j;

    for (i = 0; i < XELEM_CNT(marks); i++) {
        markLen = XSTRLEN(marks[i]);
        for (j = 0; j + markLen <= keylen; j++) {
            if (XMEMCMP(key + j, marks[i], markLen) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* An empty context and a key */
static int PkParseArgs(const mbedtls_pk_context* ctx, const unsigned char* key,
    size_t keylen)
{
    if (ctx == NULL || ctx->type != PK_TYPE_NONE || key == NULL ||
            keylen > (size_t)INT_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    return 0;
}

/* PEM with a header of the wolfCrypt type, or DER, into a new buffer */
static int PkPemToDer(const unsigned char* key, size_t keylen, int type,
    int dynType, unsigned char** out, size_t* outLen)
{
    DerBuffer* der = NULL;
    int ret;

    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }
    /* Big enough for the DER of a PEM key */
    *out = (unsigned char*)XMALLOC(keylen, NULL, dynType);
    if (*out == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#ifdef WOLFSSL_PEM_TO_DER
    if (type == PRIVATEKEY_TYPE) {
        /* Keeps a PKCS #8 header, which names the curve of an EC key */
        ret = wc_KeyPemToDer(key, (int)keylen, *out, (int)keylen, NULL);
    }
    else {
        ret = wc_PemToDer(key, (long)keylen, type, &der, NULL, NULL, NULL);
        if (ret == 0) {
            XMEMCPY(*out, der->buffer, der->length);
            ret = (int)der->length;
        }
    }
#else
    (void)type;
    ret = WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER);
#endif /* WOLFSSL_PEM_TO_DER */
    if (ret > 0) {
        *outLen = (size_t)ret;
        ret = 0;
    }
    else if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
        XMEMCPY(*out, key, keylen);
        *outLen = keylen;
        ret = 0;
    }
    else {
        ret = wolfPSA_MbedRet(ret, MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
    }
    wc_FreeDer(&der);
    return ret;
}

/* PEM or DER. Encrypted keys are not supported, so pwd is not used. */
int mbedtls_pk_parse_key(mbedtls_pk_context* ctx, const unsigned char* key,
    size_t keylen, const unsigned char* pwd, size_t pwdlen)
{
    int ret;

    (void)pwd;
    (void)pwdlen;

    ret = PkParseArgs(ctx, key, keylen);
    if (ret != 0) {
        return ret;
    }
    if (PkIsEncrypted(key, keylen)) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }
    ret = PkPemToDer(key, keylen, PRIVATEKEY_TYPE, DYNAMIC_TYPE_PRIVATE_KEY,
        &ctx->der, &ctx->der_len);
    if (ret == 0) {
        ret = PkCheckKey(ctx);
    }
    if (ret != 0) {
        mbedtls_pk_free(ctx);
    }
    return ret;
}

/* PEM or DER. RSA keys can also be PKCS #1. */
int mbedtls_pk_parse_public_key(mbedtls_pk_context* ctx,
    const unsigned char* key, size_t keylen)
{
    int ret;

    ret = PkParseArgs(ctx, key, keylen);
    if (ret != 0) {
        return ret;
    }
    ret = PkPemToDer(key, keylen, PUBLICKEY_TYPE, DYNAMIC_TYPE_PUBLIC_KEY,
        &ctx->pub, &ctx->pub_len);
    if (ret == 0) {
        ret = PkCheckPublicKey(ctx);
    }
    if (ret != 0) {
        mbedtls_pk_free(ctx);
    }
    return ret;
}
#else
/* Key parsing decodes ASN.1 */
int mbedtls_pk_parse_key(mbedtls_pk_context* ctx, const unsigned char* key,
    size_t keylen, const unsigned char* pwd, size_t pwdlen)
{
    (void)ctx;
    (void)key;
    (void)keylen;
    (void)pwd;
    (void)pwdlen;
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

int mbedtls_pk_parse_public_key(mbedtls_pk_context* ctx,
    const unsigned char* key, size_t keylen)
{
    (void)ctx;
    (void)key;
    (void)keylen;
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}
#endif /* !NO_ASN */

/* The usage and algorithm pairs mbedtls_pk_can_do_psa() allows per key type */
static const struct {
    int type;
    psa_key_usage_t usage;
    psa_algorithm_t alg;
} pkPolicy[] = {
    { PK_TYPE_RSA, PSA_KEY_USAGE_SIGN_HASH,
        PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH) },
    { PK_TYPE_RSA, PSA_KEY_USAGE_SIGN_HASH,
        PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH) },
    { PK_TYPE_RSA, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH) },
    { PK_TYPE_RSA, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH) },
    { PK_TYPE_ECC, PSA_KEY_USAGE_SIGN_HASH,
        MBEDTLS_PK_ALG_ECDSA(PSA_ALG_ANY_HASH) },
    { PK_TYPE_ECC, PSA_KEY_USAGE_DERIVE_PUBLIC, PSA_ALG_ECDH },
    { PK_TYPE_RSA_PUBLIC, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH) },
    { PK_TYPE_RSA_PUBLIC, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH) },
    { PK_TYPE_RSA_PUBLIC, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_ANY_HASH) },
    { PK_TYPE_RSA_PUBLIC, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_RSA_PKCS1V15_CRYPT },
    { PK_TYPE_RSA_PUBLIC, PSA_KEY_USAGE_ENCRYPT,
        PSA_ALG_RSA_OAEP(PSA_ALG_ANY_HASH) },
    { PK_TYPE_ECC_PUBLIC, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_ECDSA(PSA_ALG_ANY_HASH) },
    { PK_TYPE_ECC_PUBLIC, PSA_KEY_USAGE_VERIFY_HASH,
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_ANY_HASH) },
    { PK_TYPE_ECC_PUBLIC, PSA_KEY_USAGE_DERIVE_PUBLIC, PSA_ALG_ECDH },
    { PK_TYPE_MONTGOMERY_PUBLIC, PSA_KEY_USAGE_DERIVE_PUBLIC, PSA_ALG_ECDH }
};

/* alg is policyAlg, or policyAlg with its PSA_ALG_ANY_HASH set to a hash */
static int PkAlgMatches(psa_algorithm_t alg, psa_algorithm_t policyAlg)
{
    return alg == policyAlg ||
        (PSA_ALG_GET_HASH(policyAlg) == PSA_ALG_ANY_HASH &&
        (alg & ~PSA_ALG_HASH_MASK) == (policyAlg & ~PSA_ALG_HASH_MASK));
}

int mbedtls_pk_can_do_psa(const mbedtls_pk_context* pk, psa_algorithm_t alg,
    psa_key_usage_t usage)
{
    size_t i;

    if (pk == NULL) {
        return 0;
    }
    /* A public key can also do ECDH with a KDF */
    if (pk->pub != NULL && PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        alg = PSA_ALG_KEY_AGREEMENT_GET_BASE(alg);
    }
    for (i = 0; i < XELEM_CNT(pkPolicy); i++) {
        if (pkPolicy[i].type == pk->type && pkPolicy[i].usage == usage &&
                PkAlgMatches(alg, pkPolicy[i].alg)) {
            return 1;
        }
    }
    return 0;
}

#if defined(MBEDTLS_FS_IO)
int wolfPSA_MbedLoadFile(const char* path, unsigned char** buf, size_t* len)
{
    *buf = NULL;
    *len = 0;
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }
    return wolfPSA_MbedRet(wc_FileLoad(path, buf, len, NULL),
        MBEDTLS_ERR_PK_FILE_IO_ERROR);
}

/* wc_FileLoad() can fail with buf allocated. The file can be a key. */
void wolfPSA_MbedFreeFile(unsigned char* buf, size_t len)
{
    mbedtls_platform_zeroize(buf, len);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int mbedtls_pk_parse_keyfile(mbedtls_pk_context* ctx, const char* path,
    const char* password)
{
    unsigned char* buf;
    size_t len;
    int ret;

    ret = wolfPSA_MbedLoadFile(path, &buf, &len);
    if (ret == 0) {
        ret = mbedtls_pk_parse_key(ctx, buf, len,
            (const unsigned char*)password,
            (password == NULL) ? 0 : XSTRLEN(password));
    }
    wolfPSA_MbedFreeFile(buf, len);
    return ret;
}

int mbedtls_pk_parse_public_keyfile(mbedtls_pk_context* ctx, const char* path)
{
    unsigned char* buf;
    size_t len;
    int ret;

    ret = wolfPSA_MbedLoadFile(path, &buf, &len);
    if (ret == 0) {
        ret = mbedtls_pk_parse_public_key(ctx, buf, len);
    }
    wolfPSA_MbedFreeFile(buf, len);
    return ret;
}
#endif /* MBEDTLS_FS_IO */

#if defined(MBEDTLS_THREADING_PTHREAD)
static int ThreadingRet(int posixRet)
{
    return (posixRet == 0) ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

void mbedtls_mutex_init(mbedtls_threading_mutex_t* mutex)
{
    if (mutex != NULL) {
        mutex->initialized =
            (char)(pthread_mutex_init(&mutex->mutex, NULL) == 0);
    }
}

/* Does nothing for a zeroed or freed mutex, as in TF-PSA-Crypto */
void mbedtls_mutex_free(mbedtls_threading_mutex_t* mutex)
{
    if (mutex != NULL && mutex->initialized) {
        (void)pthread_mutex_destroy(&mutex->mutex);
        mutex->initialized = 0;
    }
}

int mbedtls_mutex_lock(mbedtls_threading_mutex_t* mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return ThreadingRet(pthread_mutex_lock(&mutex->mutex));
}

int mbedtls_mutex_unlock(mbedtls_threading_mutex_t* mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return ThreadingRet(pthread_mutex_unlock(&mutex->mutex));
}

int mbedtls_condition_variable_init(
    mbedtls_threading_condition_variable_t* cond)
{
    if (cond == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return ThreadingRet(pthread_cond_init(&cond->cond, NULL));
}

void mbedtls_condition_variable_free(
    mbedtls_threading_condition_variable_t* cond)
{
    if (cond != NULL) {
        (void)pthread_cond_destroy(&cond->cond);
    }
}

int mbedtls_condition_variable_signal(
    mbedtls_threading_condition_variable_t* cond)
{
    if (cond == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return ThreadingRet(pthread_cond_signal(&cond->cond));
}

int mbedtls_condition_variable_broadcast(
    mbedtls_threading_condition_variable_t* cond)
{
    if (cond == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return ThreadingRet(pthread_cond_broadcast(&cond->cond));
}

int mbedtls_condition_variable_wait(
    mbedtls_threading_condition_variable_t* cond,
    mbedtls_threading_mutex_t* mutex)
{
    if (cond == NULL || mutex == NULL || !mutex->initialized) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return ThreadingRet(pthread_cond_wait(&cond->cond, &mutex->mutex));
}
#endif /* MBEDTLS_THREADING_PTHREAD */

#endif /* WOLFSSL_PSA_ENGINE */
