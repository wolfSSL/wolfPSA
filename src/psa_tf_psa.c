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
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfpsa/psa_engine.h>
#include "psa_lock.h"

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
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
}

enum {
    PK_TYPE_NONE = 0,
    PK_TYPE_RSA = 1,
    PK_TYPE_ECC = 2
};

/* MEMORY_E becomes PSA_ERROR_INSUFFICIENT_MEMORY, other errors become err */
static int PkRet(int wcRet, int err)
{
    if (wcRet == 0) {
        return 0;
    }
    return (wcRet == WC_NO_ERR_TRACE(MEMORY_E)) ?
        PSA_ERROR_INSUFFICIENT_MEMORY : err;
}

/* A decoded key must fill the buffer */
static int PkDecodeRet(int wcRet, word32 idx, word32 len)
{
    if (wcRet == 0 && idx != len) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    return PkRet(wcRet, MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
}

/* An RSA or EC private key, traditional or PKCS #8. *type becomes PK_TYPE_*. */
static int PkCheckKey(const byte* der, word32 len, int* type)
{
    int ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    word32 idx;
#ifndef NO_RSA
    RsaKey* rsa;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    ecc_key* ecc;
#endif /* HAVE_ECC */

    *type = PK_TYPE_NONE;
#ifndef NO_RSA
    rsa = wc_NewRsaKey(NULL, INVALID_DEVID, NULL);
    if (rsa == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    idx = 0;
    ret = wc_RsaPrivateKeyDecode(der, &idx, rsa, len);
    ret = PkDecodeRet(ret, idx, len);
    if (ret == 0) {
        *type = PK_TYPE_RSA;
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
            *type = PK_TYPE_ECC;
        }
        wc_ecc_key_free(ecc);
    }
#endif /* HAVE_ECC */
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

    for (i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        markLen = XSTRLEN(marks[i]);
        for (j = 0; j + markLen <= keylen; j++) {
            if (XMEMCMP(key + j, marks[i], markLen) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* PEM or DER. Encrypted keys are not supported, so pwd is not used. */
int mbedtls_pk_parse_key(mbedtls_pk_context* ctx, const unsigned char* key,
    size_t keylen, const unsigned char* pwd, size_t pwdlen)
{
    int ret;

    (void)pwd;
    (void)pwdlen;

    if (ctx == NULL || ctx->der != NULL || key == NULL ||
            keylen > (size_t)INT_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    if (PkIsEncrypted(key, keylen)) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    /* Big enough for the DER of a PEM key */
    ctx->der = (unsigned char*)XMALLOC(keylen, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    if (ctx->der == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#ifdef WOLFSSL_PEM_TO_DER
    ret = wc_KeyPemToDer(key, (int)keylen, ctx->der, (int)keylen, NULL);
#else
    ret = WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER);
#endif /* WOLFSSL_PEM_TO_DER */
    if (ret > 0) {
        ctx->der_len = (size_t)ret;
        ret = 0;
    }
    else if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
        XMEMCPY(ctx->der, key, keylen);
        ctx->der_len = keylen;
        ret = 0;
    }
    else {
        ret = PkRet(ret, MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
    }

    if (ret == 0) {
        ret = PkCheckKey(ctx->der, (word32)ctx->der_len, &ctx->type);
    }
    if (ret != 0) {
        mbedtls_pk_free(ctx);
    }
    return ret;
}

/* The policy TF-PSA-Crypto gives the PSA key of a parsed private key */
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
    { PK_TYPE_ECC, PSA_KEY_USAGE_DERIVE_PUBLIC, PSA_ALG_ECDH }
};

/* alg is policyAlg, or policyAlg with its PSA_ALG_ANY_HASH set to a hash */
static int PkAlgMatches(psa_algorithm_t alg, psa_algorithm_t policyAlg)
{
    return alg == policyAlg || (PSA_ALG_IS_SIGN_HASH(alg) &&
        (alg & ~PSA_ALG_HASH_MASK) == (policyAlg & ~PSA_ALG_HASH_MASK));
}

int mbedtls_pk_can_do_psa(const mbedtls_pk_context* pk, psa_algorithm_t alg,
    psa_key_usage_t usage)
{
    size_t i;

    if (pk == NULL) {
        return 0;
    }
    for (i = 0; i < sizeof(pkPolicy) / sizeof(pkPolicy[0]); i++) {
        if (pkPolicy[i].type == pk->type && pkPolicy[i].usage == usage &&
                PkAlgMatches(alg, pkPolicy[i].alg)) {
            return 1;
        }
    }
    return 0;
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_pk_parse_keyfile(mbedtls_pk_context* ctx, const char* path,
    const char* password)
{
    byte* buf = NULL;
    size_t len = 0;
    int ret;

    ret = PkRet(wc_FileLoad(path, &buf, &len, NULL),
        MBEDTLS_ERR_PK_FILE_IO_ERROR);
    if (ret == 0) {
        ret = mbedtls_pk_parse_key(ctx, buf, len,
            (const unsigned char*)password,
            (password == NULL) ? 0 : XSTRLEN(password));
    }
    /* wc_FileLoad() can fail with buf allocated */
    mbedtls_platform_zeroize(buf, len);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
