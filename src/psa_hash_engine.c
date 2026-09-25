/* psa_hash_engine.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include "psa_trace.h"
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_MD5
#include <wolfssl/wolfcrypt/md5.h>
#endif

#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>
#endif

#ifndef NO_SHA256
#include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef WOLFSSL_SHA384
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef WOLFSSL_SHA3
#include <wolfssl/wolfcrypt/sha3.h>
#endif

#ifdef WOLFSSL_RIPEMD
#include <wolfssl/wolfcrypt/ripemd.h>
#endif

#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>
#endif

extern int wolfPSA_CryptoIsInitialized(void);

typedef struct psa_hash_operation_ctx {
    psa_algorithm_t alg;           /* Hash algorithm */
    int initialized;               /* Whether operation is initialized */
    int started;                   /* Whether operation has started */
    int finalized;                 /* Whether operation has been finalized */

    /* Algorithm-specific context */
    union {
#ifdef WOLFSSL_MD5
        wc_Md5 md5;                /* MD5 context */
#endif
#ifndef NO_SHA
        wc_Sha sha1;               /* SHA-1 context */
#endif
#ifndef NO_SHA256
        wc_Sha256 sha256;          /* SHA-256 context */
#endif
#ifdef WOLFSSL_SHA224
        wc_Sha224 sha224;          /* SHA-224 context */
#endif
#ifdef WOLFSSL_SHA384
        wc_Sha384 sha384;          /* SHA-384 context */
#endif
#ifdef WOLFSSL_SHA512
        wc_Sha512 sha512;          /* SHA-512 context */
#endif
#ifdef WOLFSSL_SHA3
        wc_Sha3 sha3;              /* SHA-3 context */
#endif
#ifdef WOLFSSL_RIPEMD
        RipeMd ripemd;             /* RIPEMD-160 context */
#endif
#ifdef HAVE_ASCON
        wc_AsconHash256 ascon256;  /* Ascon-Hash256 context */
#endif
    } ctx;
} psa_hash_operation_ctx_t;

static psa_hash_operation_ctx_t *psa_hash_get_ctx(psa_hash_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }

    return (psa_hash_operation_ctx_t *)(uintptr_t)operation->opaque;
}

psa_status_t psa_hash_abort(psa_hash_operation_t *operation);

static psa_status_t wolfpsa_hash_fail(psa_hash_operation_t *operation,
                                      psa_status_t status)
{
    (void)psa_hash_abort(operation);
    return status;
}

static const psa_hash_operation_ctx_t *psa_hash_get_ctx_const(
    const psa_hash_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }

    return (const psa_hash_operation_ctx_t *)(uintptr_t)operation->opaque;
}

static void psa_hash_cleanup_ctx(psa_hash_operation_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->initialized && ctx->started) {
        switch (ctx->alg) {
#ifdef WOLFSSL_MD5
            case PSA_ALG_MD5:
                wc_Md5Free(&ctx->ctx.md5);
                break;
#endif
#ifndef NO_SHA
            case PSA_ALG_SHA_1:
                wc_ShaFree(&ctx->ctx.sha1);
                break;
#endif
#ifndef NO_SHA256
            case PSA_ALG_SHA_256:
                wc_Sha256Free(&ctx->ctx.sha256);
                break;
#endif
#ifdef WOLFSSL_SHA224
            case PSA_ALG_SHA_224:
                wc_Sha224Free(&ctx->ctx.sha224);
                break;
#endif
#ifdef WOLFSSL_SHA384
            case PSA_ALG_SHA_384:
                wc_Sha384Free(&ctx->ctx.sha384);
                break;
#endif
#ifdef WOLFSSL_SHA512
            case PSA_ALG_SHA_512:
                wc_Sha512Free(&ctx->ctx.sha512);
                break;
#if !defined(WOLFSSL_NOSHA512_224)
            case PSA_ALG_SHA_512_224:
                wc_Sha512_224Free(&ctx->ctx.sha512);
                break;
#endif
#if !defined(WOLFSSL_NOSHA512_256)
            case PSA_ALG_SHA_512_256:
                wc_Sha512_256Free(&ctx->ctx.sha512);
                break;
#endif
#endif
#ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
            wc_Sha3_224_Free(&ctx->ctx.sha3);
            break;
        case PSA_ALG_SHA3_256:
            wc_Sha3_256_Free(&ctx->ctx.sha3);
            break;
        case PSA_ALG_SHA3_384:
            wc_Sha3_384_Free(&ctx->ctx.sha3);
            break;
        case PSA_ALG_SHA3_512:
            wc_Sha3_512_Free(&ctx->ctx.sha3);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            wc_Shake256_Free((wc_Shake *)&ctx->ctx.sha3);
            break;
#endif
#ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            wc_AsconHash256_Clear(&ctx->ctx.ascon256);
            break;
#endif
            default:
                break;
        }
    }
}

/* Check if a hash algorithm is supported */
psa_status_t psa_hash_check_alg_supported(psa_algorithm_t alg)
{
    switch (alg) {
#ifdef WOLFSSL_MD5
        case PSA_ALG_MD5:
            return PSA_SUCCESS;
#endif
#ifdef WOLFSSL_RIPEMD
        case PSA_ALG_RIPEMD160:
            return PSA_SUCCESS;
#endif
    #ifndef NO_SHA
        case PSA_ALG_SHA_1:
            return PSA_SUCCESS;
    #endif
    #ifndef NO_SHA256
        case PSA_ALG_SHA_256:
            return PSA_SUCCESS;
    #endif
    #ifdef WOLFSSL_SHA224
        case PSA_ALG_SHA_224:
            return PSA_SUCCESS;
    #endif
    #ifdef WOLFSSL_SHA384
        case PSA_ALG_SHA_384:
            return PSA_SUCCESS;
    #endif
    #ifdef WOLFSSL_SHA512
        case PSA_ALG_SHA_512:
            return PSA_SUCCESS;
    #if !defined(WOLFSSL_NOSHA512_224)
        case PSA_ALG_SHA_512_224:
            return PSA_SUCCESS;
    #endif
    #if !defined(WOLFSSL_NOSHA512_256)
        case PSA_ALG_SHA_512_256:
            return PSA_SUCCESS;
    #endif
    #endif
    #ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
        case PSA_ALG_SHA3_256:
        case PSA_ALG_SHA3_384:
        case PSA_ALG_SHA3_512:
            return PSA_SUCCESS;
    #endif
    #ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            return PSA_SUCCESS;
    #endif
    #ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            return PSA_SUCCESS;
    #endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

/* Get the hash size for a given algorithm */
static size_t psa_hash_get_size(psa_algorithm_t alg)
{
    switch (alg) {
#ifdef WOLFSSL_MD5
        case PSA_ALG_MD5:
            return WC_MD5_DIGEST_SIZE;
#endif
#ifdef WOLFSSL_RIPEMD
        case PSA_ALG_RIPEMD160:
            return RIPEMD_DIGEST_SIZE;
#endif
    #ifndef NO_SHA
        case PSA_ALG_SHA_1:
            return WC_SHA_DIGEST_SIZE;
    #endif
    #ifndef NO_SHA256
        case PSA_ALG_SHA_256:
            return WC_SHA256_DIGEST_SIZE;
    #endif
    #ifdef WOLFSSL_SHA224
        case PSA_ALG_SHA_224:
            return WC_SHA224_DIGEST_SIZE;
    #endif
    #ifdef WOLFSSL_SHA384
        case PSA_ALG_SHA_384:
            return WC_SHA384_DIGEST_SIZE;
    #endif
    #ifdef WOLFSSL_SHA512
        case PSA_ALG_SHA_512:
            return WC_SHA512_DIGEST_SIZE;
    #if !defined(WOLFSSL_NOSHA512_224)
        case PSA_ALG_SHA_512_224:
            return WC_SHA512_224_DIGEST_SIZE;
    #endif
    #if !defined(WOLFSSL_NOSHA512_256)
        case PSA_ALG_SHA_512_256:
            return WC_SHA512_256_DIGEST_SIZE;
    #endif
    #endif
    #ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
            return WC_SHA3_224_DIGEST_SIZE;
        case PSA_ALG_SHA3_256:
            return WC_SHA3_256_DIGEST_SIZE;
        case PSA_ALG_SHA3_384:
            return WC_SHA3_384_DIGEST_SIZE;
        case PSA_ALG_SHA3_512:
            return WC_SHA3_512_DIGEST_SIZE;
    #endif
    #ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            return 64u;
    #endif
    #ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            return ASCON_HASH256_SZ;
    #endif
        default:
            return 0;
    }
}

/* Set up a multi-part hash operation */
psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                           psa_algorithm_t alg)
{
    int ret;
    psa_hash_operation_ctx_t *ctx;
    psa_status_t status;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_trace("psa_hash_setup(alg=0x%08x)", (unsigned)alg);

    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_HASH(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if algorithm is supported */
    status = psa_hash_check_alg_supported(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    ctx = (psa_hash_operation_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                              DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;
    ctx->initialized = 1;

    /* Initialize the hash context based on algorithm */
    switch (alg) {
#ifdef WOLFSSL_MD5
        case PSA_ALG_MD5:
            ret = wc_InitMd5(&ctx->ctx.md5);
            break;
#endif
#ifdef WOLFSSL_RIPEMD
        case PSA_ALG_RIPEMD160:
            ret = wc_InitRipeMd(&ctx->ctx.ripemd);
            break;
#endif
#ifndef NO_SHA
        case PSA_ALG_SHA_1:
            ret = wc_InitSha_ex(&ctx->ctx.sha1, NULL,
                                wolfPSA_GetDefaultDevID());
            break;
#endif
#ifndef NO_SHA256
        case PSA_ALG_SHA_256:
            ret = wc_InitSha256_ex(&ctx->ctx.sha256, NULL,
                                   wolfPSA_GetDefaultDevID());
            break;
#endif
#ifdef WOLFSSL_SHA224
        case PSA_ALG_SHA_224:
            ret = wc_InitSha224_ex(&ctx->ctx.sha224, NULL,
                                   wolfPSA_GetDefaultDevID());
            break;
#endif
#ifdef WOLFSSL_SHA384
        case PSA_ALG_SHA_384:
            ret = wc_InitSha384_ex(&ctx->ctx.sha384, NULL,
                                   wolfPSA_GetDefaultDevID());
            break;
#endif
#ifdef WOLFSSL_SHA512
        case PSA_ALG_SHA_512:
            ret = wc_InitSha512_ex(&ctx->ctx.sha512, NULL,
                                   wolfPSA_GetDefaultDevID());
            break;
#if !defined(WOLFSSL_NOSHA512_224)
        case PSA_ALG_SHA_512_224:
            ret = wc_InitSha512_224_ex(&ctx->ctx.sha512, NULL,
                                       wolfPSA_GetDefaultDevID());
            break;
#endif
#if !defined(WOLFSSL_NOSHA512_256)
        case PSA_ALG_SHA_512_256:
            ret = wc_InitSha512_256_ex(&ctx->ctx.sha512, NULL,
                                       wolfPSA_GetDefaultDevID());
            break;
#endif
#endif
#ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
            ret = wc_InitSha3_224(&ctx->ctx.sha3, NULL, wolfPSA_GetDefaultDevID());
            break;
        case PSA_ALG_SHA3_256:
            ret = wc_InitSha3_256(&ctx->ctx.sha3, NULL, wolfPSA_GetDefaultDevID());
            break;
        case PSA_ALG_SHA3_384:
            ret = wc_InitSha3_384(&ctx->ctx.sha3, NULL, wolfPSA_GetDefaultDevID());
            break;
        case PSA_ALG_SHA3_512:
            ret = wc_InitSha3_512(&ctx->ctx.sha3, NULL, wolfPSA_GetDefaultDevID());
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            ret = wc_InitShake256((wc_Shake *)&ctx->ctx.sha3, NULL,
                                  wolfPSA_GetDefaultDevID());
            break;
#endif
#ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            ret = wc_AsconHash256_Init(&ctx->ctx.ascon256);
            break;
#endif
        default:
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ret != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    ctx->started = 1;
    operation->opaque = (uintptr_t)ctx;

    return PSA_SUCCESS;
}

/* Add a message fragment to a multi-part hash operation */
psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length)
{
    int ret;
    psa_hash_operation_ctx_t *ctx = psa_hash_get_ctx(operation);

    if (operation == NULL || (input == NULL && input_length > 0)) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }

    if (ctx == NULL || !ctx->initialized || !ctx->started) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_BAD_STATE);
    }

    if (ctx->finalized) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_BAD_STATE);
    }
    if (wolfpsa_check_word32_length(input_length) != PSA_SUCCESS) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }

    /* Update the hash context based on algorithm */
    switch (ctx->alg) {
#ifdef WOLFSSL_MD5
        case PSA_ALG_MD5:
            ret = wc_Md5Update(&ctx->ctx.md5, input, (word32)input_length);
            break;
#endif
#ifdef WOLFSSL_RIPEMD
        case PSA_ALG_RIPEMD160:
            ret = wc_RipeMdUpdate(&ctx->ctx.ripemd, input,
                                  (word32)input_length);
            break;
#endif
#ifndef NO_SHA
        case PSA_ALG_SHA_1:
            ret = wc_ShaUpdate(&ctx->ctx.sha1, input, (word32)input_length);
            break;
#endif
#ifndef NO_SHA256
        case PSA_ALG_SHA_256:
            ret = wc_Sha256Update(&ctx->ctx.sha256, input, (word32)input_length);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case PSA_ALG_SHA_224:
            ret = wc_Sha224Update(&ctx->ctx.sha224, input, (word32)input_length);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case PSA_ALG_SHA_384:
            ret = wc_Sha384Update(&ctx->ctx.sha384, input, (word32)input_length);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case PSA_ALG_SHA_512:
            ret = wc_Sha512Update(&ctx->ctx.sha512, input, (word32)input_length);
            break;
#if !defined(WOLFSSL_NOSHA512_224)
        case PSA_ALG_SHA_512_224:
            ret = wc_Sha512_224Update(&ctx->ctx.sha512, input,
                                      (word32)input_length);
            break;
#endif
#if !defined(WOLFSSL_NOSHA512_256)
        case PSA_ALG_SHA_512_256:
            ret = wc_Sha512_256Update(&ctx->ctx.sha512, input,
                                      (word32)input_length);
            break;
#endif
#endif
#ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
            ret = wc_Sha3_224_Update(&ctx->ctx.sha3, input,
                                     (word32)input_length);
            break;
        case PSA_ALG_SHA3_256:
            ret = wc_Sha3_256_Update(&ctx->ctx.sha3, input,
                                     (word32)input_length);
            break;
        case PSA_ALG_SHA3_384:
            ret = wc_Sha3_384_Update(&ctx->ctx.sha3, input,
                                     (word32)input_length);
            break;
        case PSA_ALG_SHA3_512:
            ret = wc_Sha3_512_Update(&ctx->ctx.sha3, input,
                                     (word32)input_length);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            ret = wc_Shake256_Update((wc_Shake *)&ctx->ctx.sha3, input,
                                     (word32)input_length);
            break;
#endif
#ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            ret = wc_AsconHash256_Update(&ctx->ctx.ascon256, input,
                                         (word32)input_length);
            break;
#endif
        default:
            return wolfpsa_hash_fail(operation, PSA_ERROR_NOT_SUPPORTED);
    }
    
    if (ret != 0) {
        return wolfpsa_hash_fail(operation, wc_error_to_psa_status(ret));
    }
    
    return PSA_SUCCESS;
}

/* Finish the calculation of the hash of a message */
psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                            uint8_t *hash,
                            size_t hash_size,
                            size_t *hash_length)
{
    int ret;
    size_t expected_hash_size;
    psa_hash_operation_ctx_t *ctx = psa_hash_get_ctx(operation);

    /* A NULL hash pointer is only an error when the caller declared a
     * nonzero capacity; (NULL, 0) must reach the size check below. */
    if (operation == NULL || hash_length == NULL ||
        (hash == NULL && hash_size != 0)) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }

    if (ctx == NULL || !ctx->initialized || !ctx->started) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_BAD_STATE);
    }

    if (ctx->finalized) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_BAD_STATE);
    }

    /* Get the expected hash size */
    expected_hash_size = psa_hash_get_size(ctx->alg);
    if (expected_hash_size == 0) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_NOT_SUPPORTED);
    }
    
    /* Check if the output buffer is large enough */
    if (hash_size < expected_hash_size) {
        return wolfpsa_hash_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
    }
    
    /* Finalize the hash based on algorithm */
    switch (ctx->alg) {
#ifdef WOLFSSL_MD5
        case PSA_ALG_MD5:
            ret = wc_Md5Final(&ctx->ctx.md5, hash);
            break;
#endif
#ifdef WOLFSSL_RIPEMD
        case PSA_ALG_RIPEMD160:
            ret = wc_RipeMdFinal(&ctx->ctx.ripemd, hash);
            break;
#endif
#ifndef NO_SHA
        case PSA_ALG_SHA_1:
            ret = wc_ShaFinal(&ctx->ctx.sha1, hash);
            break;
#endif
#ifndef NO_SHA256
        case PSA_ALG_SHA_256:
            ret = wc_Sha256Final(&ctx->ctx.sha256, hash);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case PSA_ALG_SHA_224:
            ret = wc_Sha224Final(&ctx->ctx.sha224, hash);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case PSA_ALG_SHA_384:
            ret = wc_Sha384Final(&ctx->ctx.sha384, hash);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case PSA_ALG_SHA_512:
            ret = wc_Sha512Final(&ctx->ctx.sha512, hash);
            break;
#if !defined(WOLFSSL_NOSHA512_224)
        case PSA_ALG_SHA_512_224:
            ret = wc_Sha512_224Final(&ctx->ctx.sha512, hash);
            break;
#endif
#if !defined(WOLFSSL_NOSHA512_256)
        case PSA_ALG_SHA_512_256:
            ret = wc_Sha512_256Final(&ctx->ctx.sha512, hash);
            break;
#endif
#endif
#ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
            ret = wc_Sha3_224_Final(&ctx->ctx.sha3, hash);
            break;
        case PSA_ALG_SHA3_256:
            ret = wc_Sha3_256_Final(&ctx->ctx.sha3, hash);
            break;
        case PSA_ALG_SHA3_384:
            ret = wc_Sha3_384_Final(&ctx->ctx.sha3, hash);
            break;
        case PSA_ALG_SHA3_512:
            ret = wc_Sha3_512_Final(&ctx->ctx.sha3, hash);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            ret = wc_Shake256_Final((wc_Shake *)&ctx->ctx.sha3, hash, 64u);
            break;
#endif
#ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            ret = wc_AsconHash256_Final(&ctx->ctx.ascon256, hash);
            break;
#endif
        default:
            return wolfpsa_hash_fail(operation, PSA_ERROR_NOT_SUPPORTED);
    }

    if (ret != 0) {
        return wolfpsa_hash_fail(operation, wc_error_to_psa_status(ret));
    }

    *hash_length = expected_hash_size;
    ctx->finalized = 1;
    psa_hash_cleanup_ctx(ctx);
    wc_ForceZero(ctx, sizeof(*ctx));
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    operation->opaque = (uintptr_t)NULL;

    return PSA_SUCCESS;
}

/* Finish the calculation of the hash and compare to expected value */
psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                            const uint8_t *hash,
                            size_t hash_length)
{
    psa_status_t status;
    uint8_t computed_hash[WOLFPSA_HASH_MAX_SIZE];
    size_t computed_hash_length;

    /* A NULL reference is only an argument error when it claims a length;
     * (NULL, 0) is a length mismatch, which the check below reports as
     * INVALID_SIGNATURE, matching psa_hash_compare(). */
    if (operation == NULL || (hash == NULL && hash_length != 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_hash_finish(operation, computed_hash, sizeof(computed_hash),
                             &computed_hash_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    if (hash_length != computed_hash_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    if (ConstantCompare(computed_hash, hash, (int)computed_hash_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = PSA_SUCCESS;

cleanup:
    wc_ForceZero(computed_hash, sizeof(computed_hash));
    return status;
}

/* Abort a hash operation */
psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
    psa_hash_operation_ctx_t *ctx;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ctx = psa_hash_get_ctx(operation);
    if (ctx == NULL) {
        return PSA_SUCCESS;
    }

    psa_hash_cleanup_ctx(ctx);
    wc_ForceZero(ctx, sizeof(*ctx));
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    operation->opaque = (uintptr_t)NULL;

    return PSA_SUCCESS;
}

/* Clone a hash operation */
psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
                           psa_hash_operation_t *target_operation)
{
    int ret = 0;
    const psa_hash_operation_ctx_t *source_ctx;
    psa_hash_operation_ctx_t *target_ctx;

    if (source_operation == NULL || target_operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (target_operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    source_ctx = psa_hash_get_ctx_const(source_operation);
    if (source_ctx == NULL || !source_ctx->initialized || !source_ctx->started) {
        return PSA_ERROR_BAD_STATE;
    }

    if (source_ctx->finalized) {
        return PSA_ERROR_BAD_STATE;
    }

    target_ctx = (psa_hash_operation_ctx_t *)XMALLOC(sizeof(*target_ctx), NULL,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (target_ctx == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    XMEMSET(target_ctx, 0, sizeof(*target_ctx));
    target_ctx->alg = source_ctx->alg;
    target_ctx->initialized = source_ctx->initialized;
    target_ctx->started = source_ctx->started;
    target_ctx->finalized = source_ctx->finalized;

    /* Clone the hash context based on algorithm */
    switch (source_ctx->alg) {
#ifdef WOLFSSL_MD5
        case PSA_ALG_MD5:
            ret = wc_Md5Copy((wc_Md5 *)(uintptr_t)&source_ctx->ctx.md5,
                             &target_ctx->ctx.md5);
            break;
#endif
#ifdef WOLFSSL_RIPEMD
        case PSA_ALG_RIPEMD160:
            XMEMCPY(&target_ctx->ctx.ripemd, &source_ctx->ctx.ripemd,
                    sizeof(RipeMd));
            ret = 0;
            break;
#endif
#ifndef NO_SHA
        case PSA_ALG_SHA_1:
            ret = wc_ShaCopy((wc_Sha *)(uintptr_t)&source_ctx->ctx.sha1,
                             &target_ctx->ctx.sha1);
            break;
#endif
#ifndef NO_SHA256
        case PSA_ALG_SHA_256:
            ret = wc_Sha256Copy((wc_Sha256 *)(uintptr_t)&source_ctx->ctx.sha256,
                                &target_ctx->ctx.sha256);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case PSA_ALG_SHA_224:
            ret = wc_Sha224Copy((wc_Sha224 *)(uintptr_t)&source_ctx->ctx.sha224,
                                &target_ctx->ctx.sha224);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case PSA_ALG_SHA_384:
            ret = wc_Sha384Copy((wc_Sha384 *)(uintptr_t)&source_ctx->ctx.sha384,
                                &target_ctx->ctx.sha384);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case PSA_ALG_SHA_512:
            ret = wc_Sha512Copy((wc_Sha512 *)(uintptr_t)&source_ctx->ctx.sha512,
                                &target_ctx->ctx.sha512);
            break;
#if !defined(WOLFSSL_NOSHA512_224)
        case PSA_ALG_SHA_512_224:
            ret = wc_Sha512_224Copy((wc_Sha512 *)(uintptr_t)&source_ctx->ctx.sha512,
                                    &target_ctx->ctx.sha512);
            break;
#endif
#if !defined(WOLFSSL_NOSHA512_256)
        case PSA_ALG_SHA_512_256:
            ret = wc_Sha512_256Copy((wc_Sha512 *)(uintptr_t)&source_ctx->ctx.sha512,
                                    &target_ctx->ctx.sha512);
            break;
#endif
#endif
#ifdef WOLFSSL_SHA3
        case PSA_ALG_SHA3_224:
            ret = wc_Sha3_224_Copy((wc_Sha3 *)(uintptr_t)&source_ctx->ctx.sha3,
                                   &target_ctx->ctx.sha3);
            break;
        case PSA_ALG_SHA3_256:
            ret = wc_Sha3_256_Copy((wc_Sha3 *)(uintptr_t)&source_ctx->ctx.sha3,
                                   &target_ctx->ctx.sha3);
            break;
        case PSA_ALG_SHA3_384:
            ret = wc_Sha3_384_Copy((wc_Sha3 *)(uintptr_t)&source_ctx->ctx.sha3,
                                   &target_ctx->ctx.sha3);
            break;
        case PSA_ALG_SHA3_512:
            ret = wc_Sha3_512_Copy((wc_Sha3 *)(uintptr_t)&source_ctx->ctx.sha3,
                                   &target_ctx->ctx.sha3);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256_512:
            ret = wc_Shake256_Copy((wc_Shake *)(uintptr_t)&source_ctx->ctx.sha3,
                                   &target_ctx->ctx.sha3);
            break;
#endif
#ifdef HAVE_ASCON
        case PSA_ALG_ASCON_HASH256:
            XMEMCPY(&target_ctx->ctx.ascon256, &source_ctx->ctx.ascon256,
                    sizeof(wc_AsconHash256));
            ret = 0;
            break;
#endif
        default:
            wc_ForceZero(target_ctx, sizeof(*target_ctx));
            XFREE(target_ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ret != 0) {
        psa_hash_cleanup_ctx(target_ctx);
        wc_ForceZero(target_ctx, sizeof(*target_ctx));
        XFREE(target_ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    target_operation->opaque = (uintptr_t)target_ctx;
    return PSA_SUCCESS;
}

/* Calculate the hash (digest) of a message */
psa_status_t psa_hash_compute(psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length)
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status;

    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    
    /* Set up the operation */
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    
    /* Add the input */
    status = psa_hash_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return status;
    }
    
    /* Finish the operation */
    status = psa_hash_finish(&operation, hash, hash_size, hash_length);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return status;
    }
    
    return PSA_SUCCESS;
}

/* Calculate the hash (digest) of a message and compare it with a reference value */
psa_status_t psa_hash_compare(psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             const uint8_t *hash,
                             size_t hash_length)
{
    psa_status_t status;
    uint8_t computed_hash[WOLFPSA_HASH_MAX_SIZE];
    size_t computed_hash_length;
    size_t expected_hash_size;

    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    
    /* Check if the algorithm is a supported hash */
    if (!PSA_ALG_IS_HASH(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    expected_hash_size = psa_hash_get_size(alg);
    if (expected_hash_size == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* A zero-length reference cannot match a fixed-size digest; it is a
     * verification mismatch, not an invalid argument. */
    if (hash_length != expected_hash_size) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    /* The length check above guarantees a nonzero length here, so a NULL
     * reference pointer is a caller error. */
    if (hash == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Compute the hash */
    status = psa_hash_compute(alg, input, input_length, computed_hash,
                             sizeof(computed_hash), &computed_hash_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    
    /* Compare the computed hash with the reference hash */
    if (ConstantCompare(computed_hash, hash, (int)computed_hash_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }
    
    status = PSA_SUCCESS;

cleanup:
    wc_ForceZero(computed_hash, sizeof(computed_hash));
    return status;
}

#endif /* WOLFSSL_PSA_ENGINE */
