/* mbedtls3.c
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

/* Mbed TLS 3.6 names that 4.x removed or made private (MBEDTLS_COMPAT=1), for
 * applications built with WOLFPSA_MBEDTLS_3. Defined here before any include,
 * so the 3.6 declarations are checked against these functions. */

#ifndef WOLFPSA_MBEDTLS_3
    #define WOLFPSA_MBEDTLS_3
#endif /* !WOLFPSA_MBEDTLS_3 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfpsa/psa_engine.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>

#ifdef MBEDTLS_THREADING_C
#define MBED_LOCK(m)   mbedtls_mutex_lock(m)
#define MBED_UNLOCK(m) (void)mbedtls_mutex_unlock(m)
#else
#define MBED_LOCK(m)   0
#define MBED_UNLOCK(m) WC_DO_NOTHING
#endif /* MBEDTLS_THREADING_C */

#if defined(MBEDTLS_SSL_TLS_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
/* By the bytes of the TLS version */
void mbedtls_ssl_conf_min_version(mbedtls_ssl_config* conf, int major,
    int minor)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_min_version");

    mbedtls_ssl_conf_min_tls_version(conf,
        (mbedtls_ssl_protocol_version)((major << 8) | minor));
}

void mbedtls_ssl_conf_max_version(mbedtls_ssl_config* conf, int major,
    int minor)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_max_version");

    mbedtls_ssl_conf_max_tls_version(conf,
        (mbedtls_ssl_protocol_version)((major << 8) | minor));
}
#endif /* MBEDTLS_SSL_TLS_C && !MBEDTLS_DEPRECATED_REMOVED */

#ifdef MBEDTLS_SSL_TLS_C
/* wolfSSL draws its own random numbers */
void mbedtls_ssl_conf_rng(mbedtls_ssl_config* conf,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
    WOLFSSL_ENTER("mbedtls_ssl_conf_rng");

    (void)conf;
    (void)f_rng;
    (void)p_rng;
}
#endif /* MBEDTLS_SSL_TLS_C */

#ifdef MBEDTLS_ENTROPY_C
#ifdef MBEDTLS_ENTROPY_SHA512_ACCUMULATOR
#define MBED_ENTROPY_HASH WC_HASH_TYPE_SHA512
#else
#define MBED_ENTROPY_HASH WC_HASH_TYPE_SHA256
#endif /* MBEDTLS_ENTROPY_SHA512_ACCUMULATOR */
/* As Mbed TLS: polls before failing, and the platform source's threshold */
#define MBED_ENTROPY_MAX_LOOP    256
#define MBED_ENTROPY_MIN_DEFAULT 32

/* The default source, in place of Mbed TLS's platform source */
static int MbedEntropyDefault(void* data, unsigned char* output, size_t len,
    size_t* olen)
{
    WC_RNG rng;
    int ret;

    (void)data;
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, output, (word32)len);
        (void)wc_FreeRng(&rng);
    }
    if (ret != 0) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *olen = len;
    return 0;
}

void mbedtls_entropy_init(mbedtls_entropy_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_entropy_init");

    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(*ctx));
#ifdef MBEDTLS_THREADING_C
        mbedtls_mutex_init(&ctx->mutex);
#endif /* MBEDTLS_THREADING_C */
        (void)mbedtls_entropy_add_source(ctx, MbedEntropyDefault, NULL,
            MBED_ENTROPY_MIN_DEFAULT, MBEDTLS_ENTROPY_SOURCE_STRONG);
    }
}

void mbedtls_entropy_free(mbedtls_entropy_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_entropy_free");

    if (ctx != NULL) {
#ifdef MBEDTLS_THREADING_C
        mbedtls_mutex_free(&ctx->mutex);
#endif /* MBEDTLS_THREADING_C */
        wc_ForceZero(ctx, sizeof(*ctx));
    }
}

int mbedtls_entropy_add_source(mbedtls_entropy_context* ctx,
    mbedtls_entropy_f_source_ptr f_source, void* p_source, size_t threshold,
    int strong)
{
    mbedtls_entropy_source_state* src;
    int ret;

    WOLFSSL_ENTER("mbedtls_entropy_add_source");

    if (ctx == NULL || f_source == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    ret = MBED_LOCK(&ctx->mutex);
    if (ret == 0) {
        if (ctx->source_count >= MBEDTLS_ENTROPY_MAX_SOURCES) {
            ret = MBEDTLS_ERR_ENTROPY_MAX_SOURCES;
        }
        else {
            src = &ctx->source[ctx->source_count++];
            src->f_source = f_source;
            src->p_source = p_source;
            src->size = 0;
            src->threshold = threshold;
            src->strong = strong;
        }
        MBED_UNLOCK(&ctx->mutex);
    }
    return ret;
}

/* Polls each source once. done: thresholds met, a block from strong ones */
static int MbedEntropyGather(mbedtls_entropy_context* ctx, wc_HashAlg* hash,
    int* done)
{
    mbedtls_entropy_source_state* src;
    byte buf[MBEDTLS_ENTROPY_MAX_GATHER];
    byte header[2];
    size_t strong = 0;
    size_t olen;
    int ret = 0;
    int i;

    *done = 1;
    for (i = 0; ret == 0 && i < ctx->source_count; i++) {
        src = &ctx->source[i];
        olen = 0;
        ret = src->f_source(src->p_source, buf, sizeof(buf), &olen);
        if (ret == 0 && olen > sizeof(buf)) {
            ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        if (ret == 0 && olen > 0) {
            /* As Mbed TLS: the source and length before the data */
            header[0] = (byte)i;
            header[1] = (byte)olen;
            if (wc_HashUpdate(hash, MBED_ENTROPY_HASH, header,
                    sizeof(header)) != 0 ||
                    wc_HashUpdate(hash, MBED_ENTROPY_HASH, buf,
                    (word32)olen) != 0) {
                ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            }
            src->size += olen;
        }
        if (src->size < src->threshold) {
            *done = 0;
        }
        if (src->strong == MBEDTLS_ENTROPY_SOURCE_STRONG) {
            strong += src->size;
        }
    }
    if (strong < MBEDTLS_ENTROPY_BLOCK_SIZE) {
        *done = 0;
    }
    wc_ForceZero(buf, sizeof(buf));
    return ret;
}

int mbedtls_entropy_func(void* data, unsigned char* output, size_t len)
{
    mbedtls_entropy_context* ctx = (mbedtls_entropy_context*)data;
    wc_HashAlg hash;
    byte digest[MBEDTLS_ENTROPY_BLOCK_SIZE];
    int rounds = 0;
    int done = 0;
    int ret;
    int i;

    WOLFSSL_ENTER("mbedtls_entropy_func");

    if (ctx == NULL || (output == NULL && len > 0) || len > sizeof(digest)) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    ret = MBED_LOCK(&ctx->mutex);
    if (ret != 0) {
        return ret;
    }
    if (ctx->source_count == 0) {
        ret = MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED;
    }
    else if (wc_HashInit_ex(&hash, MBED_ENTROPY_HASH, NULL,
            wolfPSA_GetDefaultDevID()) != 0) {
        ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    else {
        while (ret == 0 && !done) {
            if (rounds++ == MBED_ENTROPY_MAX_LOOP) {
                ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            }
            else {
                ret = MbedEntropyGather(ctx, &hash, &done);
            }
        }
        if (ret == 0 && wc_HashFinal(&hash, MBED_ENTROPY_HASH, digest) != 0) {
            ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        (void)wc_HashFree(&hash, MBED_ENTROPY_HASH);
    }
    if (ret == 0 && len > 0) {
        XMEMCPY(output, digest, len);
    }
    for (i = 0; i < ctx->source_count; i++) {
        ctx->source[i].size = 0;
    }
    wc_ForceZero(digest, sizeof(digest));
    MBED_UNLOCK(&ctx->mutex);
    return ret;
}
#endif /* MBEDTLS_ENTROPY_C */

#ifdef MBEDTLS_CTR_DRBG_C
/* seed: MBEDTLS_CTR_DRBG_ENTROPY_LEN bytes from f_entropy, then add */
static int MbedDrbgSeedInput(int (*f_entropy)(void*, unsigned char*, size_t),
    void* p_entropy, const unsigned char* add, size_t addLen,
    byte seed[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT], word32* seedLen)
{
    if (addLen > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT -
            MBEDTLS_CTR_DRBG_ENTROPY_LEN) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }
    if (f_entropy(p_entropy, seed, MBEDTLS_CTR_DRBG_ENTROPY_LEN) != 0) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    *seedLen = MBEDTLS_CTR_DRBG_ENTROPY_LEN;
    /* NULL add is empty, as in Mbed TLS */
    if (add != NULL && addLen > 0) {
        XMEMCPY(seed + *seedLen, add, addLen);
        *seedLen += (word32)addLen;
    }
    return 0;
}

/* Called with the context locked */
static int MbedDrbgReseed(mbedtls_ctr_drbg_context* ctx,
    const unsigned char* additional, size_t len)
{
    byte seed[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT];
    word32 seedLen = 0;
    int ret;

    ret = MbedDrbgSeedInput(ctx->f_entropy, ctx->p_entropy, additional, len,
        seed, &seedLen);
    if (ret == 0 && wc_RNG_DRBG_Reseed(ctx->rng, seed, seedLen) != 0) {
        ret = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    if (ret == 0) {
        ctx->reseed_counter = 0;
    }
    wc_ForceZero(seed, sizeof(seed));
    return ret;
}

/* Frees what mbedtls_ctr_drbg_seed() made */
static void MbedDrbgUnseed(mbedtls_ctr_drbg_context* ctx)
{
#ifdef MBEDTLS_THREADING_C
    mbedtls_mutex_free(&ctx->mutex);
#endif /* MBEDTLS_THREADING_C */
    wc_rng_free(ctx->rng);
    ctx->rng = NULL;
}

void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_ctr_drbg_init");

    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
}

void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_ctr_drbg_free");

    if (ctx != NULL) {
        MbedDrbgUnseed(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
}

int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context* ctx,
    int (*f_entropy)(void*, unsigned char*, size_t), void* p_entropy,
    const unsigned char* custom, size_t len)
{
    byte seed[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT];
    word32 seedLen = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_ctr_drbg_seed");

    if (ctx == NULL || f_entropy == NULL) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    MbedDrbgUnseed(ctx);
    ret = MbedDrbgSeedInput(f_entropy, p_entropy, custom, len, seed,
        &seedLen);
    /* wolfCrypt seeds its DRBG itself, with the seed input as the nonce */
    if (ret == 0 && wc_rng_new_ex(&ctx->rng, seed, seedLen, NULL,
            wolfPSA_GetDefaultDevID()) != 0) {
        ret = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    if (ret == 0) {
        ctx->f_entropy = f_entropy;
        ctx->p_entropy = p_entropy;
        ctx->reseed_counter = 0;
#ifdef MBEDTLS_THREADING_C
        mbedtls_mutex_init(&ctx->mutex);
#endif /* MBEDTLS_THREADING_C */
    }
    wc_ForceZero(seed, sizeof(seed));
    return ret;
}

void mbedtls_ctr_drbg_set_prediction_resistance(mbedtls_ctr_drbg_context* ctx,
    int resistance)
{
    WOLFSSL_ENTER("mbedtls_ctr_drbg_set_prediction_resistance");

    if (ctx != NULL) {
        ctx->prediction_resistance = resistance;
    }
}

int mbedtls_ctr_drbg_reseed(mbedtls_ctr_drbg_context* ctx,
    const unsigned char* additional, size_t len)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_ctr_drbg_reseed");

    if (ctx == NULL || ctx->rng == NULL) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    ret = MBED_LOCK(&ctx->mutex);
    if (ret == 0) {
        ret = MbedDrbgReseed(ctx, additional, len);
        MBED_UNLOCK(&ctx->mutex);
    }
    return ret;
}

int mbedtls_ctr_drbg_random(void* p_rng, unsigned char* output,
    size_t output_len)
{
    mbedtls_ctr_drbg_context* ctx = (mbedtls_ctr_drbg_context*)p_rng;
    int ret;

    WOLFSSL_ENTER("mbedtls_ctr_drbg_random");

    if (output_len > MBEDTLS_CTR_DRBG_MAX_REQUEST) {
        return MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG;
    }
    if (ctx == NULL || ctx->rng == NULL || (output == NULL && output_len > 0)) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    ret = MBED_LOCK(&ctx->mutex);
    if (ret == 0) {
        if (ctx->prediction_resistance ||
                ctx->reseed_counter >= MBEDTLS_CTR_DRBG_RESEED_INTERVAL) {
            ret = MbedDrbgReseed(ctx, NULL, 0);
        }
        if (ret == 0 && output_len > 0 && wc_RNG_GenerateBlock(ctx->rng,
                output, (word32)output_len) != 0) {
            ret = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
        }
        if (ret == 0) {
            ctx->reseed_counter++;
        }
        MBED_UNLOCK(&ctx->mutex);
    }
    return ret;
}
#endif /* MBEDTLS_CTR_DRBG_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
