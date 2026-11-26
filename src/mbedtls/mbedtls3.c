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

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfpsa/psa_engine.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include "psa_tf_psa_internal.h"

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
#if defined(CUSTOM_RAND_GENERATE_BLOCK) || defined(WC_RNG_SEED_CB)
    /* No wc_GenerateSeed, or not the seed source the RNG uses */
    WC_RNG rng;
#else
    OS_Seed os;
#endif /* CUSTOM_RAND_GENERATE_BLOCK || WC_RNG_SEED_CB */
    int ret;

    (void)data;
#if defined(CUSTOM_RAND_GENERATE_BLOCK) || defined(WC_RNG_SEED_CB)
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, output, (word32)len);
        (void)wc_FreeRng(&rng);
    }
#else
    XMEMSET(&os, 0, sizeof(os));
    ret = wc_GenerateSeed(&os, output, (word32)len);
#endif /* CUSTOM_RAND_GENERATE_BLOCK || WC_RNG_SEED_CB */
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
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
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
/* seed: MBEDTLS_CTR_DRBG_ENTROPY_LEN bytes from f_entropy, nonceLen more in
 * a second call, then add */
static int MbedDrbgSeedInput(int (*f_entropy)(void*, unsigned char*, size_t),
    void* p_entropy, size_t nonceLen, const unsigned char* add, size_t addLen,
    byte seed[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT], word32* seedLen)
{
    if (addLen > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT -
            MBEDTLS_CTR_DRBG_ENTROPY_LEN - nonceLen) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }
    if (f_entropy(p_entropy, seed, MBEDTLS_CTR_DRBG_ENTROPY_LEN) != 0) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    *seedLen = MBEDTLS_CTR_DRBG_ENTROPY_LEN;
    if (nonceLen > 0) {
        if (f_entropy(p_entropy, seed + *seedLen, nonceLen) != 0) {
            return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
        }
        *seedLen += (word32)nonceLen;
    }
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

    ret = MbedDrbgSeedInput(ctx->f_entropy, ctx->p_entropy, 0, additional,
        len, seed, &seedLen);
#ifdef WC_RNG_HAVE_RESEED_NOW
    /* From wolfCrypt's seed source, the input uncredited */
    if (ret == 0 && wc_RNG_DRBG_Reseed_Now(ctx->rng, seed, seedLen) != 0) {
        ret = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
#else
    if (ret == 0 && wc_RNG_DRBG_Reseed(ctx->rng, seed, seedLen) != 0) {
        ret = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
#endif /* WC_RNG_HAVE_RESEED_NOW */
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
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }
    MbedDrbgUnseed(ctx);
    ret = MbedDrbgSeedInput(f_entropy, p_entropy,
        MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN, custom, len, seed, &seedLen);
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

struct mbedtls_pk_info_t {
    mbedtls_pk_type_t type;
    int ctxType;
};

/* The first entry of each pk type is its info */
static const mbedtls_pk_info_t pkInfo[] = {
#ifndef NO_RSA
    { MBEDTLS_PK_RSA, PK_TYPE_RSA },
    { MBEDTLS_PK_RSA, PK_TYPE_RSA_PUBLIC },
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    { MBEDTLS_PK_ECKEY, PK_TYPE_ECC },
    { MBEDTLS_PK_ECKEY, PK_TYPE_ECC_PUBLIC },
#endif /* HAVE_ECC */
#if defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
    { MBEDTLS_PK_ECKEY, PK_TYPE_MONTGOMERY_PUBLIC }
#endif /* HAVE_CURVE25519 || HAVE_CURVE448 */
};

const mbedtls_pk_info_t* mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type)
{
    size_t i;

    for (i = 0; i < XELEM_CNT(pkInfo); i++) {
        if (pkInfo[i].type == pk_type) {
            return &pkInfo[i];
        }
    }
    return NULL;
}

/* No key until mbedtls_ecp_gen_key() or mbedtls_rsa_gen_key() */
int mbedtls_pk_setup(mbedtls_pk_context* ctx, const mbedtls_pk_info_t* info)
{
    WOLFSSL_ENTER("mbedtls_pk_setup");

    if (ctx == NULL || info == NULL || ctx->type != PK_TYPE_NONE) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    ctx->type = info->ctxType;
    return 0;
}

mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context* ctx)
{
    size_t i;

    for (i = 0; ctx != NULL && i < XELEM_CNT(pkInfo); i++) {
        if (pkInfo[i].ctxType == ctx->type) {
            return pkInfo[i].type;
        }
    }
    return MBEDTLS_PK_NONE;
}

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(NO_ASN)
    #define MBED_ECP_GEN
#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT && !NO_ASN */
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
        !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(NO_ASN)
    #define MBED_RSA_GEN
#endif /* !NO_RSA && WOLFSSL_KEY_GEN && !WOLFSSL_RSA_PUBLIC_ONLY && !NO_ASN */

#if defined(MBED_ECP_GEN) || defined(MBED_RSA_GEN)
/* ctx takes der, of a new key, when ret is 0. Else der is freed. */
static int MbedPkTakeKey(mbedtls_pk_context* ctx, int ret, unsigned char* der,
    int len)
{
    if (ret == 0) {
        return wolfPSA_MbedPkSetKey(ctx, der, (size_t)len);
    }
    if (der != NULL) {
        mbedtls_platform_zeroize(der, (size_t)len);
        XFREE(der, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    }
    return ret;
}
#endif /* MBED_ECP_GEN || MBED_RSA_GEN */

#ifdef MBED_ECP_GEN
extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);

/* The PSA curve of each group. pk has Montgomery public keys only. */
static const struct {
    mbedtls_ecp_group_id id;
    psa_ecc_family_t family;
    size_t bits;
} ecpGroups[] = {
    { MBEDTLS_ECP_DP_SECP192R1, PSA_ECC_FAMILY_SECP_R1, 192 },
    { MBEDTLS_ECP_DP_SECP224R1, PSA_ECC_FAMILY_SECP_R1, 224 },
    { MBEDTLS_ECP_DP_SECP256R1, PSA_ECC_FAMILY_SECP_R1, 256 },
    { MBEDTLS_ECP_DP_SECP384R1, PSA_ECC_FAMILY_SECP_R1, 384 },
    { MBEDTLS_ECP_DP_SECP521R1, PSA_ECC_FAMILY_SECP_R1, 521 },
    { MBEDTLS_ECP_DP_BP256R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 256 },
    { MBEDTLS_ECP_DP_BP384R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 384 },
    { MBEDTLS_ECP_DP_BP512R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 512 },
    { MBEDTLS_ECP_DP_SECP192K1, PSA_ECC_FAMILY_SECP_K1, 192 },
    { MBEDTLS_ECP_DP_SECP224K1, PSA_ECC_FAMILY_SECP_K1, 224 },
    { MBEDTLS_ECP_DP_SECP256K1, PSA_ECC_FAMILY_SECP_K1, 256 }
};

/* wolfCrypt's curve for the group, if the PSA engine has it */
static int MbedEcpCurveId(mbedtls_ecp_group_id id)
{
    size_t i;

    for (i = 0; i < XELEM_CNT(ecpGroups); i++) {
        if (ecpGroups[i].id == id) {
            return wc_psa_get_ecc_curve_id(
                PSA_KEY_TYPE_ECC_KEY_PAIR(ecpGroups[i].family),
                ecpGroups[i].bits);
        }
    }
    return ECC_CURVE_INVALID;
}

/* From wolfCrypt's RNG, as PSA keys: f_rng is not used */
int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair* key,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
    mbedtls_pk_context* ctx = (mbedtls_pk_context*)key;
    int curveId = MbedEcpCurveId(grp_id);
    /* Fails for a curve the PSA engine lists but wolfCrypt left out */
    int keySz = wc_ecc_get_curve_size_from_id(curveId);
    unsigned char* der = NULL;
    ecc_key* ecc = NULL;
    WC_RNG rng;
    int len = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_ecp_gen_key");
    (void)f_rng;
    (void)p_rng;

    if (ctx == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (keySz <= 0) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret == 0) {
        ecc = wc_ecc_key_new_ex(NULL, wolfPSA_GetDefaultDevID());
        if (ecc == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0) {
            ret = wc_ecc_make_key_ex(&rng, keySz, ecc, curveId);
        }
        if (ret == 0) {
            ret = wc_EccKeyDerSize(ecc, 1);
        }
        if (ret > 0) {
            len = ret;
            der = (unsigned char*)XMALLOC((size_t)len, NULL,
                DYNAMIC_TYPE_PRIVATE_KEY);
            ret = (der == NULL) ? MEMORY_E :
                wc_EccKeyToDer(ecc, der, (word32)len);
        }
        if (ret > 0) {
            len = ret;
            ret = 0;
        }
        wc_ecc_key_free(ecc);
        (void)wc_FreeRng(&rng);
    }
    return MbedPkTakeKey(ctx, (int)wc_error_to_psa_status(ret), der, len);
}
#else
int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair* key,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
    (void)grp_id;
    (void)key;
    (void)f_rng;
    (void)p_rng;
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}
#endif /* MBED_ECP_GEN */

size_t mbedtls_rsa_get_len(const mbedtls_rsa_context* ctx)
{
    return (mbedtls_pk_get_bitlen((const mbedtls_pk_context*)ctx) + 7) / 8;
}

#ifdef MBED_RSA_GEN
/* From wolfCrypt's RNG, as PSA keys: f_rng is not used */
int mbedtls_rsa_gen_key(mbedtls_rsa_context* ctx,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng,
    unsigned int nbits, int exponent)
{
    mbedtls_pk_context* pk = (mbedtls_pk_context*)ctx;
    unsigned char* der = NULL;
    RsaKey* rsa = NULL;
    WC_RNG rng;
    int len = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_rsa_gen_key");
    (void)f_rng;
    (void)p_rng;

    if (pk == NULL || exponent < 3 || (exponent & 1) == 0 ||
            (nbits & 1) != 0 || nbits < MBEDTLS_RSA_GEN_KEY_MIN_BITS ||
            nbits < RSA_MIN_SIZE || nbits > RSA_MAX_SIZE) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    /* wolfCrypt rounds other sizes down to a multiple of 16 bits */
    if (nbits % 16 != 0) {
        return MBEDTLS_ERR_RSA_KEY_GEN_FAILED;
    }
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret == 0) {
        rsa = wc_NewRsaKey(NULL, wolfPSA_GetDefaultDevID(), NULL);
        if (rsa == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0) {
            ret = wc_MakeRsaKey(rsa, (int)nbits, exponent, &rng);
        }
        if (ret == 0) {
            ret = wc_RsaKeyToDer(rsa, NULL, 0);
        }
        if (ret > 0) {
            len = ret;
            der = (unsigned char*)XMALLOC((size_t)len, NULL,
                DYNAMIC_TYPE_PRIVATE_KEY);
            ret = (der == NULL) ? MEMORY_E :
                wc_RsaKeyToDer(rsa, der, (word32)len);
        }
        if (ret > 0) {
            len = ret;
            ret = 0;
        }
        if (rsa != NULL) {
            (void)wc_DeleteRsaKey(rsa, &rsa);
        }
        (void)wc_FreeRng(&rng);
    }
    return MbedPkTakeKey(pk,
        wolfPSA_MbedRet(ret, MBEDTLS_ERR_RSA_KEY_GEN_FAILED), der, len);
}
#else
int mbedtls_rsa_gen_key(mbedtls_rsa_context* ctx,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng,
    unsigned int nbits, int exponent)
{
    (void)ctx;
    (void)f_rng;
    (void)p_rng;
    (void)nbits;
    (void)exponent;
    return MBEDTLS_ERR_RSA_KEY_GEN_FAILED;
}
#endif /* MBED_RSA_GEN */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
