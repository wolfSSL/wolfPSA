/* psa_key_derivation.c
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

#include <limits.h>
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Defined in psa_asymmetric_api.c: compute the raw ECDH shared secret while
 * enforcing the private key's full key-agreement policy (base algorithm and
 * embedded KDF), not just the base algorithm. */
extern psa_status_t wolfpsa_key_agreement_secret(psa_algorithm_t alg,
                                                 psa_key_id_t private_key,
                                                 const uint8_t *peer_key,
                                                 size_t peer_key_length,
                                                 uint8_t *output,
                                                 size_t output_size,
                                                 size_t *output_length);

typedef struct wolfpsa_kdf_ctx {
    psa_algorithm_t alg;
    psa_algorithm_t ka_alg;
    size_t capacity;
    size_t output_offset;
    uint32_t steps_set;
    uint8_t *secret;
    size_t secret_length;
    uint8_t *other_secret;
    size_t other_secret_length;
    uint8_t *salt;
    size_t salt_length;
    uint8_t *info;
    size_t info_length;
    uint8_t *label;
    size_t label_length;
    uint8_t *context;
    size_t context_length;
    uint8_t *seed;
    size_t seed_length;
    uint8_t *password;
    size_t password_length;
    uint32_t cost;
    size_t sp800_108_L_bytes; /* total output length in bytes, snapshotted at
                               * first output_bytes() call for SP800-108 */
    int is_key_agreement;
    int is_raw_kdf;
    int output_started;
    uint8_t *output_cache;
    size_t output_cache_length;
} wolfpsa_kdf_ctx_t;

/* PSA_KEY_DERIVATION_INPUT_CONTEXT (0x0206) is defined in PSA 1.4 but not
 * yet present in this header set; provide a local fallback so the SP800-108
 * implementation can refer to it without touching the shared headers. */
#ifndef PSA_KEY_DERIVATION_INPUT_CONTEXT
#define PSA_KEY_DERIVATION_INPUT_CONTEXT  ((psa_key_derivation_step_t) 0x0206)
#endif

#define WOLFPSA_KDF_STEP_SECRET        (1u << 0)
#define WOLFPSA_KDF_STEP_OTHER_SECRET  (1u << 1)
#define WOLFPSA_KDF_STEP_SALT          (1u << 2)
#define WOLFPSA_KDF_STEP_INFO          (1u << 3)
#define WOLFPSA_KDF_STEP_LABEL         (1u << 4)
#define WOLFPSA_KDF_STEP_SEED          (1u << 5)
#define WOLFPSA_KDF_STEP_PASSWORD      (1u << 6)
#define WOLFPSA_KDF_STEP_COST          (1u << 7)
#define WOLFPSA_KDF_STEP_CONTEXT       (1u << 8)

/* Upper bound on how much of a bounded-capacity derivation is pre-computed
 * and cached on the first output_bytes() call.  HKDF's default capacity is at
 * most 255 * hash_len (roughly 16 KB), which fits comfortably.  SP800-108
 * counter mode defaults its capacity to 2^29 - 1 bytes; caching that whole
 * keystream up front would allocate about 512 MB and compute millions of MAC
 * blocks just to return a few bytes, so above this bound the derivation is
 * computed lazily per call instead. */
#define WOLFPSA_KDF_MAX_CACHE_BYTES    (64u * 1024u)

static wolfpsa_kdf_ctx_t* wolfpsa_kdf_get_ctx(psa_key_derivation_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }
    return (wolfpsa_kdf_ctx_t *)(uintptr_t)operation->opaque;
}

static void wolfpsa_kdf_free_buf(uint8_t **buf, size_t *len)
{
    if (buf != NULL && *buf != NULL) {
        wc_ForceZero(*buf, len != NULL ? *len : 0);
        XFREE(*buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *buf = NULL;
    }
    if (len != NULL) {
        *len = 0;
    }
}

static psa_status_t wolfpsa_kdf_append(uint8_t **buf, size_t *len,
                                       const uint8_t *data, size_t data_length)
{
    uint8_t *new_buf;

    if (buf == NULL || len == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data == NULL && data_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_length == 0) {
        return PSA_SUCCESS;
    }
    if (*len > SIZE_MAX - data_length) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    new_buf = (uint8_t *)XMALLOC(*len + data_length, NULL,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (new_buf == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    if (*buf != NULL) {
        XMEMCPY(new_buf, *buf, *len);
        wc_ForceZero(*buf, *len);
        XFREE(*buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    XMEMCPY(new_buf + *len, data, data_length);
    *buf = new_buf;
    *len += data_length;

    return PSA_SUCCESS;
}

static const uint8_t* wolfpsa_kdf_input_ptr(const uint8_t *buf, size_t len)
{
    static const uint8_t empty[1] = { 0 };

    if (buf == NULL && len == 0) {
        return empty;
    }

    return buf;
}

static int wolfpsa_hash_type_from_alg(psa_algorithm_t alg)
{
    psa_algorithm_t hash_alg = 0;

    if (PSA_ALG_IS_ANY_HKDF(alg)) {
        hash_alg = PSA_ALG_HKDF_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_TLS12_PRF(alg)) {
        hash_alg = PSA_ALG_TLS12_PRF_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_TLS12_PSK_TO_MS(alg)) {
        hash_alg = PSA_ALG_TLS12_PSK_TO_MS_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_PBKDF2_HMAC(alg)) {
        hash_alg = PSA_ALG_PBKDF2_HMAC_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(alg)) {
        hash_alg = PSA_ALG_GET_HASH(alg);
    }

    switch (hash_alg) {
        case PSA_ALG_SHA_1:
            return WC_HASH_TYPE_SHA;
        case PSA_ALG_SHA_224:
            return WC_HASH_TYPE_SHA224;
        case PSA_ALG_SHA_256:
            return WC_HASH_TYPE_SHA256;
        case PSA_ALG_SHA_384:
            return WC_HASH_TYPE_SHA384;
        case PSA_ALG_SHA_512:
            return WC_HASH_TYPE_SHA512;
        case PSA_ALG_SHA_512_224:
            return WC_HASH_TYPE_SHA512_224;
        case PSA_ALG_SHA_512_256:
            return WC_HASH_TYPE_SHA512_256;
        default:
            return WC_HASH_TYPE_NONE;
    }
}

static psa_status_t wolfpsa_kdf_require_output(wolfpsa_kdf_ctx_t *ctx,
                                               size_t output_length)
{
    if (ctx->capacity == PSA_KEY_DERIVATION_UNLIMITED_CAPACITY) {
        return PSA_SUCCESS;
    }
    if (ctx->capacity < output_length) {
        ctx->capacity = 0;
        return PSA_ERROR_INSUFFICIENT_DATA;
    }
    ctx->capacity -= output_length;
    return PSA_SUCCESS;
}

static uint32_t wolfpsa_kdf_step_mask(psa_key_derivation_step_t step)
{
    switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            return WOLFPSA_KDF_STEP_SECRET;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            return WOLFPSA_KDF_STEP_OTHER_SECRET;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            return WOLFPSA_KDF_STEP_SALT;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            return WOLFPSA_KDF_STEP_INFO;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            return WOLFPSA_KDF_STEP_LABEL;
        case PSA_KEY_DERIVATION_INPUT_SEED:
            return WOLFPSA_KDF_STEP_SEED;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            return WOLFPSA_KDF_STEP_PASSWORD;
        case PSA_KEY_DERIVATION_INPUT_COST:
            return WOLFPSA_KDF_STEP_COST;
        case PSA_KEY_DERIVATION_INPUT_CONTEXT:
            return WOLFPSA_KDF_STEP_CONTEXT;
        default:
            return 0;
    }
}

static psa_status_t wolfpsa_kdf_validate_step(wolfpsa_kdf_ctx_t *ctx,
                                              psa_key_derivation_step_t step,
                                              size_t data_length)
{
    int hash_len;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->output_started) {
        return PSA_ERROR_BAD_STATE;
    }
    if (step == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->is_raw_kdf) {
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }

    if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET ||
            step == PSA_KEY_DERIVATION_INPUT_LABEL ||
            step == PSA_KEY_DERIVATION_INPUT_SEED ||
            step == PSA_KEY_DERIVATION_INPUT_PASSWORD ||
            step == PSA_KEY_DERIVATION_INPUT_COST) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
            if (step == PSA_KEY_DERIVATION_INPUT_INFO) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SALT) == 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
        }

        if (PSA_ALG_IS_HKDF_EXPAND(ctx->alg)) {
            if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
                if (ctx->steps_set != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                hash_len = wc_HashGetDigestSize(wolfpsa_hash_type_from_alg(ctx->alg));
                if (hash_len <= 0 || data_length != (size_t)hash_len) {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }
            }
            if (step == PSA_KEY_DERIVATION_INPUT_INFO &&
                (ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
            return PSA_SUCCESS;
        }

        if (PSA_ALG_IS_HKDF(ctx->alg)) {
            if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_INFO) {
                return PSA_SUCCESS;
            }
        }

        return PSA_ERROR_INVALID_ARGUMENT;
    }
    else if (PSA_ALG_IS_TLS12_PRF(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_LABEL &&
            step != PSA_KEY_DERIVATION_INPUT_SEED) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_OTHER_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_SEED) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
        if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET &&
            (ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
        return PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_PASSWORD &&
            step != PSA_KEY_DERIVATION_INPUT_SALT) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(ctx->alg) ||
             ctx->alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        /* Allowed steps: SECRET (mandatory), LABEL (optional), CONTEXT
         * (optional).  SECRET must be provided before output; each step
         * can only be set once. */
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_LABEL &&
            step != PSA_KEY_DERIVATION_INPUT_CONTEXT) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if ((ctx->steps_set & wolfpsa_kdf_step_mask(step)) != 0) {
            return PSA_ERROR_BAD_STATE;
        }
        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
                                      psa_algorithm_t alg)
{
    wolfpsa_kdf_ctx_t *ctx;
    psa_algorithm_t kdf_alg = alg;
    int hash_type = WC_HASH_TYPE_NONE;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_KEY_DERIVATION_OR_AGREEMENT(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        if (PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) != PSA_ALG_ECDH) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
    }

    if (!(PSA_ALG_IS_ANY_HKDF(kdf_alg) || PSA_ALG_IS_TLS12_PRF(kdf_alg) ||
          PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg) || PSA_ALG_IS_PBKDF2(kdf_alg) ||
          PSA_ALG_IS_SP800_108_COUNTER_HMAC(kdf_alg) ||
          kdf_alg == PSA_ALG_SP800_108_COUNTER_CMAC ||
          kdf_alg == PSA_ALG_CATEGORY_KEY_DERIVATION)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if !defined(HAVE_HKDF) || defined(NO_HMAC)
    if (PSA_ALG_IS_ANY_HKDF(kdf_alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#if !defined(WOLFSSL_HAVE_PRF) || defined(NO_HMAC)
    if (PSA_ALG_IS_TLS12_PRF(kdf_alg) || PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#if !defined(HAVE_PBKDF2) || defined(NO_HMAC)
    if (PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#if defined(NO_HMAC)
    if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(kdf_alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#if !defined(WOLFSSL_CMAC) || defined(NO_AES)
    if (kdf_alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif

    if (PSA_ALG_IS_ANY_HKDF(kdf_alg) || PSA_ALG_IS_TLS12_PRF(kdf_alg) ||
        PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg) || PSA_ALG_IS_PBKDF2_HMAC(kdf_alg) ||
        PSA_ALG_IS_SP800_108_COUNTER_HMAC(kdf_alg)) {
        hash_type = wolfpsa_hash_type_from_alg(kdf_alg);
        if (hash_type == WC_HASH_TYPE_NONE) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    ctx = (wolfpsa_kdf_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->alg = kdf_alg;
    if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        ctx->is_key_agreement = 1;
        ctx->ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE(alg);
        if (kdf_alg == PSA_ALG_CATEGORY_KEY_DERIVATION) {
            ctx->is_raw_kdf = 1;
        }
    }
    ctx->capacity = PSA_KEY_DERIVATION_UNLIMITED_CAPACITY;
    if (PSA_ALG_IS_ANY_HKDF(kdf_alg)) {
        int hash_len = wc_HashGetDigestSize(hash_type);

        if (hash_len <= 0) {
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
            ctx->capacity = (size_t)hash_len;
        }
        else {
            ctx->capacity = 255u * (size_t)hash_len;
        }
    }
    /* SP 800-108 counter-mode: default capacity is 2^29 - 1 bytes per spec */
    if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(kdf_alg) ||
        kdf_alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        ctx->capacity = (size_t)0x1fffffffu;
    }

    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx != NULL) {
        wolfpsa_kdf_free_buf(&ctx->secret, &ctx->secret_length);
        wolfpsa_kdf_free_buf(&ctx->other_secret, &ctx->other_secret_length);
        wolfpsa_kdf_free_buf(&ctx->salt, &ctx->salt_length);
        wolfpsa_kdf_free_buf(&ctx->info, &ctx->info_length);
        wolfpsa_kdf_free_buf(&ctx->label, &ctx->label_length);
        wolfpsa_kdf_free_buf(&ctx->context, &ctx->context_length);
        wolfpsa_kdf_free_buf(&ctx->seed, &ctx->seed_length);
        wolfpsa_kdf_free_buf(&ctx->password, &ctx->password_length);
        if (ctx->output_cache != NULL) {
            wc_ForceZero(ctx->output_cache, ctx->output_cache_length);
            XFREE(ctx->output_cache, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ctx->output_cache = NULL;
            ctx->output_cache_length = 0;
        }
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        operation->opaque = (uintptr_t)NULL;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
                                             size_t capacity)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    int hash_len;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        hash_len = wc_HashGetDigestSize(wolfpsa_hash_type_from_alg(ctx->alg));
        if (hash_len <= 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
            if (capacity > (size_t)hash_len) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else if (capacity > (size_t)(255u * (size_t)hash_len)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    if (capacity > ctx->capacity) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ctx->capacity = capacity;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
                                             size_t *capacity)
{
    const wolfpsa_kdf_ctx_t *ctx;

    if (operation == NULL || capacity == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ctx = (const wolfpsa_kdf_ctx_t *)(uintptr_t)operation->opaque;
    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    *capacity = ctx->capacity;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t *data,
                                            size_t data_length)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_status_t status;
    uint32_t mask;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_kdf_validate_step(ctx, step, data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    mask = wolfpsa_kdf_step_mask(step);
    if (mask == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            status = wolfpsa_kdf_append(&ctx->secret, &ctx->secret_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            status = wolfpsa_kdf_append(&ctx->other_secret, &ctx->other_secret_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            status = wolfpsa_kdf_append(&ctx->salt, &ctx->salt_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            status = wolfpsa_kdf_append(&ctx->info, &ctx->info_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            status = wolfpsa_kdf_append(&ctx->label, &ctx->label_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_CONTEXT:
            status = wolfpsa_kdf_append(&ctx->context, &ctx->context_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_SEED:
            status = wolfpsa_kdf_append(&ctx->seed, &ctx->seed_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            status = wolfpsa_kdf_append(&ctx->password, &ctx->password_length,
                                        data, data_length);
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (status == PSA_SUCCESS) {
        ctx->steps_set |= mask;
    }
    return status;
}

psa_status_t psa_key_derivation_input_integer(psa_key_derivation_operation_t *operation,
                                              psa_key_derivation_step_t step,
                                              uint64_t value)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->output_started) {
        return PSA_ERROR_BAD_STATE;
    }

    if (step != PSA_KEY_DERIVATION_INPUT_COST) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_ALG_IS_PBKDF2(ctx->alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (value == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (value > 0xFFFFFFFFu) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    ctx->cost = (uint32_t)value;
    ctx->steps_set |= WOLFPSA_KDF_STEP_COST;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
                                          psa_key_derivation_step_t step,
                                          psa_key_id_t key)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_algorithm_t key_alg;
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_kdf_validate_step(ctx, step, key_data_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }

    if ((psa_get_key_usage_flags(&attributes) &
         (PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_VERIFY_DERIVATION)) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_PASSWORD ||
            psa_get_key_type(&attributes) != PSA_KEY_TYPE_PASSWORD) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (step == PSA_KEY_DERIVATION_INPUT_SECRET ||
             step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET) {
        if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_DERIVE) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (key_alg == PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Algorithm match checks */
    if (ctx->is_key_agreement) {
        if (!PSA_ALG_IS_KEY_AGREEMENT(key_alg) ||
            PSA_ALG_KEY_AGREEMENT_GET_KDF(key_alg) != ctx->alg) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else if (key_alg != ctx->alg) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    status = psa_key_derivation_input_bytes(operation, step,
                                            key_data, key_data_length);
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
                                              psa_key_derivation_step_t step,
                                              psa_key_id_t private_key,
                                              const uint8_t *peer_key,
                                              size_t peer_key_length)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_key_attributes_t priv_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    size_t secret_len;
    size_t output_len = 0;
    uint8_t *secret = NULL;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!ctx->is_key_agreement) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->output_started) {
        return PSA_ERROR_BAD_STATE;
    }
    if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
        step != PSA_KEY_DERIVATION_INPUT_OTHER_SECRET) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET &&
        !PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_key_attributes(private_key, &priv_attr);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((psa_get_key_usage_flags(&priv_attr) & PSA_KEY_USAGE_DERIVE) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_KEY_TYPE_IS_KEY_PAIR(psa_get_key_type(&priv_attr))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    secret_len = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(psa_get_key_type(&priv_attr),
                                                   psa_get_key_bits(&priv_attr));
    if (secret_len == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    secret = (uint8_t *)XMALLOC(secret_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secret == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = wolfpsa_key_agreement_secret(
                 PSA_ALG_KEY_AGREEMENT(ctx->ka_alg, ctx->alg), private_key,
                 peer_key, peer_key_length, secret, secret_len, &output_len);
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(operation,
                                                step,
                                                secret, output_len);
    }

    wc_ForceZero(secret, secret_len);
    XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

static psa_status_t wolfpsa_kdf_hkdf(wolfpsa_kdf_ctx_t *ctx,
                                     uint8_t *output,
                                     size_t output_length)
{
#if !defined(HAVE_HKDF) || defined(NO_HMAC)
    (void)ctx;
    (void)output;
    (void)output_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    int ret;

    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
        int hash_len = wc_HashGetDigestSize(hash_type);
        uint8_t prk[WC_MAX_DIGEST_SIZE];
        if (hash_len <= 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if ((size_t)hash_len > sizeof(prk)) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if ((wolfpsa_check_word32_length(ctx->salt_length) != PSA_SUCCESS) ||
            (wolfpsa_check_word32_length(ctx->secret_length) != PSA_SUCCESS)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (output_length > (size_t)hash_len) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (output_length < (size_t)hash_len) {
            uint8_t tmp[WC_MAX_DIGEST_SIZE];
            ret = wc_HKDF_Extract(hash_type,
                                  ctx->salt, (word32)ctx->salt_length,
                                  ctx->secret, (word32)ctx->secret_length,
                                  tmp);
            if (ret == 0) {
                XMEMCPY(output, tmp, output_length);
            }
            wc_ForceZero(tmp, sizeof(tmp));
            return ret == 0 ? PSA_SUCCESS : wc_error_to_psa_status(ret);
        }
        ret = wc_HKDF_Extract(hash_type,
                              ctx->salt, (word32)ctx->salt_length,
                              ctx->secret, (word32)ctx->secret_length,
                              prk);
        if (ret != 0) {
            wc_ForceZero(prk, (size_t)hash_len);
            return wc_error_to_psa_status(ret);
        }

        XMEMCPY(output, prk, output_length);
        wc_ForceZero(prk, (size_t)hash_len);
        return PSA_SUCCESS;
    }

    if (PSA_ALG_IS_HKDF_EXPAND(ctx->alg)) {
        if ((wolfpsa_check_word32_length(ctx->secret_length) != PSA_SUCCESS) ||
            (wolfpsa_check_word32_length(ctx->info_length) != PSA_SUCCESS) ||
            (wolfpsa_check_word32_length(output_length) != PSA_SUCCESS)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ret = wc_HKDF_Expand(hash_type,
                             ctx->secret, (word32)ctx->secret_length,
                             ctx->info, (word32)ctx->info_length,
                             output, (word32)output_length);
        return ret == 0 ? PSA_SUCCESS : wc_error_to_psa_status(ret);
    }

    if (PSA_ALG_IS_HKDF(ctx->alg)) {
        int hash_len = wc_HashGetDigestSize(hash_type);
        uint8_t prk[WC_MAX_DIGEST_SIZE];
        psa_status_t status;

        if (hash_len <= 0 || (size_t)hash_len > sizeof(prk)) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if ((wolfpsa_check_word32_length(ctx->salt_length) != PSA_SUCCESS) ||
            (wolfpsa_check_word32_length(ctx->secret_length) != PSA_SUCCESS) ||
            (wolfpsa_check_word32_length(ctx->info_length) != PSA_SUCCESS) ||
            (wolfpsa_check_word32_length(output_length) != PSA_SUCCESS)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ret = wc_HKDF_Extract(hash_type,
                              ctx->salt, (word32)ctx->salt_length,
                              ctx->secret, (word32)ctx->secret_length,
                              prk);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            wc_ForceZero(prk, sizeof(prk));
            return status;
        }

        ret = wc_HKDF_Expand(hash_type,
                             prk, (word32)hash_len,
                             ctx->info, (word32)ctx->info_length,
                             output, (word32)output_length);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            wc_ForceZero(prk, sizeof(prk));
            return status;
        }
        wc_ForceZero(prk, sizeof(prk));
        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
#endif
}

static psa_status_t wolfpsa_kdf_tls12_prf(wolfpsa_kdf_ctx_t *ctx,
                                          uint8_t *output,
                                          size_t output_length)
{
#if !defined(WOLFSSL_HAVE_PRF) || defined(NO_HMAC)
    (void)ctx;
    (void)output;
    (void)output_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    int ret;

    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(output_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->secret_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->label_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->seed_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ret = wc_PRF_TLS(output, (word32)output_length,
                     ctx->secret, (word32)ctx->secret_length,
                     ctx->label, (word32)ctx->label_length,
                     ctx->seed, (word32)ctx->seed_length,
                     1, hash_type, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    return PSA_SUCCESS;
#endif
}

static psa_status_t wolfpsa_kdf_tls12_psk_to_ms(wolfpsa_kdf_ctx_t *ctx,
                                                uint8_t *output,
                                                size_t output_length)
{
#if !defined(WOLFSSL_HAVE_PRF) || defined(NO_HMAC)
    (void)ctx;
    (void)output;
    (void)output_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    size_t other_secret_length;
    const uint8_t *other_secret;
    uint8_t *premaster = NULL;
    size_t premaster_len;
    psa_status_t status;
    int ret;

    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((ctx->steps_set & WOLFPSA_KDF_STEP_OTHER_SECRET) == 0) {
        other_secret = NULL;
        other_secret_length = ctx->secret_length;
    }
    else {
        other_secret = ctx->other_secret;
        other_secret_length = ctx->other_secret_length;
    }

    premaster_len = 2u + ctx->secret_length + 2u + other_secret_length;
    if ((wolfpsa_check_word32_length(output_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(premaster_len) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->seed_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    premaster = (uint8_t *)XMALLOC(premaster_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (premaster == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    premaster[0] = (uint8_t)((other_secret_length >> 8) & 0xff);
    premaster[1] = (uint8_t)(other_secret_length & 0xff);
    if (other_secret == NULL) {
        XMEMSET(premaster + 2u, 0, other_secret_length);
    }
    else {
        XMEMCPY(premaster + 2u, other_secret, other_secret_length);
    }
    premaster[2u + other_secret_length] = (uint8_t)((ctx->secret_length >> 8) & 0xff);
    premaster[3u + other_secret_length] = (uint8_t)(ctx->secret_length & 0xff);
    XMEMCPY(premaster + 4u + other_secret_length, ctx->secret,
            ctx->secret_length);

    ret = wc_PRF_TLS(output, (word32)output_length,
                     premaster, (word32)premaster_len,
                     (const byte *)"master secret", 13u,
                     ctx->seed, (word32)ctx->seed_length,
                     1, hash_type, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        status = wc_error_to_psa_status(ret);
    }
    else {
        status = PSA_SUCCESS;
    }

    wc_ForceZero(premaster, premaster_len);
    XFREE(premaster, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
#endif
}

static psa_status_t wolfpsa_kdf_pbkdf2(wolfpsa_kdf_ctx_t *ctx,
                                       uint8_t *output,
                                       size_t output_length)
{
    const uint8_t *password = wolfpsa_kdf_input_ptr(ctx->password,
                                                    ctx->password_length);
    const uint8_t *salt = wolfpsa_kdf_input_ptr(ctx->salt, ctx->salt_length);

    if (PSA_ALG_IS_PBKDF2_HMAC(ctx->alg)) {
#if !defined(HAVE_PBKDF2) || defined(NO_HMAC)
        (void)output;
        (void)output_length;
        return PSA_ERROR_NOT_SUPPORTED;
#else
        int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
        int ret;

        if (hash_type == WC_HASH_TYPE_NONE) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (ctx->password_length > (size_t)INT_MAX ||
            ctx->salt_length > (size_t)INT_MAX ||
            ctx->cost > (uint32_t)INT_MAX ||
            output_length > (size_t)INT_MAX) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ret = wc_PBKDF2(output, password, (int)ctx->password_length,
                        salt, (int)ctx->salt_length,
                        (int)ctx->cost, (int)output_length, hash_type);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        return PSA_SUCCESS;
#endif
    }

    if (ctx->alg == PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
        uint8_t prf_key[WC_AES_BLOCK_SIZE];
        uint8_t u_block[WC_AES_BLOCK_SIZE];
        uint8_t t_block[WC_AES_BLOCK_SIZE];
        uint8_t *block_input = NULL;
        uint8_t zero_key[WC_AES_BLOCK_SIZE];
        size_t blocks;
        size_t block_input_len;
        size_t offset = 0;
        uint32_t i;
        uint32_t j;
        int ret;
        Cmac cmac;
        word32 out_sz = WC_AES_BLOCK_SIZE;
        psa_status_t status = PSA_SUCCESS;

        if (wolfpsa_check_word32_length(ctx->password_length) != PSA_SUCCESS) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        XMEMSET(zero_key, 0, sizeof(zero_key));
        ret = wc_InitCmac(&cmac, zero_key, (word32)sizeof(zero_key),
                          WC_CMAC_AES, NULL);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto cleanup;
        }
        ret = wc_CmacUpdate(&cmac, password, (word32)ctx->password_length);
        if (ret != 0) {
            wc_CmacFree(&cmac);
            status = wc_error_to_psa_status(ret);
            goto cleanup;
        }
        ret = wc_CmacFinal(&cmac, prf_key, &out_sz);
        wc_CmacFree(&cmac);
        if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
            status = ret == 0 ? PSA_ERROR_NOT_SUPPORTED :
                                wc_error_to_psa_status(ret);
            goto cleanup;
        }

        block_input_len = ctx->salt_length + 4;
        if (wolfpsa_check_word32_length(block_input_len) != PSA_SUCCESS) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        block_input = (uint8_t *)XMALLOC(block_input_len, NULL,
                                         DYNAMIC_TYPE_TMP_BUFFER);
        if (block_input == NULL) {
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
            goto cleanup;
        }

        blocks = (output_length + WC_AES_BLOCK_SIZE - 1) / WC_AES_BLOCK_SIZE;
        for (i = 1; i <= blocks; i++) {
            XMEMCPY(block_input, salt, ctx->salt_length);
            block_input[ctx->salt_length + 0] = (uint8_t)((i >> 24) & 0xff);
            block_input[ctx->salt_length + 1] = (uint8_t)((i >> 16) & 0xff);
            block_input[ctx->salt_length + 2] = (uint8_t)((i >> 8) & 0xff);
            block_input[ctx->salt_length + 3] = (uint8_t)(i & 0xff);

            ret = wc_InitCmac(&cmac, prf_key, (word32)sizeof(prf_key),
                              WC_CMAC_AES, NULL);
            if (ret != 0) {
                status = wc_error_to_psa_status(ret);
                goto cleanup;
            }
            out_sz = WC_AES_BLOCK_SIZE;
            ret = wc_CmacUpdate(&cmac, block_input, (word32)block_input_len);
            if (ret == 0) {
                ret = wc_CmacFinal(&cmac, u_block, &out_sz);
            }
            wc_CmacFree(&cmac);
            if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
                status = ret == 0 ? PSA_ERROR_NOT_SUPPORTED :
                                    wc_error_to_psa_status(ret);
                goto cleanup;
            }

            XMEMCPY(t_block, u_block, WC_AES_BLOCK_SIZE);
            for (j = 1; j < ctx->cost; j++) {
                ret = wc_InitCmac(&cmac, prf_key, (word32)sizeof(prf_key),
                                  WC_CMAC_AES, NULL);
                if (ret != 0) {
                    status = wc_error_to_psa_status(ret);
                    goto cleanup;
                }
                out_sz = WC_AES_BLOCK_SIZE;
                ret = wc_CmacUpdate(&cmac, u_block, WC_AES_BLOCK_SIZE);
                if (ret == 0) {
                    ret = wc_CmacFinal(&cmac, u_block, &out_sz);
                }
                wc_CmacFree(&cmac);
                if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
                    status = ret == 0 ? PSA_ERROR_NOT_SUPPORTED :
                                        wc_error_to_psa_status(ret);
                    goto cleanup;
                }
                t_block[0] ^= u_block[0];
                t_block[1] ^= u_block[1];
                t_block[2] ^= u_block[2];
                t_block[3] ^= u_block[3];
                t_block[4] ^= u_block[4];
                t_block[5] ^= u_block[5];
                t_block[6] ^= u_block[6];
                t_block[7] ^= u_block[7];
                t_block[8] ^= u_block[8];
                t_block[9] ^= u_block[9];
                t_block[10] ^= u_block[10];
                t_block[11] ^= u_block[11];
                t_block[12] ^= u_block[12];
                t_block[13] ^= u_block[13];
                t_block[14] ^= u_block[14];
                t_block[15] ^= u_block[15];
            }

            if (offset + WC_AES_BLOCK_SIZE <= output_length) {
                XMEMCPY(output + offset, t_block, WC_AES_BLOCK_SIZE);
                offset += WC_AES_BLOCK_SIZE;
            }
            else {
                XMEMCPY(output + offset, t_block, output_length - offset);
                offset = output_length;
            }
        }
cleanup:
        wc_ForceZero(t_block, sizeof(t_block));
        wc_ForceZero(u_block, sizeof(u_block));
        wc_ForceZero(prf_key, sizeof(prf_key));
        XFREE(block_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

/*
 * SP 800-108r1 counter-mode KDF — HMAC variant.
 *
 * Fixed-input construction (PSA 1.4 §10.8):
 *   K(i) = HMAC(K_IN, [i]_4 || Label || 0x00 || Context || [L]_4)
 *
 * Where:
 *   [i]_4   — 4-byte big-endian counter starting at 1
 *   Label   — PSA_KEY_DERIVATION_INPUT_LABEL bytes (may be zero-length)
 *   0x00    — single separator byte
 *   Context — PSA_KEY_DERIVATION_INPUT_CONTEXT bytes (may be zero-length)
 *   [L]_4   — 4-byte big-endian encoding of total requested output in BITS,
 *              snapshotted from capacity at first output_bytes() call
 *
 * Output stream is K(1) || K(2) || ... truncated to output_length bytes.
 *
 * Interoperability note: L is bound to the operation's capacity, not to the
 * amount of output actually read (PSA 1.4 §10.8).  Callers MUST set the
 * capacity to the exact total derivation length before the first output
 * call to match other SP 800-108 implementations that encode L from the
 * requested output length; with the default capacity (2^29 - 1 bytes) the
 * output is self-consistent but not interoperable.
 */
static psa_status_t wolfpsa_kdf_sp800_108_hmac(wolfpsa_kdf_ctx_t *ctx,
                                               uint8_t *output,
                                               size_t output_length)
{
#if defined(NO_HMAC)
    (void)ctx;
    (void)output;
    (void)output_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    int hash_type;
    int hmac_len;
    uint32_t L_bits_hi;
    uint32_t L_bits_lo;
    uint32_t counter;
    size_t offset = 0;
    uint8_t block[WC_MAX_DIGEST_SIZE];
    uint8_t counter_buf[4];
    uint8_t sep = 0x00u;
    uint8_t L_buf[4];
    psa_status_t status = PSA_SUCCESS;
    Hmac hmac;
    int ret;
    int hmac_inited = 0;

    hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    hmac_len = wc_HashGetDigestSize(hash_type);
    if (hmac_len <= 0 || (size_t)hmac_len > sizeof(block)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* L = total derivation length in bits (fits in 32 bits since capacity
     * <= 2^29-1 bytes, so bits <= 2^32-8 which wraps — use 64-bit arithmetic
     * to split into hi and lo words for the [L]_4 encoding; the PSA spec
     * uses a 32-bit field so L must fit in 32 bits of bits, i.e. <= 2^29-1
     * bytes guarantees L_bits <= (2^29-1)*8 = 2^32-8, which does NOT fit in
     * 32 bits.  The spec encodes [L]_4 as a 32-bit big-endian value so we
     * use only the lower 32 bits of (capacity_bytes * 8) — for capacity up
     * to 2^29-1 bytes the bit count is at most 0xFFFFFFF8, fitting in 32. */
    {
        uint64_t L_bits = (uint64_t)ctx->sp800_108_L_bytes * 8u;
        L_bits_hi = (uint32_t)(L_bits >> 32);
        L_bits_lo = (uint32_t)(L_bits & 0xffffffffu);
        (void)L_bits_hi; /* only low 32 bits used per spec [L]_4 */
    }
    L_buf[0] = (uint8_t)((L_bits_lo >> 24) & 0xff);
    L_buf[1] = (uint8_t)((L_bits_lo >> 16) & 0xff);
    L_buf[2] = (uint8_t)((L_bits_lo >>  8) & 0xff);
    L_buf[3] = (uint8_t)( L_bits_lo        & 0xff);

    if (ctx->secret_length > (size_t)INT_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    for (counter = 1u; offset < output_length; counter++) {
        size_t copy_len;

        counter_buf[0] = (uint8_t)((counter >> 24) & 0xff);
        counter_buf[1] = (uint8_t)((counter >> 16) & 0xff);
        counter_buf[2] = (uint8_t)((counter >>  8) & 0xff);
        counter_buf[3] = (uint8_t)( counter        & 0xff);

        ret = wc_HmacInit(&hmac, NULL, wolfPSA_GetDefaultDevID());
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto hmac_cleanup;
        }
        hmac_inited = 1;

        ret = wc_HmacSetKey(&hmac, hash_type,
                            ctx->secret, (word32)ctx->secret_length);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto hmac_cleanup;
        }

        /* [i]_4 */
        ret = wc_HmacUpdate(&hmac, counter_buf, sizeof(counter_buf));
        if (ret == 0 && ctx->label_length > 0) {
            /* Label */
            ret = wc_HmacUpdate(&hmac, ctx->label, (word32)ctx->label_length);
        }
        /* 0x00 separator */
        if (ret == 0) {
            ret = wc_HmacUpdate(&hmac, &sep, 1u);
        }
        if (ret == 0 && ctx->context_length > 0) {
            /* Context */
            ret = wc_HmacUpdate(&hmac, ctx->context,
                                (word32)ctx->context_length);
        }
        /* [L]_4 */
        if (ret == 0) {
            ret = wc_HmacUpdate(&hmac, L_buf, sizeof(L_buf));
        }
        if (ret == 0) {
            ret = wc_HmacFinal(&hmac, block);
        }

        wc_HmacFree(&hmac);
        hmac_inited = 0;

        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto hmac_cleanup;
        }

        copy_len = (size_t)hmac_len;
        if (offset + copy_len > output_length) {
            copy_len = output_length - offset;
        }
        XMEMCPY(output + offset, block, copy_len);
        offset += copy_len;
    }

hmac_cleanup:
    if (hmac_inited) {
        wc_HmacFree(&hmac);
    }
    wc_ForceZero(block, sizeof(block));
    return status;
#endif /* NO_HMAC */
}

/*
 * SP 800-108r1 counter-mode KDF — CMAC variant.
 *
 * Fixed-input construction (PSA 1.4 §10.8):
 *   K_0 = CMAC(K_IN, Label || 0x00 || Context || [L]_4)
 *   K(i) = CMAC(K_IN, [i]_4 || Label || 0x00 || Context || [L]_4 || K_0)
 *                                                           for i = 1, 2, 3, ...
 *
 * K_0 is a robustness-mitigation term specific to the CMAC construction.
 * The secret (K_IN) must be a valid AES key: 16, 24, or 32 bytes.
 * Output block size is WC_AES_BLOCK_SIZE (16 bytes).
 * [L]_4 encodes total output length in bits as 4-byte big-endian.
 * The interoperability note on wolfpsa_kdf_sp800_108_hmac() about binding
 * L via psa_key_derivation_set_capacity() applies here as well.
 */
static psa_status_t wolfpsa_kdf_sp800_108_cmac(wolfpsa_kdf_ctx_t *ctx,
                                               uint8_t *output,
                                               size_t output_length)
{
#if !defined(WOLFSSL_CMAC) || defined(NO_AES)
    (void)ctx;
    (void)output;
    (void)output_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    uint32_t L_bits_lo;
    uint32_t counter;
    size_t offset = 0;
    uint8_t K0[WC_AES_BLOCK_SIZE];
    uint8_t block[WC_AES_BLOCK_SIZE];
    uint8_t counter_buf[4];
    uint8_t sep = 0x00u;
    uint8_t L_buf[4];
    word32 out_sz;
    psa_status_t status = PSA_SUCCESS;
    Cmac cmac;
    int ret;

    /* CMAC key must be a valid AES key length */
    if (ctx->secret_length != 16u &&
        ctx->secret_length != 24u &&
        ctx->secret_length != 32u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wolfpsa_check_word32_length(ctx->secret_length) != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    {
        uint64_t L_bits = (uint64_t)ctx->sp800_108_L_bytes * 8u;
        L_bits_lo = (uint32_t)(L_bits & 0xffffffffu);
    }
    L_buf[0] = (uint8_t)((L_bits_lo >> 24) & 0xff);
    L_buf[1] = (uint8_t)((L_bits_lo >> 16) & 0xff);
    L_buf[2] = (uint8_t)((L_bits_lo >>  8) & 0xff);
    L_buf[3] = (uint8_t)( L_bits_lo        & 0xff);

    /* --- compute K_0 = CMAC(K_IN, Label || 0x00 || Context || [L]_4) --- */
    ret = wc_InitCmac(&cmac, ctx->secret, (word32)ctx->secret_length,
                      WC_CMAC_AES, NULL);
    if (ret != 0) {
        status = wc_error_to_psa_status(ret);
        goto cmac_cleanup;
    }
    if (ctx->label_length > 0) {
        ret = wc_CmacUpdate(&cmac, ctx->label, (word32)ctx->label_length);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(&cmac, &sep, 1u);
    }
    if (ret == 0 && ctx->context_length > 0) {
        ret = wc_CmacUpdate(&cmac, ctx->context, (word32)ctx->context_length);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(&cmac, L_buf, sizeof(L_buf));
    }
    out_sz = WC_AES_BLOCK_SIZE;
    if (ret == 0) {
        ret = wc_CmacFinal(&cmac, K0, &out_sz);
    }
    wc_CmacFree(&cmac);
    if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
        status = ret == 0 ? PSA_ERROR_NOT_SUPPORTED :
                            wc_error_to_psa_status(ret);
        goto cmac_cleanup;
    }

    /* --- K(i) loop --- */
    for (counter = 1u; offset < output_length; counter++) {
        size_t copy_len;

        counter_buf[0] = (uint8_t)((counter >> 24) & 0xff);
        counter_buf[1] = (uint8_t)((counter >> 16) & 0xff);
        counter_buf[2] = (uint8_t)((counter >>  8) & 0xff);
        counter_buf[3] = (uint8_t)( counter        & 0xff);

        ret = wc_InitCmac(&cmac, ctx->secret, (word32)ctx->secret_length,
                          WC_CMAC_AES, NULL);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto cmac_cleanup;
        }

        /* [i]_4 */
        ret = wc_CmacUpdate(&cmac, counter_buf, sizeof(counter_buf));
        if (ret == 0 && ctx->label_length > 0) {
            ret = wc_CmacUpdate(&cmac, ctx->label, (word32)ctx->label_length);
        }
        if (ret == 0) {
            ret = wc_CmacUpdate(&cmac, &sep, 1u);
        }
        if (ret == 0 && ctx->context_length > 0) {
            ret = wc_CmacUpdate(&cmac, ctx->context,
                                (word32)ctx->context_length);
        }
        if (ret == 0) {
            ret = wc_CmacUpdate(&cmac, L_buf, sizeof(L_buf));
        }
        /* K_0 appended (CMAC robustness mitigation) */
        if (ret == 0) {
            ret = wc_CmacUpdate(&cmac, K0, WC_AES_BLOCK_SIZE);
        }
        out_sz = WC_AES_BLOCK_SIZE;
        if (ret == 0) {
            ret = wc_CmacFinal(&cmac, block, &out_sz);
        }
        wc_CmacFree(&cmac);
        if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
            status = ret == 0 ? PSA_ERROR_NOT_SUPPORTED :
                                wc_error_to_psa_status(ret);
            goto cmac_cleanup;
        }

        copy_len = WC_AES_BLOCK_SIZE;
        if (offset + copy_len > output_length) {
            copy_len = output_length - offset;
        }
        XMEMCPY(output + offset, block, copy_len);
        offset += copy_len;
    }

cmac_cleanup:
    wc_ForceZero(K0, sizeof(K0));
    wc_ForceZero(block, sizeof(block));
    return status;
#endif /* WOLFSSL_CMAC && !NO_AES */
}

static psa_status_t wolfpsa_kdf_compute_output(wolfpsa_kdf_ctx_t *ctx,
                                               uint8_t *output,
                                               size_t output_length)
{
    if (ctx->is_raw_kdf) {
        XMEMCPY(output, ctx->secret, output_length);
        return PSA_SUCCESS;
    }

    if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        return wolfpsa_kdf_hkdf(ctx, output, output_length);
    }
    if (PSA_ALG_IS_TLS12_PRF(ctx->alg)) {
        return wolfpsa_kdf_tls12_prf(ctx, output, output_length);
    }
    if (PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        return wolfpsa_kdf_tls12_psk_to_ms(ctx, output, output_length);
    }
    if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        return wolfpsa_kdf_pbkdf2(ctx, output, output_length);
    }
    if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(ctx->alg)) {
        return wolfpsa_kdf_sp800_108_hmac(ctx, output, output_length);
    }
    if (ctx->alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        return wolfpsa_kdf_sp800_108_cmac(ctx, output, output_length);
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
                                             uint8_t *output,
                                             size_t output_length)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    size_t total_output_length;
    psa_status_t status;

    if (ctx == NULL || output == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->is_raw_kdf) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
            ctx->output_offset > ctx->secret_length ||
            output_length > ctx->secret_length - ctx->output_offset) {
            return PSA_ERROR_INSUFFICIENT_DATA;
        }
    }
    else if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SALT) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
        else if (PSA_ALG_IS_HKDF_EXPAND(ctx->alg)) {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_INFO) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
        else {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_INFO) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
    }
    else if (PSA_ALG_IS_TLS12_PRF(ctx->alg)) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_LABEL) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
    }
    else if (PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
    }
    else if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_PASSWORD) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_SALT) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_COST) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
    }
    else if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(ctx->alg) ||
             ctx->alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
        /* Snapshot L on the first output call.  L = capacity in bits before
         * any output has been consumed (spec: PSA 1.4 §10.8, SP800-108
         * counter mode).  At this point capacity has not yet been decremented
         * by wolfpsa_kdf_require_output, so capacity + output_length equals
         * the original capacity set at setup / set_capacity time.
         *
         * Callers that did not call psa_key_derivation_set_capacity() get
         * L derived from the default capacity (2^29 - 1 bytes).  That is
         * the behavior the PSA spec mandates, but the resulting stream will
         * not match SP 800-108 implementations that bind L to the requested
         * output length — see the interoperability note on
         * wolfpsa_kdf_sp800_108_hmac(). */
        if (!ctx->output_started) {
            ctx->sp800_108_L_bytes = ctx->capacity;
        }
    }

    status = wolfpsa_kdf_require_output(ctx, output_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx->output_started = 1;
    total_output_length = ctx->output_offset + output_length;
    if (total_output_length < ctx->output_offset) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->output_cache == NULL
        && !ctx->is_raw_kdf
        && ctx->capacity != PSA_KEY_DERIVATION_UNLIMITED_CAPACITY
        && ctx->output_offset == 0
        && (output_length + ctx->capacity) <= WOLFPSA_KDF_MAX_CACHE_BYTES) {
        /* First output_bytes() call with a small bounded capacity: compute
         * the full derivation once and cache it. Subsequent calls serve
         * slices from the cache, avoiding O(n^2) recomputation. Capacities
         * above the cache bound (for example the SP800-108 counter-mode
         * default) skip this path and compute lazily per call. */
        size_t cache_length = output_length + ctx->capacity;

        ctx->output_cache = (uint8_t *)XMALLOC(cache_length, NULL,
                                               DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx->output_cache == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        status = wolfpsa_kdf_compute_output(ctx, ctx->output_cache,
                                            cache_length);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(ctx->output_cache, cache_length);
            XFREE(ctx->output_cache, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ctx->output_cache = NULL;
            return status;
        }
        ctx->output_cache_length = cache_length;
    }

    if (ctx->output_cache != NULL) {
        if (total_output_length > ctx->output_cache_length) {
            return PSA_ERROR_INSUFFICIENT_DATA;
        }
        XMEMCPY(output, ctx->output_cache + ctx->output_offset, output_length);
        status = PSA_SUCCESS;
    }
    else if (ctx->output_offset == 0) {
        status = wolfpsa_kdf_compute_output(ctx, output, output_length);
    }
    else {
        uint8_t *full_output;

        full_output = (uint8_t *)XMALLOC(total_output_length, NULL,
                                         DYNAMIC_TYPE_TMP_BUFFER);
        if (full_output == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        status = wolfpsa_kdf_compute_output(ctx, full_output, total_output_length);
        if (status == PSA_SUCCESS) {
            XMEMCPY(output, full_output + ctx->output_offset, output_length);
        }
        wc_ForceZero(full_output, total_output_length);
        XFREE(full_output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (status == PSA_SUCCESS) {
        ctx->output_offset += output_length;
    }
    return status;
}

psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
                                           psa_key_derivation_operation_t *operation,
                                           psa_key_id_t *key)
{
    size_t key_len;
    uint8_t *buffer;
    psa_status_t status;

    if (attributes == NULL || key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_KEY_TYPE_IS_UNSTRUCTURED(attributes->type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_len = PSA_BITS_TO_BYTES(attributes->bits);
    if (key_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    buffer = (uint8_t *)XMALLOC(key_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_key_derivation_output_bytes(operation, buffer, key_len);
    if (status != PSA_SUCCESS) {
        wc_ForceZero(buffer, key_len);
        XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    status = psa_import_key(attributes, buffer, key_len, key);
    wc_ForceZero(buffer, key_len);
    XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

psa_status_t psa_key_derivation_verify_bytes(psa_key_derivation_operation_t *operation,
                                             const uint8_t *expected,
                                             size_t expected_length)
{
    uint8_t *buffer;
    uint8_t dummy = 0;
    psa_status_t status;

    if (expected == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (expected_length > INT_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (expected_length == 0) {
        return psa_key_derivation_output_bytes(operation, &dummy, 0);
    }

    buffer = (uint8_t *)XMALLOC(expected_length, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_key_derivation_output_bytes(operation, buffer, expected_length);
    if (status != PSA_SUCCESS) {
        wc_ForceZero(buffer, expected_length);
        XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    if (ConstantCompare(buffer, expected, (int)expected_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }
    else {
        status = PSA_SUCCESS;
    }

    wc_ForceZero(buffer, expected_length);
    XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

psa_status_t psa_key_derivation_verify_key(psa_key_derivation_operation_t *operation,
                                           psa_key_id_t expected)
{
    uint8_t *expected_data = NULL;
    size_t expected_length = 0;
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = psa_get_key_attributes(expected, &attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((psa_get_key_usage_flags(&attributes) & PSA_KEY_USAGE_VERIFY_DERIVATION) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_PASSWORD_HASH) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_RAW_DATA) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_get_key_data(expected, NULL, &expected_data, &expected_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(expected_data, expected_length);
        return status;
    }

    status = psa_key_derivation_verify_bytes(operation, expected_data,
                                             expected_length);
    wolfpsa_forcezero_free_key_data(expected_data, expected_length);
    return status;
}

#endif /* WOLFSSL_PSA_ENGINE */
