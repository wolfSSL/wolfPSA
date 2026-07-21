/* psa_mac.c
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

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfssl/wolfcrypt/hmac.h>
#ifdef WOLFSSL_CMAC
#include <wolfssl/wolfcrypt/cmac.h>
#endif
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

typedef enum {
    WOLFPSA_MAC_NONE = 0,
    WOLFPSA_MAC_HMAC,
    WOLFPSA_MAC_CMAC
} wolfpsa_mac_type_t;

typedef struct wolfpsa_mac_ctx {
    psa_algorithm_t alg;
    psa_key_type_t key_type;
    size_t key_bits;
    size_t mac_length;
    size_t full_length;
    wolfpsa_mac_type_t type;
    union {
        Hmac hmac;
#ifdef WOLFSSL_CMAC
        Cmac cmac;
#endif
    } ctx;
} wolfpsa_mac_ctx_t;

static wolfpsa_mac_ctx_t* wolfpsa_mac_get_ctx(psa_mac_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }
    return (wolfpsa_mac_ctx_t *)(uintptr_t)operation->opaque;
}

static void wolfpsa_mac_free_underlying(wolfpsa_mac_ctx_t *ctx)
{
    if (ctx->type == WOLFPSA_MAC_HMAC) {
        wc_HmacFree(&ctx->ctx.hmac);
    }
#ifdef WOLFSSL_CMAC
    if (ctx->type == WOLFPSA_MAC_CMAC) {
        wc_CmacFree(&ctx->ctx.cmac);
    }
#endif
}

psa_status_t psa_mac_abort(psa_mac_operation_t *operation);

static psa_status_t wolfpsa_mac_fail(psa_mac_operation_t *operation,
                                     psa_status_t status)
{
    (void)psa_mac_abort(operation);
    return status;
}

static int wolfpsa_hash_type_from_alg(psa_algorithm_t alg)
{
    psa_algorithm_t hash_alg = 0;

    if (PSA_ALG_IS_HMAC(alg)) {
        hash_alg = PSA_ALG_HMAC_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_HASH(alg)) {
        hash_alg = alg;
    }

    switch (hash_alg) {
        case PSA_ALG_MD5:
            return WC_HASH_TYPE_MD5;
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

static psa_status_t wolfpsa_mac_check_key(psa_key_id_t key,
                                          psa_key_usage_t usage,
                                          psa_algorithm_t alg,
                                          psa_key_attributes_t *attributes,
                                          uint8_t **key_data,
                                          size_t *key_data_length)
{
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    psa_algorithm_t key_alg_full;
    psa_algorithm_t req_alg_full;
    size_t req_mac_length;
    size_t key_full_length;
    size_t key_min_length;

    status = wolfpsa_get_key_data(key, attributes, key_data, key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_ALG_IS_HMAC(alg)) {
        if (attributes->type != PSA_KEY_TYPE_HMAC) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_ALG_IS_BLOCK_CIPHER_MAC(alg)) {
#ifndef WOLFSSL_CMAC
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_SUPPORTED;
#endif
        if (attributes->type != PSA_KEY_TYPE_AES) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & usage) != usage) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(attributes);
    if (key_alg == PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Algorithm match checks */
    key_alg_full = PSA_ALG_FULL_LENGTH_MAC(key_alg);
    req_alg_full = PSA_ALG_FULL_LENGTH_MAC(alg);

    if (key_alg_full != req_alg_full) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    req_mac_length = PSA_MAC_LENGTH(attributes->type, attributes->bits, alg);
    key_full_length = PSA_MAC_LENGTH(attributes->type, attributes->bits, key_alg_full);
    key_min_length = PSA_MAC_TRUNCATED_LENGTH(key_alg);
    if (key_min_length == 0) {
        key_min_length = key_full_length;
    }

    if ((key_alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        if (req_mac_length < key_min_length) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else {
        if ((key_alg & PSA_ALG_MAC_TRUNCATION_MASK) != 0) {
            if (req_mac_length != key_min_length) {
                wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
                *key_data = NULL;
                *key_data_length = 0;
                return PSA_ERROR_NOT_PERMITTED;
            }
        }
        else if (req_mac_length != key_full_length) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }

    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_mac_setup(psa_mac_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg,
                                      psa_key_usage_t usage)
{
    psa_status_t status;
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    wolfpsa_mac_ctx_t *ctx = NULL;
    int ret;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_MAC(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_mac_check_key(key, usage, alg, &attributes,
                                   &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = (wolfpsa_mac_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));

    ctx->alg = alg;
    ctx->key_type = attributes.type;
    ctx->key_bits = attributes.bits;
    ctx->mac_length = PSA_MAC_LENGTH(attributes.type, attributes.bits, alg);
    ctx->full_length = PSA_MAC_LENGTH(attributes.type, attributes.bits,
                                       PSA_ALG_FULL_LENGTH_MAC(alg));
    if (wolfpsa_check_word32_length(key_data_length) != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_ALG_IS_HMAC(alg)) {
        int hash_type = wolfpsa_hash_type_from_alg(alg);
        if (hash_type == WC_HASH_TYPE_NONE) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        ret = wc_HmacSetKey(&ctx->ctx.hmac, hash_type, key_data,
                            (word32)key_data_length);
        ctx->type = WOLFPSA_MAC_HMAC;
    }
#ifdef WOLFSSL_CMAC
    else if (PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) &&
             PSA_ALG_FULL_LENGTH_MAC(alg) == PSA_ALG_CMAC) {
        ret = wc_InitCmac(&ctx->ctx.cmac, key_data, (word32)key_data_length,
                          WC_CMAC_AES, NULL);
        ctx->type = WOLFPSA_MAC_CMAC;
    }
#endif
    else {
        ret = NOT_COMPILED_IN;
    }

    if (ctx->mac_length == 0 || ctx->full_length == 0 ||
        ctx->mac_length > ctx->full_length) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        wolfpsa_mac_free_underlying(ctx);
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((alg & PSA_ALG_MAC_TRUNCATION_MASK) != 0) {
        size_t trunc_len = PSA_MAC_TRUNCATED_LENGTH(alg);
        if (trunc_len > ctx->full_length) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            wolfpsa_mac_free_underlying(ctx);
            wc_ForceZero(ctx, sizeof(*ctx));
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (trunc_len < 4u) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            wolfpsa_mac_free_underlying(ctx);
            wc_ForceZero(ctx, sizeof(*ctx));
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret != 0) {
        wolfpsa_mac_free_underlying(ctx);
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg)
{
    return wolfpsa_mac_setup(operation, key, alg, PSA_KEY_USAGE_SIGN_MESSAGE);
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg)
{
    return wolfpsa_mac_setup(operation, key, alg, PSA_KEY_USAGE_VERIFY_MESSAGE);
}

psa_status_t psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length)
{
    wolfpsa_mac_ctx_t *ctx = wolfpsa_mac_get_ctx(operation);
    int ret;

    if (ctx == NULL) {
        return wolfpsa_mac_fail(operation, PSA_ERROR_BAD_STATE);
    }
    if (input == NULL && input_length > 0) {
        return wolfpsa_mac_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }
    if (wolfpsa_check_word32_length(input_length) != PSA_SUCCESS) {
        return wolfpsa_mac_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }

    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    if (ctx->type == WOLFPSA_MAC_HMAC) {
        ret = wc_HmacUpdate(&ctx->ctx.hmac, input, (word32)input_length);
    }
#ifdef WOLFSSL_CMAC
    else if (ctx->type == WOLFPSA_MAC_CMAC) {
        ret = wc_CmacUpdate(&ctx->ctx.cmac, input, (word32)input_length);
    }
#endif
    else {
        return wolfpsa_mac_fail(operation, PSA_ERROR_BAD_STATE);
    }

    if (ret != 0) {
        return wolfpsa_mac_fail(operation, wc_error_to_psa_status(ret));
    }

    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_mac_final(wolfpsa_mac_ctx_t *ctx,
                                      uint8_t *mac,
                                      size_t mac_size,
                                      size_t *mac_length)
{
    uint8_t full_mac[PSA_MAC_MAX_SIZE];
    word32 full_len = 0;
    int ret;
    psa_status_t status;

    if (mac == NULL || mac_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->full_length > sizeof(full_mac)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mac_size < ctx->mac_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (ctx->type == WOLFPSA_MAC_HMAC) {
        full_len = (word32)sizeof(full_mac);
        ret = wc_HmacFinal(&ctx->ctx.hmac, full_mac);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto cleanup;
        }
        full_len = (word32)ctx->full_length;
    }
#ifdef WOLFSSL_CMAC
    else if (ctx->type == WOLFPSA_MAC_CMAC) {
        full_len = (word32)ctx->full_length;
        ret = wc_CmacFinal(&ctx->ctx.cmac, full_mac, &full_len);
        if (ret != 0) {
            status = wc_error_to_psa_status(ret);
            goto cleanup;
        }
    }
#endif
    else {
        status = PSA_ERROR_BAD_STATE;
        goto cleanup;
    }

    if (ctx->mac_length > (size_t)full_len) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    XMEMCPY(mac, full_mac, ctx->mac_length);
    *mac_length = ctx->mac_length;
    status = PSA_SUCCESS;

cleanup:
    wc_ForceZero(full_mac, sizeof(full_mac));
    return status;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation,
                                 uint8_t *mac,
                                 size_t mac_size,
                                 size_t *mac_length)
{
    wolfpsa_mac_ctx_t *ctx = wolfpsa_mac_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return wolfpsa_mac_fail(operation, PSA_ERROR_BAD_STATE);
    }

    status = wolfpsa_mac_final(ctx, mac, mac_size, mac_length);
    if (status != PSA_SUCCESS) {
        return wolfpsa_mac_fail(operation, status);
    }

    psa_mac_abort(operation);
    return PSA_SUCCESS;
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
                                   const uint8_t *mac,
                                   size_t mac_length)
{
    wolfpsa_mac_ctx_t *ctx = wolfpsa_mac_get_ctx(operation);
    uint8_t computed[PSA_MAC_MAX_SIZE];
    size_t computed_length = 0;
    size_t min_length;
    size_t compare_length;
    psa_status_t status = PSA_ERROR_BAD_STATE;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (mac == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    min_length = ctx->mac_length;
    if ((ctx->alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        if (mac_length < min_length || mac_length > ctx->full_length) {
            psa_mac_abort(operation);
            return PSA_ERROR_INVALID_SIGNATURE;
        }
    }
    else {
        if (mac_length != min_length) {
            psa_mac_abort(operation);
            return PSA_ERROR_INVALID_SIGNATURE;
        }
    }

    compare_length = ctx->mac_length;
    if ((ctx->alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        ctx->mac_length = ctx->full_length;
    }
    status = wolfpsa_mac_final(ctx, computed, sizeof(computed),
                               &computed_length);
    ctx->mac_length = compare_length;
    psa_mac_abort(operation);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    if (mac_length > computed_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    if (ConstantCompare(computed, mac, (int)mac_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = PSA_SUCCESS;

cleanup:
    wc_ForceZero(computed, sizeof(computed));
    return status;
}

psa_status_t psa_mac_abort(psa_mac_operation_t *operation)
{
    wolfpsa_mac_ctx_t *ctx = wolfpsa_mac_get_ctx(operation);

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx != NULL) {
        if (ctx->type == WOLFPSA_MAC_HMAC) {
            wc_HmacFree(&ctx->ctx.hmac);
        }
#ifdef WOLFSSL_CMAC
        if (ctx->type == WOLFPSA_MAC_CMAC) {
            wc_CmacFree(&ctx->ctx.cmac);
        }
#endif
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        operation->opaque = (uintptr_t)NULL;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length)
{
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_status_t status;

    status = psa_mac_sign_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_mac_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        psa_mac_abort(&operation);
        return status;
    }

    status = psa_mac_sign_finish(&operation, mac, mac_size, mac_length);
    if (status != PSA_SUCCESS) {
        psa_mac_abort(&operation);
        return status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t *input,
                            size_t input_length,
                            const uint8_t *mac,
                            size_t mac_length)
{
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_status_t status;

    status = psa_mac_verify_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_mac_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        psa_mac_abort(&operation);
        return status;
    }

    status = psa_mac_verify_finish(&operation, mac, mac_length);
    if (status != PSA_SUCCESS) {
        psa_mac_abort(&operation);
        return status;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
