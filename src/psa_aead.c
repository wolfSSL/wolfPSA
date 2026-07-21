/* psa_aead.c
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
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfpsa/psa_chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#ifdef HAVE_XCHACHA
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>
#endif
#include "psa_aead_internal.h"
#include "psa_size.h"

static wolfpsa_aead_ctx_t* wolfpsa_aead_get_ctx(psa_aead_operation_t *operation)
{
    return wolfpsa_aead_get_ctx_ptr(operation);
}

static psa_status_t wolfpsa_aead_append(uint8_t **buf, size_t *len,
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

static const uint8_t* wolfpsa_aead_nonnull_data(const uint8_t *data,
                                                size_t data_length)
{
    static const uint8_t empty = 0;

    if (data == NULL && data_length == 0) {
        return &empty;
    }

    return data;
}

static size_t wolfpsa_aead_tag_length(psa_algorithm_t alg)
{
    return PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
}

#ifdef HAVE_AESGCM
static int wolfpsa_aead_gcm_check_tag_size(size_t tag_length)
{
    return tag_length == 4 || tag_length == 8 ||
           (tag_length >= 12 && tag_length <= WC_AES_BLOCK_SIZE);
}
#endif

static psa_status_t wolfpsa_aead_check_key(psa_key_id_t key,
                                           psa_key_usage_t usage,
                                           psa_algorithm_t alg,
                                           psa_key_attributes_t *attributes,
                                           uint8_t **key_data,
                                           size_t *key_data_length)
{
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    psa_algorithm_t key_base;
    psa_algorithm_t req_base;
    size_t key_tag_len;
    size_t req_tag_len;

    status = wolfpsa_get_key_data(key, attributes, key_data, key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM) ||
        PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        if (attributes->type != PSA_KEY_TYPE_AES) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CHACHA20_POLY1305)) {
        if (attributes->type != PSA_KEY_TYPE_CHACHA20) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        /* XChaCha20-Poly1305 and Ascon-AEAD128 never reach this function:
         * they are one-shot only and rejected by wolfpsa_aead_setup before
         * the key is checked; the one-shot paths validate the key inline. */
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & usage) == 0) {
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
    key_base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(key_alg);
    req_base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
    key_tag_len = wolfpsa_aead_tag_length(key_alg);
    req_tag_len = wolfpsa_aead_tag_length(alg);

    if (key_tag_len == 0 || req_tag_len == 0) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_base != req_base) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    if ((key_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        if (req_tag_len < key_tag_len) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else if (req_tag_len != key_tag_len) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_aead_setup(psa_aead_operation_t *operation,
                                       psa_key_id_t key,
                                       psa_algorithm_t alg,
                                       psa_key_usage_t usage)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    wolfpsa_aead_ctx_t *ctx;
    psa_status_t status;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_AEAD(alg) || PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM_STAR_NO_TAG)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#ifndef HAVE_AESGCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#ifndef HAVE_AESCCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#if !defined(HAVE_CHACHA) || !defined(HAVE_POLY1305)
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CHACHA20_POLY1305)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    /* XChaCha20-Poly1305 and Ascon-AEAD128 are one-shot only; wolfCrypt
     * provides no streaming API for these algorithms. */
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305) ||
        PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = wolfpsa_aead_check_key(key, usage, alg, &attributes,
                                    &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = (wolfpsa_aead_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));

    ctx->alg = alg;
    ctx->key_type = attributes.type;
    ctx->key_bits = attributes.bits;
    ctx->tag_length = wolfpsa_aead_tag_length(alg);
    if (ctx->tag_length == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ctx->direction = (usage == PSA_KEY_USAGE_ENCRYPT) ? 1 : 0;
#ifdef HAVE_AESCCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM) &&
        wc_AesCcmCheckTagSize((int)ctx->tag_length) != 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif
#ifdef HAVE_AESGCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM) &&
        !wolfpsa_aead_gcm_check_tag_size(ctx->tag_length)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    ctx->key = (uint8_t *)XMALLOC(key_data_length, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx->key == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMCPY(ctx->key, key_data, key_data_length);
    ctx->key_length = key_data_length;

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    return wolfpsa_aead_setup(operation, key, alg, PSA_KEY_USAGE_ENCRYPT);
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    return wolfpsa_aead_setup(operation, key, alg, PSA_KEY_USAGE_DECRYPT);
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length != 0 || ctx->aad_length != 0 || ctx->input_length != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    ctx->ad_expected = ad_length;
    ctx->plaintext_expected = plaintext_length;
    ctx->lengths_set = 1;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
                                const uint8_t *nonce,
                                size_t nonce_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    size_t expected;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (nonce == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->nonce_length != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
        if (nonce_length < 12 || nonce_length > PSA_AEAD_NONCE_MAX_SIZE) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
        if (nonce_length < 7 || nonce_length > 13) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        expected = PSA_AEAD_NONCE_LENGTH(ctx->key_type, ctx->alg);
        if (expected == 0 || nonce_length != expected) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    XMEMCPY(ctx->nonce, nonce, nonce_length);
    ctx->nonce_length = nonce_length;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
                                     uint8_t *nonce,
                                     size_t nonce_size,
                                     size_t *nonce_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    size_t expected;
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (nonce == NULL || nonce_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!ctx->direction) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length != 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }

    expected = PSA_AEAD_NONCE_LENGTH(ctx->key_type, ctx->alg);
    if (expected == 0 || nonce_size < expected) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = psa_generate_random(nonce, expected);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_aead_set_nonce(operation, nonce, expected);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *nonce_length = expected;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->lengths_set &&
        (input_length > SIZE_MAX - ctx->aad_length ||
         ctx->aad_length + input_length > ctx->ad_expected)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        psa_aead_abort(operation);
        return status;
    }

    status = wolfpsa_aead_append(&ctx->aad, &ctx->aad_length, input, input_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(operation);
    }
    return status;
}

psa_status_t psa_aead_update(psa_aead_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *output,
                             size_t output_size,
                             size_t *output_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)output;
    (void)output_size;
    *output_length = 0;

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->lengths_set && ctx->aad_length != ctx->ad_expected) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        psa_aead_abort(operation);
        return status;
    }
    if (ctx->lengths_set &&
        (input_length > SIZE_MAX - ctx->input_length ||
         ctx->input_length + input_length > ctx->plaintext_expected)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        psa_aead_abort(operation);
        return status;
    }
    if (output != NULL && input_length > 0 && output_size < input_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        psa_aead_abort(operation);
        return status;
    }

    status = wolfpsa_aead_append(&ctx->input, &ctx->input_length, input, input_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(operation);
    }
    return status;
}

static psa_status_t wolfpsa_aead_encrypt_final(wolfpsa_aead_ctx_t *ctx,
                                               uint8_t *ciphertext,
                                               size_t ciphertext_size,
                                               size_t *ciphertext_length,
                                               uint8_t *tag,
                                               size_t tag_size,
                                               size_t *tag_length)
{
    int ret;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    size_t chacha_ciphertext_size = 0;
#endif
    const uint8_t *input;
    const uint8_t *aad;

    if (ciphertext == NULL || ciphertext_length == NULL ||
        tag == NULL || tag_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->lengths_set &&
        (ctx->aad_length != ctx->ad_expected ||
         ctx->input_length != ctx->plaintext_expected)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
        if (ctx->input_length > SIZE_MAX - ctx->tag_length) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        chacha_ciphertext_size = ctx->input_length + ctx->tag_length;
    }
#endif

    if (ciphertext_size < ctx->input_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (tag_size < ctx->tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if ((wolfpsa_check_word32_length(ctx->input_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->aad_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    input = wolfpsa_aead_nonnull_data(ctx->input, ctx->input_length);
    aad = wolfpsa_aead_nonnull_data(ctx->aad, ctx->aad_length);

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
#ifdef HAVE_AESGCM
        Aes aes;
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesGcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesGcmEncrypt(&aes, ciphertext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)ctx->tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
#ifdef HAVE_AESCCM
        Aes aes;
        if (wc_AesCcmCheckTagSize((int)ctx->tag_length) != 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesCcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesCcmEncrypt(&aes, ciphertext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)ctx->tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        size_t out_len = 0;
        uint8_t *tmp = (uint8_t *)XMALLOC(chacha_ciphertext_size, NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ret = psa_chacha20_poly1305_encrypt(ctx->key, ctx->key_length, ctx->alg,
                                            ctx->nonce, ctx->nonce_length,
                                            aad, ctx->aad_length,
                                            input, ctx->input_length,
                                            tmp, chacha_ciphertext_size,
                                            &out_len);
        if (ret != 0) {
            wc_ForceZero(tmp, chacha_ciphertext_size);
            XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return (psa_status_t)ret;
        }
        if (out_len < ctx->input_length + ctx->tag_length) {
            wc_ForceZero(tmp, chacha_ciphertext_size);
            XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_GENERIC_ERROR;
        }
        XMEMCPY(ciphertext, tmp, ctx->input_length);
        XMEMCPY(tag, tmp + ctx->input_length, ctx->tag_length);
        wc_ForceZero(tmp, chacha_ciphertext_size);
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *ciphertext_length = ctx->input_length;
    *tag_length = ctx->tag_length;
    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_aead_decrypt_final(wolfpsa_aead_ctx_t *ctx,
                                               uint8_t *plaintext,
                                               size_t plaintext_size,
                                               size_t *plaintext_length,
                                               const uint8_t *tag,
                                               size_t tag_length)
{
    int ret;
    const uint8_t *input;
    const uint8_t *aad;

    if (plaintext == NULL || plaintext_length == NULL || tag == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->lengths_set &&
        (ctx->aad_length != ctx->ad_expected ||
         ctx->input_length != ctx->plaintext_expected)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_size < ctx->input_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (tag_length != ctx->tag_length &&
        (ctx->alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) == 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (tag_length < ctx->tag_length &&
        (ctx->alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if ((wolfpsa_check_word32_length(ctx->input_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->aad_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    input = wolfpsa_aead_nonnull_data(ctx->input, ctx->input_length);
    aad = wolfpsa_aead_nonnull_data(ctx->aad, ctx->aad_length);

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
#ifdef HAVE_AESGCM
        Aes aes;
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesGcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesGcmDecrypt(&aes, plaintext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret == AES_GCM_AUTH_E || ret == MAC_CMP_FAILED_E) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
#ifdef HAVE_AESCCM
        Aes aes;
        if (wc_AesCcmCheckTagSize((int)tag_length) != 0) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesCcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesCcmDecrypt(&aes, plaintext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret == AES_CCM_AUTH_E || ret == MAC_CMP_FAILED_E) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        size_t out_len = 0;
        uint8_t *ciphertext = ctx->input;
        size_t ciphertext_len;
        uint8_t *tmp;
        if (ctx->input_length > SIZE_MAX - tag_length) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ciphertext_len = ctx->input_length + tag_length;
        tmp = (uint8_t *)XMALLOC(ciphertext_len, NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        XMEMCPY(tmp, ciphertext, ctx->input_length);
        XMEMCPY(tmp + ctx->input_length, tag, tag_length);
        ret = psa_chacha20_poly1305_decrypt(ctx->key, ctx->key_length, ctx->alg,
                                            ctx->nonce, ctx->nonce_length,
                                            aad, ctx->aad_length,
                                            tmp, ciphertext_len,
                                            plaintext, plaintext_size, &out_len);
        wc_ForceZero(tmp, ciphertext_len);
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ret != 0) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        *plaintext_length = out_len;
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *plaintext_length = ctx->input_length;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length,
                             uint8_t *tag,
                             size_t tag_size,
                             size_t *tag_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!ctx->direction) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_aead_encrypt_final(ctx, ciphertext, ciphertext_size,
                                        ciphertext_length, tag, tag_size,
                                        tag_length);
    psa_aead_abort(operation);
    return status;
}

psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
                             uint8_t *plaintext,
                             size_t plaintext_size,
                             size_t *plaintext_length,
                             const uint8_t *tag,
                             size_t tag_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->direction) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_aead_decrypt_final(ctx, plaintext, plaintext_size,
                                        plaintext_length, tag, tag_length);
    psa_aead_abort(operation);
    return status;
}

#ifdef HAVE_XCHACHA
/* One-shot encrypt for XChaCha20-Poly1305.
 * ciphertext = plaintext || tag (16-byte Poly1305 tag appended). */
static psa_status_t wolfpsa_xchacha_oneshot_encrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    int ret;
    /* Encrypt produces plaintext_length bytes of ciphertext plus 16-byte tag. */
    size_t out_len;

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than silently emitting a full-length tag. */
    if (alg != PSA_ALG_XCHACHA20_POLY1305) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != XCHACHA20_POLY1305_AEAD_NONCE_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check for overflow before output-size check. */
    if (plaintext_length > SIZE_MAX - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    out_len = plaintext_length + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (ciphertext_size < out_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_XCHACHA20 ||
        key_data_length != CHACHA20_POLY1305_AEAD_KEYSIZE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_ENCRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_XCHACHA20_POLY1305)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wc_XChaCha20Poly1305_Encrypt(
        ciphertext, ciphertext_size,
        plaintext, plaintext_length,
        additional_data, additional_data_length,
        nonce, nonce_length,
        key_data, key_data_length);

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *ciphertext_length = out_len;
    return PSA_SUCCESS;
}

/* One-shot decrypt for XChaCha20-Poly1305.
 * ciphertext = ciphertext_body || tag (16-byte Poly1305 tag appended). */
static psa_status_t wolfpsa_xchacha_oneshot_decrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    int ret;
    size_t pt_len;

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than mis-framing the trailing tag bytes. */
    if (alg != PSA_ALG_XCHACHA20_POLY1305) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != XCHACHA20_POLY1305_AEAD_NONCE_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    pt_len = ciphertext_length - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (plaintext_size < pt_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_XCHACHA20 ||
        key_data_length != CHACHA20_POLY1305_AEAD_KEYSIZE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_XCHACHA20_POLY1305)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* wc_XChaCha20Poly1305_Decrypt expects src = ciphertext || tag and
     * dst_space must accommodate pt_len output bytes. */
    ret = wc_XChaCha20Poly1305_Decrypt(
        plaintext, plaintext_size,
        ciphertext, ciphertext_length,
        additional_data, additional_data_length,
        nonce, nonce_length,
        key_data, key_data_length);

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret == MAC_CMP_FAILED_E) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *plaintext_length = pt_len;
    return PSA_SUCCESS;
}
#endif /* HAVE_XCHACHA */

#ifdef HAVE_ASCON
/* One-shot encrypt for Ascon-AEAD128.
 * ciphertext = encrypted_body || tag (16-byte tag appended). */
static psa_status_t wolfpsa_ascon_oneshot_encrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    wc_AsconAEAD128 ascon;
    int ret;
    size_t out_len;

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than silently emitting a full-length tag. */
    if (alg != PSA_ALG_ASCON_AEAD128) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != ASCON_AEAD128_NONCE_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_length > SIZE_MAX - ASCON_AEAD128_TAG_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    out_len = plaintext_length + ASCON_AEAD128_TAG_SZ;
    if (ciphertext_size < out_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if ((wolfpsa_check_word32_length(plaintext_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(additional_data_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_ASCON ||
        key_data_length != ASCON_AEAD128_KEY_SZ) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_ENCRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_ASCON_AEAD128)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wc_AsconAEAD128_Init(&ascon);
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetKey(&ascon, key_data);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetNonce(&ascon, nonce);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetAD(&ascon, additional_data,
                                    (word32)additional_data_length);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_EncryptUpdate(&ascon, ciphertext,
                                            plaintext, (word32)plaintext_length);
    }
    if (ret == 0) {
        /* Tag is written to ciphertext + plaintext_length. */
        ret = wc_AsconAEAD128_EncryptFinal(&ascon,
                                           ciphertext + plaintext_length);
    }

    wc_AsconAEAD128_Clear(&ascon);
    wc_ForceZero(&ascon, sizeof(ascon));
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *ciphertext_length = out_len;
    return PSA_SUCCESS;
}

/* One-shot decrypt for Ascon-AEAD128.
 * ciphertext = encrypted_body || tag (16-byte tag appended). */
static psa_status_t wolfpsa_ascon_oneshot_decrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    wc_AsconAEAD128 ascon;
    int ret;
    size_t ct_len; /* ciphertext body length (without tag) */

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than mis-framing the trailing tag bytes. */
    if (alg != PSA_ALG_ASCON_AEAD128) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != ASCON_AEAD128_NONCE_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length < ASCON_AEAD128_TAG_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ct_len = ciphertext_length - ASCON_AEAD128_TAG_SZ;
    if (plaintext_size < ct_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if ((wolfpsa_check_word32_length(ct_len) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(additional_data_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_ASCON ||
        key_data_length != ASCON_AEAD128_KEY_SZ) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_ASCON_AEAD128)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wc_AsconAEAD128_Init(&ascon);
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetKey(&ascon, key_data);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetNonce(&ascon, nonce);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetAD(&ascon, additional_data,
                                    (word32)additional_data_length);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_DecryptUpdate(&ascon, plaintext,
                                            ciphertext, (word32)ct_len);
    }
    if (ret == 0) {
        /* Tag is at ciphertext + ct_len. */
        ret = wc_AsconAEAD128_DecryptFinal(&ascon, ciphertext + ct_len);
    }

    wc_AsconAEAD128_Clear(&ascon);
    wc_ForceZero(&ascon, sizeof(ascon));
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret == MAC_CMP_FAILED_E || ret == ASCON_AUTH_E) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *plaintext_length = ct_len;
    return PSA_SUCCESS;
}
#endif /* HAVE_ASCON */

psa_status_t psa_aead_encrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *plaintext,
                              size_t plaintext_length,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length)
{
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    psa_status_t status;
    uint8_t tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t tag_length = 0;
    size_t out_len = 0;

    /* One-shot-only algorithms: bypass the multipart state machine. */
#ifdef HAVE_XCHACHA
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305)) {
        return wolfpsa_xchacha_oneshot_encrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, plaintext, plaintext_length,
            ciphertext, ciphertext_size, ciphertext_length);
    }
#endif /* HAVE_XCHACHA */
#ifdef HAVE_ASCON
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128)) {
        return wolfpsa_ascon_oneshot_encrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, plaintext, plaintext_length,
            ciphertext, ciphertext_size, ciphertext_length);
    }
#endif /* HAVE_ASCON */

    status = psa_aead_encrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        status = psa_aead_set_lengths(&operation, additional_data_length,
                                      plaintext_length);
        if (status != PSA_SUCCESS) {
            psa_aead_abort(&operation);
            return status;
        }
    }

    status = psa_aead_set_nonce(&operation, nonce, nonce_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update_ad(&operation, additional_data, additional_data_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update(&operation, plaintext, plaintext_length,
                             NULL, 0, &out_len);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    {
        size_t needed_tag_len = wolfpsa_aead_tag_length(alg);
        if (needed_tag_len > ciphertext_size ||
            ciphertext_size - needed_tag_len < plaintext_length) {
            psa_aead_abort(&operation);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }

    status = psa_aead_finish(&operation, ciphertext, ciphertext_size,
                             &out_len, tag, sizeof(tag), &tag_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (ciphertext_size < out_len + tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    XMEMCPY(ciphertext + out_len, tag, tag_length);
    *ciphertext_length = out_len + tag_length;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_decrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *ciphertext,
                              size_t ciphertext_length,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length)
{
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    psa_status_t status;
    size_t tag_length;
    size_t ct_len;

    /* One-shot-only algorithms: bypass the multipart state machine. */
#ifdef HAVE_XCHACHA
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305)) {
        return wolfpsa_xchacha_oneshot_decrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, ciphertext, ciphertext_length,
            plaintext, plaintext_size, plaintext_length);
    }
#endif /* HAVE_XCHACHA */
#ifdef HAVE_ASCON
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128)) {
        return wolfpsa_ascon_oneshot_decrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, ciphertext, ciphertext_length,
            plaintext, plaintext_size, plaintext_length);
    }
#endif /* HAVE_ASCON */

    status = psa_aead_decrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    tag_length = wolfpsa_aead_tag_length(alg);
    if (tag_length == 0 || ciphertext_length < tag_length) {
        psa_aead_abort(&operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ct_len = ciphertext_length - tag_length;

    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        status = psa_aead_set_lengths(&operation, additional_data_length,
                                      ct_len);
        if (status != PSA_SUCCESS) {
            psa_aead_abort(&operation);
            return status;
        }
    }

    status = psa_aead_set_nonce(&operation, nonce, nonce_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update_ad(&operation, additional_data, additional_data_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update(&operation, ciphertext, ct_len,
                             NULL, 0, plaintext_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_verify(&operation, plaintext, plaintext_size,
                             plaintext_length,
                             ciphertext + ct_len, tag_length);
    return status;
}

psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx != NULL) {
        if (ctx->aad != NULL) {
            wc_ForceZero(ctx->aad, ctx->aad_length);
            XFREE(ctx->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        if (ctx->input != NULL) {
            wc_ForceZero(ctx->input, ctx->input_length);
            XFREE(ctx->input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        if (ctx->key != NULL) {
            wc_ForceZero(ctx->key, ctx->key_length);
            XFREE(ctx->key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        operation->opaque = (uintptr_t)NULL;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
