/* psa_cipher.c
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
#include "psa_trace.h"
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfssl/wolfcrypt/aes.h>
#ifndef NO_DES3
#include <wolfssl/wolfcrypt/des3.h>
#endif
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define WOLFPSA_CHACHA20_IV_BYTES 12

typedef struct wolfpsa_cipher_ctx {
    psa_algorithm_t alg;
    psa_key_type_t key_type;
    size_t key_bits;
    int direction;
    int iv_set;
    int iv_attempted;
    int is_chacha;
    int is_des3;
    size_t block_size;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t partial[AES_BLOCK_SIZE];
    size_t partial_len;
    Aes aes;
#ifndef NO_DES3
    Des3 des3;
#endif
#ifdef HAVE_CHACHA
    ChaCha chacha;
#endif
} wolfpsa_cipher_ctx_t;

static wolfpsa_cipher_ctx_t *wolfpsa_cipher_get_ctx(
    psa_cipher_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }
    return (wolfpsa_cipher_ctx_t *)(uintptr_t)operation->opaque;
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation);

static psa_status_t wolfpsa_cipher_fail(psa_cipher_operation_t *operation,
                                        psa_status_t status)
{
    (void)psa_cipher_abort(operation);
    return status;
}

static psa_status_t wolfpsa_cipher_check_alg(psa_algorithm_t alg)
{
    if (!PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch (alg) {
        case PSA_ALG_CBC_NO_PADDING:
        case PSA_ALG_CBC_PKCS7:
            return PSA_SUCCESS;
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_DES_ECB)
        case PSA_ALG_ECB_NO_PADDING:
            return PSA_SUCCESS;
#endif
#ifdef WOLFSSL_AES_COUNTER
        case PSA_ALG_CTR:
        case PSA_ALG_CCM_STAR_NO_TAG:
            return PSA_SUCCESS;
#endif
#ifdef WOLFSSL_AES_CFB
        case PSA_ALG_CFB:
            return PSA_SUCCESS;
#endif
#ifdef WOLFSSL_AES_OFB
        case PSA_ALG_OFB:
            return PSA_SUCCESS;
#endif
#ifdef HAVE_CHACHA
        case PSA_ALG_STREAM_CIPHER:
            return PSA_SUCCESS;
#endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

static size_t wolfpsa_cipher_block_size(psa_key_type_t key_type)
{
#ifndef NO_DES3
    return (key_type == PSA_KEY_TYPE_DES) ? DES_BLOCK_SIZE : AES_BLOCK_SIZE;
#else
    (void)key_type;
    return AES_BLOCK_SIZE;
#endif
}

static size_t wolfpsa_cipher_iv_length(psa_algorithm_t alg,
                                       psa_key_type_t key_type)
{
    switch (alg) {
        case PSA_ALG_CBC_NO_PADDING:
        case PSA_ALG_CBC_PKCS7:
        case PSA_ALG_CTR:
        case PSA_ALG_CFB:
        case PSA_ALG_OFB:
            return wolfpsa_cipher_block_size(key_type);
        case PSA_ALG_STREAM_CIPHER:
            return WOLFPSA_CHACHA20_IV_BYTES;
        case PSA_ALG_CCM_STAR_NO_TAG:
            return 13;
        default:
            return 0;
    }
}

static psa_status_t wolfpsa_cipher_check_key(
    psa_key_id_t key,
    psa_key_usage_t usage,
    psa_algorithm_t alg,
    psa_key_attributes_t *attributes,
    uint8_t **key_data,
    size_t *key_data_length)
{
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;

    status = wolfpsa_get_key_data(key, attributes, key_data, key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

#ifndef HAVE_CHACHA
    if (alg == PSA_ALG_STREAM_CIPHER) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    if (alg == PSA_ALG_STREAM_CIPHER) {
        if (attributes->type != PSA_KEY_TYPE_CHACHA20) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (attributes->type == PSA_KEY_TYPE_DES) {
        if (alg != PSA_ALG_CBC_NO_PADDING && alg != PSA_ALG_ECB_NO_PADDING) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (alg == PSA_ALG_ECB_NO_PADDING) {
#if defined(NO_DES3) || !defined(WOLFSSL_DES_ECB)
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_SUPPORTED;
#endif
        }
    }
    else {
        if (attributes->type != PSA_KEY_TYPE_AES) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (alg == PSA_ALG_ECB_NO_PADDING) {
#ifndef HAVE_AES_ECB
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_SUPPORTED;
#endif
        }
    }

    key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & usage) != usage) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(attributes);
    if (key_alg == PSA_ALG_NONE || key_alg != alg) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

#ifdef HAVE_CHACHA
    if (attributes->type == PSA_KEY_TYPE_CHACHA20) {
        if (*key_data_length != CHACHA_MAX_KEY_SZ) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (attributes->bits != 256) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }
#endif

    if (attributes->type == PSA_KEY_TYPE_DES) {
        if (*key_data_length == 16) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_SUPPORTED;
        }

        if (*key_data_length != 24) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (attributes->bits != (psa_key_bits_t)(*key_data_length * 8U)) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        return PSA_SUCCESS;
    }

    if (*key_data_length != 16 && *key_data_length != 24 &&
        *key_data_length != 32) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (attributes->bits != 128 && attributes->bits != 192 &&
        attributes->bits != 256) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                     psa_key_id_t key,
                                     psa_algorithm_t alg)
{
    wolfpsa_cipher_ctx_t *ctx;
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    int ret;
    uint8_t zero_iv[AES_BLOCK_SIZE] = {0};

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_trace("psa_cipher_encrypt_setup(key=%u alg=0x%08x)",
                  (unsigned)key, (unsigned)alg);
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_cipher_check_alg(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_cipher_check_key(key, PSA_KEY_USAGE_ENCRYPT, alg,
                                      &attributes, &key_data,
                                      &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = (wolfpsa_cipher_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;
    ctx->key_type = attributes.type;
    ctx->key_bits = attributes.bits;
    ctx->direction = AES_ENCRYPTION;
    ctx->iv_set = 0;
    ctx->iv_attempted = 0;
    ctx->is_chacha = (alg == PSA_ALG_STREAM_CIPHER);
#ifndef NO_DES3
    ctx->is_des3 = (attributes.type == PSA_KEY_TYPE_DES);
#else
    ctx->is_des3 = 0;
    if (attributes.type == PSA_KEY_TYPE_DES) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    ctx->block_size = wolfpsa_cipher_block_size(attributes.type);
    ctx->partial_len = 0;
    XMEMCPY(ctx->iv, zero_iv, sizeof(ctx->iv));
    if (wolfpsa_check_word32_length(key_data_length) != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#ifdef HAVE_CHACHA
    if (ctx->is_chacha) {
        ret = wc_Chacha_SetKey(&ctx->chacha, key_data,
                               (word32)key_data_length);
    }
    else
#endif
    if (ctx->is_des3) {
#ifndef NO_DES3
        byte des_key[DES3_KEY_SIZE];

        XMEMCPY(des_key, key_data, DES3_KEY_SIZE);

        ret = wc_Des3Init(&ctx->des3, NULL, wolfPSA_GetDefaultDevID());
        if (ret != 0) {
            wc_ForceZero(des_key, sizeof(des_key));
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return wc_error_to_psa_status(ret);
        }

        ret = wc_Des3_SetKey(&ctx->des3, des_key, ctx->iv, AES_ENCRYPTION);
        wc_ForceZero(des_key, sizeof(des_key));
#else
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else {
        ret = wc_AesInit(&ctx->aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret != 0) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return wc_error_to_psa_status(ret);
        }

#ifdef WOLFSSL_AES_COUNTER
        if (alg == PSA_ALG_CTR) {
            ret = wc_AesCtrSetKey(&ctx->aes, key_data, (word32)key_data_length,
                                  ctx->iv, AES_ENCRYPTION);
        }
        else
#endif
        if (alg == PSA_ALG_CCM_STAR_NO_TAG) {
            ret = wc_AesSetKey(&ctx->aes, key_data, (word32)key_data_length,
                               ctx->iv, AES_ENCRYPTION);
        }
        else
        {
            ret = wc_AesSetKey(&ctx->aes, key_data, (word32)key_data_length,
                               ctx->iv, AES_ENCRYPTION);
        }
    }
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    if (ret != 0) {
#ifndef NO_DES3
        if (ctx->is_des3) {
            wc_Des3Free(&ctx->des3);
        }
#else
        if (0) {
        }
#endif
        else if (!ctx->is_chacha) {
            wc_AesFree(&ctx->aes);
        }
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                     psa_key_id_t key,
                                     psa_algorithm_t alg)
{
    wolfpsa_cipher_ctx_t *ctx;
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    int ret;
    uint8_t zero_iv[AES_BLOCK_SIZE] = {0};

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_trace("psa_cipher_decrypt_setup(key=%u alg=0x%08x)",
                  (unsigned)key, (unsigned)alg);
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_cipher_check_alg(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_cipher_check_key(key, PSA_KEY_USAGE_DECRYPT, alg,
                                      &attributes, &key_data,
                                      &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = (wolfpsa_cipher_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;
    ctx->key_type = attributes.type;
    ctx->key_bits = attributes.bits;
    ctx->direction = AES_DECRYPTION;
    ctx->iv_set = 0;
    ctx->iv_attempted = 0;
    ctx->is_chacha = (alg == PSA_ALG_STREAM_CIPHER);
#ifndef NO_DES3
    ctx->is_des3 = (attributes.type == PSA_KEY_TYPE_DES);
#else
    ctx->is_des3 = 0;
    if (attributes.type == PSA_KEY_TYPE_DES) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    ctx->block_size = wolfpsa_cipher_block_size(attributes.type);
    ctx->partial_len = 0;
    XMEMCPY(ctx->iv, zero_iv, sizeof(ctx->iv));
    if (wolfpsa_check_word32_length(key_data_length) != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#ifdef HAVE_CHACHA
    if (ctx->is_chacha) {
        ret = wc_Chacha_SetKey(&ctx->chacha, key_data,
                               (word32)key_data_length);
    }
    else
#endif
    if (ctx->is_des3) {
#ifndef NO_DES3
        byte des_key[DES3_KEY_SIZE];

        XMEMCPY(des_key, key_data, DES3_KEY_SIZE);

        ret = wc_Des3Init(&ctx->des3, NULL, wolfPSA_GetDefaultDevID());
        if (ret != 0) {
            wc_ForceZero(des_key, sizeof(des_key));
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return wc_error_to_psa_status(ret);
        }

        ret = wc_Des3_SetKey(&ctx->des3, des_key, ctx->iv, AES_DECRYPTION);
        wc_ForceZero(des_key, sizeof(des_key));
#else
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else {
        ret = wc_AesInit(&ctx->aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret != 0) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return wc_error_to_psa_status(ret);
        }

#ifdef WOLFSSL_AES_COUNTER
        if (alg == PSA_ALG_CTR) {
            ret = wc_AesCtrSetKey(&ctx->aes, key_data, (word32)key_data_length,
                                  ctx->iv, AES_ENCRYPTION);
        }
        else
#endif
        if (alg == PSA_ALG_CCM_STAR_NO_TAG || alg == PSA_ALG_OFB ||
            alg == PSA_ALG_CFB) {
            ret = wc_AesSetKey(&ctx->aes, key_data, (word32)key_data_length,
                               ctx->iv, AES_ENCRYPTION);
        }
        else {
            ret = wc_AesSetKey(&ctx->aes, key_data, (word32)key_data_length,
                               ctx->iv, AES_DECRYPTION);
        }
    }
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    if (ret != 0) {
#ifndef NO_DES3
        if (ctx->is_des3) {
            wc_Des3Free(&ctx->des3);
        }
#else
        if (0) {
        }
#endif
        else if (!ctx->is_chacha) {
            wc_AesFree(&ctx->aes);
        }
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
                              const uint8_t *iv,
                              size_t iv_length)
{
    wolfpsa_cipher_ctx_t *ctx = wolfpsa_cipher_get_ctx(operation);
    int ret;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->iv_attempted) {
        return PSA_ERROR_BAD_STATE;
    }
    ctx->iv_attempted = 1;
    if (iv == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->alg != PSA_ALG_CBC_NO_PADDING &&
        ctx->alg != PSA_ALG_CBC_PKCS7 &&
        ctx->alg != PSA_ALG_CTR &&
        ctx->alg != PSA_ALG_CFB &&
        ctx->alg != PSA_ALG_OFB &&
        ctx->alg != PSA_ALG_STREAM_CIPHER &&
        ctx->alg != PSA_ALG_CCM_STAR_NO_TAG) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ctx->alg == PSA_ALG_STREAM_CIPHER) {
#ifdef HAVE_CHACHA
        if (iv_length != WOLFPSA_CHACHA20_IV_BYTES) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ret = wc_Chacha_SetIV(&ctx->chacha, iv, 0);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (ctx->alg == PSA_ALG_CCM_STAR_NO_TAG) {
        uint8_t counter[AES_BLOCK_SIZE];

        if (iv_length != 13) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        counter[0] = 0x01;
        XMEMCPY(counter + 1, iv, 13);
        counter[14] = 0x00;
        counter[15] = 0x01;

        XMEMCPY(ctx->iv, counter, AES_BLOCK_SIZE);
        ret = wc_AesSetIV(&ctx->aes, ctx->iv);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
    }
    else {
        size_t expected_len = wolfpsa_cipher_block_size(ctx->key_type);

        if (iv_length != expected_len) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        XMEMCPY(ctx->iv, iv, expected_len);
        if (ctx->is_des3) {
#ifndef NO_DES3
            ret = wc_Des3_SetIV(&ctx->des3, ctx->iv);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
#endif
        }
        else {
            ret = wc_AesSetIV(&ctx->aes, ctx->iv);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
        }
    }

    ctx->iv_set = 1;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
                                   uint8_t *iv,
                                   size_t iv_size,
                                   size_t *iv_length)
{
    psa_status_t status;
    wolfpsa_cipher_ctx_t *ctx = wolfpsa_cipher_get_ctx(operation);
    size_t expected_len;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->iv_attempted) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->direction != AES_ENCRYPTION) {
        return PSA_ERROR_BAD_STATE;
    }
    if (iv == NULL || iv_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    expected_len = wolfpsa_cipher_iv_length(ctx->alg, ctx->key_type);
    if (expected_len == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (iv_size < expected_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = psa_generate_random(iv, expected_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_cipher_set_iv(operation, iv, expected_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *iv_length = expected_len;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *output,
                              size_t output_size,
                              size_t *output_length)
{
    wolfpsa_cipher_ctx_t *ctx = wolfpsa_cipher_get_ctx(operation);
    int ret = 0;
    size_t output_len = 0;

    if (output_length == NULL) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }
    *output_length = 0;
    if (ctx == NULL) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
    }
    if (input == NULL && input_length > 0) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }
    if (output == NULL && output_size > 0) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }
    if (wolfpsa_check_word32_length(input_length) != PSA_SUCCESS) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }

    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    if (ctx->alg == PSA_ALG_CBC_NO_PADDING) {
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        {
            size_t block_size = ctx->block_size;
            size_t total = ctx->partial_len + input_length;
            size_t blocks = total / block_size;
            size_t full_len = blocks * block_size;
            size_t input_offset = 0;
            size_t output_offset = 0;

            output_len = full_len;
            if (output_size < output_len) {
                return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
            }

            if (blocks == 0) {
                if (input_length > 0) {
                    XMEMCPY(ctx->partial + ctx->partial_len, input, input_length);
                    ctx->partial_len += input_length;
                }
                return PSA_SUCCESS;
            }

            if (ctx->partial_len > 0) {
                size_t needed = block_size - ctx->partial_len;
                uint8_t block[AES_BLOCK_SIZE];

                XMEMCPY(block, ctx->partial, ctx->partial_len);
                XMEMCPY(block + ctx->partial_len, input, needed);

                if (ctx->is_des3) {
#ifndef NO_DES3
                    if (ctx->direction == AES_ENCRYPTION) {
                        ret = wc_Des3_CbcEncrypt(&ctx->des3, output, block,
                                                (word32)block_size);
                    }
                    else {
                        ret = wc_Des3_CbcDecrypt(&ctx->des3, output, block,
                                                (word32)block_size);
                    }
#else
                    return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
                }
                else {
                    if (ctx->direction == AES_ENCRYPTION) {
                        ret = wc_AesCbcEncrypt(&ctx->aes, output, block,
                                               (word32)block_size);
                    }
                    else {
                        ret = wc_AesCbcDecrypt(&ctx->aes, output, block,
                                               (word32)block_size);
                    }
                }
                if (ret != 0) {
                    return wolfpsa_cipher_fail(operation,
                                               wc_error_to_psa_status(ret));
                }
                wc_ForceZero(block, sizeof(block));
                output_offset += block_size;
                input_offset += needed;
                ctx->partial_len = 0;
            }

            if (input_length > input_offset) {
                size_t remaining = input_length - input_offset;
                size_t full_blocks = (remaining / block_size) * block_size;

                if (full_blocks > 0) {
                    if (ctx->is_des3) {
#ifndef NO_DES3
                        if (ctx->direction == AES_ENCRYPTION) {
                            ret = wc_Des3_CbcEncrypt(&ctx->des3,
                                                    output + output_offset,
                                                    input + input_offset,
                                                    (word32)full_blocks);
                        }
                        else {
                            ret = wc_Des3_CbcDecrypt(&ctx->des3,
                                                    output + output_offset,
                                                    input + input_offset,
                                                    (word32)full_blocks);
                        }
#else
                        return wolfpsa_cipher_fail(operation,
                                                   PSA_ERROR_NOT_SUPPORTED);
#endif
                    }
                    else {
                        if (ctx->direction == AES_ENCRYPTION) {
                            ret = wc_AesCbcEncrypt(&ctx->aes,
                                                   output + output_offset,
                                                   input + input_offset,
                                                   (word32)full_blocks);
                        }
                        else {
                            ret = wc_AesCbcDecrypt(&ctx->aes,
                                                   output + output_offset,
                                                   input + input_offset,
                                                   (word32)full_blocks);
                        }
                    }
                    if (ret != 0) {
                        return wolfpsa_cipher_fail(operation,
                                                   wc_error_to_psa_status(ret));
                    }
                    output_offset += full_blocks;
                    input_offset += full_blocks;
                }

                if (input_length > input_offset) {
                    ctx->partial_len = input_length - input_offset;
                    XMEMCPY(ctx->partial, input + input_offset, ctx->partial_len);
                }
            }

            *output_length = output_offset;
            return PSA_SUCCESS;
        }
    }
    else if (ctx->alg == PSA_ALG_CBC_PKCS7) {
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        {
            size_t block_size = ctx->block_size;
            size_t total = ctx->partial_len + input_length;
            size_t input_offset = 0;
            size_t output_offset = 0;

            if (ctx->direction == AES_ENCRYPTION) {
                size_t full_blocks = total / block_size;
                size_t full_len = full_blocks * block_size;

                if (output_size < full_len) {
                    return wolfpsa_cipher_fail(operation,
                                               PSA_ERROR_BUFFER_TOO_SMALL);
                }

                if (full_blocks == 0) {
                    if (input_length > 0) {
                        XMEMCPY(ctx->partial + ctx->partial_len, input, input_length);
                        ctx->partial_len += input_length;
                    }
                    return PSA_SUCCESS;
                }

                if (ctx->partial_len > 0) {
                    size_t needed = block_size - ctx->partial_len;
                    uint8_t block[AES_BLOCK_SIZE];

                    XMEMCPY(block, ctx->partial, ctx->partial_len);
                    XMEMCPY(block + ctx->partial_len, input, needed);

                    if (ctx->is_des3) {
#ifndef NO_DES3
                        ret = wc_Des3_CbcEncrypt(&ctx->des3, output, block,
                                                (word32)block_size);
#else
                        return wolfpsa_cipher_fail(operation,
                                                   PSA_ERROR_NOT_SUPPORTED);
#endif
                    }
                    else {
                        ret = wc_AesCbcEncrypt(&ctx->aes, output, block,
                                               (word32)block_size);
                    }
                    if (ret != 0) {
                        return wolfpsa_cipher_fail(operation,
                                                   wc_error_to_psa_status(ret));
                    }
                    wc_ForceZero(block, sizeof(block));
                    output_offset += block_size;
                    input_offset += needed;
                    ctx->partial_len = 0;
                }

                if (input_length > input_offset) {
                    size_t remaining = input_length - input_offset;
                    size_t full_blocks_len = (remaining / block_size) * block_size;

                    if (full_blocks_len > 0) {
                        if (ctx->is_des3) {
#ifndef NO_DES3
                            ret = wc_Des3_CbcEncrypt(&ctx->des3,
                                                    output + output_offset,
                                                    input + input_offset,
                                                    (word32)full_blocks_len);
#else
                            return wolfpsa_cipher_fail(operation,
                                                       PSA_ERROR_NOT_SUPPORTED);
#endif
                        }
                        else {
                            ret = wc_AesCbcEncrypt(&ctx->aes,
                                                   output + output_offset,
                                                   input + input_offset,
                                                   (word32)full_blocks_len);
                        }
                        if (ret != 0) {
                            return wolfpsa_cipher_fail(operation,
                                                       wc_error_to_psa_status(ret));
                        }
                        output_offset += full_blocks_len;
                        input_offset += full_blocks_len;
                    }

                    if (input_length > input_offset) {
                        ctx->partial_len = input_length - input_offset;
                        XMEMCPY(ctx->partial, input + input_offset, ctx->partial_len);
                    }
                }

                *output_length = output_offset;
                return PSA_SUCCESS;
            }
            else {
                size_t process_len;
                size_t full_blocks_len;

                if (total < block_size) {
                    if (input_length > 0) {
                        XMEMCPY(ctx->partial + ctx->partial_len, input, input_length);
                        ctx->partial_len += input_length;
                    }
                    return PSA_SUCCESS;
                }

                /* Decrypt whole blocks while retaining the final ciphertext block. */
                process_len = ((total - 1U) / block_size) * block_size;
                if (process_len == 0) {
                    XMEMCPY(ctx->partial + ctx->partial_len, input, input_length);
                    ctx->partial_len += input_length;
                    return PSA_SUCCESS;
                }

                if (output_size < process_len) {
                    return wolfpsa_cipher_fail(operation,
                                               PSA_ERROR_BUFFER_TOO_SMALL);
                }

                if (ctx->partial_len > 0) {
                    size_t needed = block_size - ctx->partial_len;
                    uint8_t block[AES_BLOCK_SIZE];

                    XMEMCPY(block, ctx->partial, ctx->partial_len);
                    XMEMCPY(block + ctx->partial_len, input, needed);

                    if (ctx->is_des3) {
#ifndef NO_DES3
                        ret = wc_Des3_CbcDecrypt(&ctx->des3, output, block,
                                                (word32)block_size);
#else
                        return wolfpsa_cipher_fail(operation,
                                                   PSA_ERROR_NOT_SUPPORTED);
#endif
                    }
                    else {
                        ret = wc_AesCbcDecrypt(&ctx->aes, output, block,
                                               (word32)block_size);
                    }
                    if (ret != 0) {
                        return wolfpsa_cipher_fail(operation,
                                                   wc_error_to_psa_status(ret));
                    }
                    output_offset += block_size;
                    input_offset += needed;
                    ctx->partial_len = 0;
                }

                full_blocks_len = process_len - output_offset;
                if (full_blocks_len > 0) {
                    if (ctx->is_des3) {
#ifndef NO_DES3
                        ret = wc_Des3_CbcDecrypt(&ctx->des3,
                                                output + output_offset,
                                                input + input_offset,
                                                (word32)full_blocks_len);
#else
                        return wolfpsa_cipher_fail(operation,
                                                   PSA_ERROR_NOT_SUPPORTED);
#endif
                    }
                    else {
                        ret = wc_AesCbcDecrypt(&ctx->aes,
                                               output + output_offset,
                                               input + input_offset,
                                               (word32)full_blocks_len);
                    }
                    if (ret != 0) {
                        return wolfpsa_cipher_fail(operation,
                                                   wc_error_to_psa_status(ret));
                    }
                    output_offset += full_blocks_len;
                    input_offset += full_blocks_len;
                }

                if (input_length >= input_offset + block_size) {
                    XMEMCPY(ctx->partial, input + input_offset, block_size);
                    ctx->partial_len = block_size;
                }
                else if (input_length > input_offset) {
                    size_t remaining = input_length - input_offset;
                    XMEMCPY(ctx->partial, input + input_offset, remaining);
                    ctx->partial_len = remaining;
                }

                *output_length = output_offset;
                return PSA_SUCCESS;
            }
        }
    }
    else if (ctx->alg == PSA_ALG_CCM_STAR_NO_TAG) {
#ifdef WOLFSSL_AES_COUNTER
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        if (output_size < input_length) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
        }
        if (input_length == 0) {
            return PSA_SUCCESS;
        }
        ret = wc_AesCtrEncrypt(&ctx->aes, output, input,
                               (word32)input_length);
        if (ret != 0) {
            return wolfpsa_cipher_fail(operation, wc_error_to_psa_status(ret));
        }
        *output_length = input_length;
        return PSA_SUCCESS;
#else
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
    }
    else if (ctx->alg == PSA_ALG_ECB_NO_PADDING) {
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_DES_ECB)
        {
            size_t block_size = ctx->block_size;
            size_t total = ctx->partial_len + input_length;
            size_t blocks = total / block_size;
            size_t full_len = blocks * block_size;
            size_t input_offset = 0;
            size_t output_offset = 0;

            output_len = full_len;
            if (output_size < output_len) {
                return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
            }

            if (blocks == 0) {
                if (input_length > 0) {
                    XMEMCPY(ctx->partial + ctx->partial_len, input, input_length);
                    ctx->partial_len += input_length;
                }
                return PSA_SUCCESS;
            }

            if (ctx->partial_len > 0) {
                size_t needed = block_size - ctx->partial_len;
                uint8_t block[AES_BLOCK_SIZE];

                XMEMCPY(block, ctx->partial, ctx->partial_len);
                XMEMCPY(block + ctx->partial_len, input, needed);

                if (ctx->is_des3) {
#if !defined(NO_DES3) && defined(WOLFSSL_DES_ECB)
                    if (ctx->direction == AES_ENCRYPTION) {
                        ret = wc_Des3_EcbEncrypt(&ctx->des3, output, block,
                                                (word32)block_size);
                    }
                    else {
                        ret = wc_Des3_EcbDecrypt(&ctx->des3, output, block,
                                                (word32)block_size);
                    }
#else
                    return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
                }
                else {
#ifdef HAVE_AES_ECB
                    if (ctx->direction == AES_ENCRYPTION) {
                        ret = wc_AesEcbEncrypt(&ctx->aes, output, block,
                                               (word32)block_size);
                    }
                    else {
                        ret = wc_AesEcbDecrypt(&ctx->aes, output, block,
                                               (word32)block_size);
                    }
#else
                    return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
                }
                if (ret != 0) {
                    return wolfpsa_cipher_fail(operation,
                                               wc_error_to_psa_status(ret));
                }
                wc_ForceZero(block, sizeof(block));
                output_offset += block_size;
                input_offset += needed;
                ctx->partial_len = 0;
            }

            if (input_length > input_offset) {
                size_t remaining = input_length - input_offset;
                size_t full_blocks = (remaining / block_size) * block_size;

                if (full_blocks > 0) {
                    if (ctx->is_des3) {
#if !defined(NO_DES3) && defined(WOLFSSL_DES_ECB)
                        if (ctx->direction == AES_ENCRYPTION) {
                            ret = wc_Des3_EcbEncrypt(&ctx->des3,
                                                    output + output_offset,
                                                    input + input_offset,
                                                    (word32)full_blocks);
                        }
                        else {
                            ret = wc_Des3_EcbDecrypt(&ctx->des3,
                                                    output + output_offset,
                                                    input + input_offset,
                                                    (word32)full_blocks);
                        }
#else
                        return wolfpsa_cipher_fail(operation,
                                                   PSA_ERROR_NOT_SUPPORTED);
#endif
                    }
                    else {
#ifdef HAVE_AES_ECB
                        if (ctx->direction == AES_ENCRYPTION) {
                            ret = wc_AesEcbEncrypt(&ctx->aes,
                                                   output + output_offset,
                                                   input + input_offset,
                                                   (word32)full_blocks);
                        }
                        else {
                            ret = wc_AesEcbDecrypt(&ctx->aes,
                                                   output + output_offset,
                                                   input + input_offset,
                                                   (word32)full_blocks);
                        }
#else
                        return wolfpsa_cipher_fail(operation,
                                                   PSA_ERROR_NOT_SUPPORTED);
#endif
                    }
                    if (ret != 0) {
                        return wolfpsa_cipher_fail(operation,
                                                   wc_error_to_psa_status(ret));
                    }
                    output_offset += full_blocks;
                    input_offset += full_blocks;
                }

                if (input_length > input_offset) {
                    ctx->partial_len = input_length - input_offset;
                    XMEMCPY(ctx->partial, input + input_offset, ctx->partial_len);
                }
            }

            *output_length = output_offset;
            return PSA_SUCCESS;
        }
#else
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
    }
    else if (ctx->alg == PSA_ALG_CTR) {
#ifdef WOLFSSL_AES_COUNTER
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        if (output_size < input_length) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
        }
        ret = wc_AesCtrEncrypt(&ctx->aes, output, input,
                               (word32)input_length);
        if (ret != 0) {
            return wolfpsa_cipher_fail(operation, wc_error_to_psa_status(ret));
        }
#else
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
    }
    else if (ctx->alg == PSA_ALG_CFB) {
#ifdef WOLFSSL_AES_CFB
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        if (output_size < input_length) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
        }
        if (ctx->direction == AES_ENCRYPTION) {
            ret = wc_AesCfbEncrypt(&ctx->aes, output, input,
                                   (word32)input_length);
        }
        else {
            ret = wc_AesCfbDecrypt(&ctx->aes, output, input,
                                   (word32)input_length);
        }
        if (ret != 0) {
            return wolfpsa_cipher_fail(operation, wc_error_to_psa_status(ret));
        }
#else
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
    }
    else if (ctx->alg == PSA_ALG_OFB) {
#ifdef WOLFSSL_AES_OFB
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        if (output_size < input_length) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
        }
        if (ctx->direction == AES_ENCRYPTION) {
            ret = wc_AesOfbEncrypt(&ctx->aes, output, input,
                                   (word32)input_length);
        }
        else {
            ret = wc_AesOfbDecrypt(&ctx->aes, output, input,
                                   (word32)input_length);
        }
        if (ret != 0) {
            return wolfpsa_cipher_fail(operation, wc_error_to_psa_status(ret));
        }
#else
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
    }
    else if (ctx->alg == PSA_ALG_STREAM_CIPHER) {
#ifdef HAVE_CHACHA
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        if (output_size < input_length) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
        }
        ret = wc_Chacha_Process(&ctx->chacha, output, input,
                                (word32)input_length);
        if (ret != 0) {
            return wolfpsa_cipher_fail(operation, wc_error_to_psa_status(ret));
        }
#else
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
    }
    else {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
    }

    *output_length = input_length;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
                              uint8_t *output,
                              size_t output_size,
                              size_t *output_length)
{
    wolfpsa_cipher_ctx_t *ctx = wolfpsa_cipher_get_ctx(operation);
    int ret = 0;

    if (operation == NULL || output_length == NULL) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }
    if (ctx == NULL) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
    }

    if (ctx->alg == PSA_ALG_CBC_PKCS7) {
        size_t block_size = ctx->block_size;
        if (!ctx->iv_set) {
            return wolfpsa_cipher_fail(operation, PSA_ERROR_BAD_STATE);
        }
        if (ctx->direction == AES_ENCRYPTION) {
            uint8_t block[AES_BLOCK_SIZE];
            size_t pad_len = block_size - ctx->partial_len;
            psa_status_t status = PSA_SUCCESS;

            if (pad_len == 0) {
                pad_len = block_size;
            }
            if (output_size < block_size) {
                return wolfpsa_cipher_fail(operation, PSA_ERROR_BUFFER_TOO_SMALL);
            }
            if (ctx->partial_len > 0) {
                XMEMCPY(block, ctx->partial, ctx->partial_len);
            }
            XMEMSET(block + ctx->partial_len, (byte)pad_len, pad_len);

            if (ctx->is_des3) {
#ifndef NO_DES3
                ret = wc_Des3_CbcEncrypt(&ctx->des3, output, block,
                                        (word32)block_size);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
                goto cbc_pkcs7_encrypt_done;
#endif
            }
            else {
                ret = wc_AesCbcEncrypt(&ctx->aes, output, block,
                                       (word32)block_size);
            }
            if (ret != 0) {
                status = wc_error_to_psa_status(ret);
                goto cbc_pkcs7_encrypt_done;
            }
            ctx->partial_len = 0;
            *output_length = block_size;

cbc_pkcs7_encrypt_done:
            wc_ForceZero(block, sizeof(block));
            if (status != PSA_SUCCESS) {
                return wolfpsa_cipher_fail(operation, status);
            }
            psa_cipher_abort(operation);
            return PSA_SUCCESS;
        }
        else {
            uint8_t block[AES_BLOCK_SIZE];
            byte invalid;
            size_t pad_len;
            size_t plain_len;
            psa_status_t status = PSA_SUCCESS;

            if (ctx->partial_len != block_size) {
                return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_PADDING);
            }

            if (ctx->is_des3) {
#ifndef NO_DES3
                ret = wc_Des3_CbcDecrypt(&ctx->des3, block, ctx->partial,
                                        (word32)block_size);
#else
                return wolfpsa_cipher_fail(operation, PSA_ERROR_NOT_SUPPORTED);
#endif
            }
            else {
                ret = wc_AesCbcDecrypt(&ctx->aes, block, ctx->partial,
                                       (word32)block_size);
            }
            if (ret != 0) {
                wc_ForceZero(block, sizeof(block));
                return wolfpsa_cipher_fail(operation, wc_error_to_psa_status(ret));
            }

            pad_len = block[block_size - 1];
            invalid = ctMaskEq((int)pad_len, 0);
            invalid |= ctMaskGT((int)pad_len, (int)block_size);
            for (size_t i = 0; i < block_size; i++) {
                volatile byte mask = ctMaskLT((int)i, (int)pad_len);
                invalid |= mask & (byte)(block[block_size - 1 - i] ^
                                         (byte)pad_len);
            }
            if (invalid != 0) {
                status = PSA_ERROR_INVALID_PADDING;
                goto cbc_pkcs7_decrypt_done;
            }

            plain_len = block_size - pad_len;
            if (output_size < plain_len) {
                status = PSA_ERROR_BUFFER_TOO_SMALL;
                goto cbc_pkcs7_decrypt_done;
            }
            if (plain_len > 0) {
                XMEMCPY(output, block, plain_len);
            }
            ctx->partial_len = 0;
            *output_length = plain_len;

cbc_pkcs7_decrypt_done:
            wc_ForceZero(block, sizeof(block));
            if (status != PSA_SUCCESS) {
                return wolfpsa_cipher_fail(operation, status);
            }
            psa_cipher_abort(operation);
            return status;
        }
    }

    if ((ctx->alg == PSA_ALG_CBC_NO_PADDING ||
         ctx->alg == PSA_ALG_ECB_NO_PADDING) &&
        ctx->partial_len != 0) {
        return wolfpsa_cipher_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    }

    *output_length = 0;
    psa_cipher_abort(operation);
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation)
{
    wolfpsa_cipher_ctx_t *ctx = wolfpsa_cipher_get_ctx(operation);

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx != NULL) {
        if (ctx->is_des3) {
#ifndef NO_DES3
            wc_Des3Free(&ctx->des3);
#endif
        }
        else if (!ctx->is_chacha) {
            wc_AesFree(&ctx->aes);
        }
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        operation->opaque = (uintptr_t)NULL;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key,
                               psa_algorithm_t alg,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length)
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t iv[AES_BLOCK_SIZE];
    size_t out_len = 0;
    size_t finish_len = 0;
    size_t iv_len = 0;
    size_t offset = 0;
    wolfpsa_cipher_ctx_t *ctx;

    status = psa_cipher_encrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = wolfpsa_cipher_get_ctx(&operation);
    if (ctx == NULL) {
        psa_cipher_abort(&operation);
        return PSA_ERROR_BAD_STATE;
    }

    iv_len = wolfpsa_cipher_iv_length(alg, ctx->key_type);
    if (iv_len != 0) {
        if (output_size < iv_len) {
            psa_cipher_abort(&operation);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&operation);
            return status;
        }
        XMEMCPY(output, iv, iv_len);
        offset = iv_len;
    }

    status = psa_cipher_update(&operation, input, input_length, output + offset,
                               output_size - offset, &out_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        return status;
    }

    status = psa_cipher_finish(&operation, output + offset + out_len,
                               output_size - offset - out_len, &finish_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        return status;
    }

    psa_cipher_abort(&operation);
    *output_length = offset + out_len + finish_len;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt(psa_key_id_t key,
                               psa_algorithm_t alg,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length)
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t iv[AES_BLOCK_SIZE];
    size_t out_len = 0;
    size_t finish_len = 0;
    size_t iv_len = 0;
    size_t offset = 0;
    wolfpsa_cipher_ctx_t *ctx;

    status = psa_cipher_decrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = wolfpsa_cipher_get_ctx(&operation);
    if (ctx == NULL) {
        psa_cipher_abort(&operation);
        return PSA_ERROR_BAD_STATE;
    }

    iv_len = wolfpsa_cipher_iv_length(alg, ctx->key_type);
    if (iv_len != 0) {
        if (input_length < iv_len) {
            psa_cipher_abort(&operation);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        XMEMCPY(iv, input, iv_len);
        status = psa_cipher_set_iv(&operation, iv, iv_len);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&operation);
            return status;
        }
        offset = iv_len;
    }

    status = psa_cipher_update(&operation, input + offset, input_length - offset,
                               output, output_size, &out_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        return status;
    }

    status = psa_cipher_finish(&operation, output + out_len,
                               output_size - out_len, &finish_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        return status;
    }

    psa_cipher_abort(&operation);
    *output_length = out_len + finish_len;
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
