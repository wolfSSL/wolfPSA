/* psa_ed25519_ed448.c
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

#if defined(WOLFSSL_PSA_ENGINE) && (defined(HAVE_ED25519) || defined(HAVE_ED448))

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif

#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif

#ifdef HAVE_ED25519
/* Sign a hash or short message with an ED25519 private key */
psa_status_t psa_asymmetric_sign_ed25519(psa_key_type_t key_type,
                                        size_t key_bits,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        uint8_t *signature,
                                        size_t signature_size,
                                        size_t *signature_length,
                                        const uint8_t *context,
                                        size_t context_length)
{
    int ret;
    ed25519_key ed_key;
    word32 sig_len32;
    const byte *ctx_ptr;
    byte ctx_len;

    if (alg != PSA_ALG_PURE_EDDSA &&
        alg != PSA_ALG_EDDSA_CTX  &&
        alg != PSA_ALG_ED25519PH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* PSA_ALG_PURE_EDDSA forbids any context */
    if (alg == PSA_ALG_PURE_EDDSA && context_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* context must fit in a byte for all Ed25519 variants */
    if (context_length > 255u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if key type is ED25519 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* HashEdDSA (Ed25519ph) signs the SHA-512 prehash, which is exactly
     * PSA_HASH_LENGTH(PSA_ALG_SHA_512) (64) bytes. */
    if (alg == PSA_ALG_ED25519PH &&
        hash_length != PSA_HASH_LENGTH(PSA_ALG_SHA_512)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ctx_ptr = (context_length > 0u) ? (const byte *)context : NULL;
    ctx_len = (byte)context_length;

    /* Initialize ED25519 key */
    ret = wc_ed25519_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Import the stored private seed and derive the public component. */
    ret = wc_ed25519_import_private_only(key_buffer, (word32)key_buffer_size,
                                         &ed_key);
    if (ret == 0) {
        ret = wc_ed25519_make_public(&ed_key, ed_key.p, ED25519_PUB_KEY_SIZE);
    }
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    sig_len32 = (word32)signature_size;

    if (alg == PSA_ALG_ED25519PH) {
        /* HashEdDSA: sign the prehash with optional context */
        ret = wc_ed25519ph_sign_hash(hash, (word32)hash_length, signature,
                                     &sig_len32, &ed_key, ctx_ptr, ctx_len);
    }
    else {
        /* PURE_EDDSA (Ed25519, no context) or EDDSA_CTX (Ed25519ctx, with
         * optional context): use the _ex variant selecting the right type. */
        byte wc_type = (alg == PSA_ALG_EDDSA_CTX) ? Ed25519ctx : Ed25519;
        ret = wc_ed25519_sign_msg_ex(hash, (word32)hash_length, signature,
                                     &sig_len32, &ed_key, wc_type,
                                     ctx_ptr, ctx_len);
    }

    wc_ed25519_free(&ed_key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *signature_length = (size_t)sig_len32;

    return PSA_SUCCESS;
}

/* Verify a signature of a hash or short message with an ED25519 public key */
psa_status_t psa_asymmetric_verify_ed25519(psa_key_type_t key_type,
                                          size_t key_bits,
                                          const uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          psa_algorithm_t alg,
                                          const uint8_t *hash,
                                          size_t hash_length,
                                          const uint8_t *signature,
                                          size_t signature_length,
                                          const uint8_t *context,
                                          size_t context_length)
{
    int ret;
    ed25519_key ed_key;
    int verify_res = 0;
    const byte *ctx_ptr;
    byte ctx_len;

    if (alg != PSA_ALG_PURE_EDDSA &&
        alg != PSA_ALG_EDDSA_CTX  &&
        alg != PSA_ALG_ED25519PH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* PSA_ALG_PURE_EDDSA forbids any context */
    if (alg == PSA_ALG_PURE_EDDSA && context_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* context must fit in a byte for all Ed25519 variants */
    if (context_length > 255u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if key type is ED25519 */
    if ((key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) &&
         key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) ||
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* HashEdDSA (Ed25519ph) verifies over the SHA-512 prehash, which is
     * exactly PSA_HASH_LENGTH(PSA_ALG_SHA_512) (64) bytes. */
    if (alg == PSA_ALG_ED25519PH &&
        hash_length != PSA_HASH_LENGTH(PSA_ALG_SHA_512)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ctx_ptr = (context_length > 0u) ? (const byte *)context : NULL;
    ctx_len = (byte)context_length;

    /* Initialize ED25519 key */
    ret = wc_ed25519_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Import the key material needed for verification. */
    if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        ret = wc_ed25519_import_private_only(key_buffer, (word32)key_buffer_size,
                                             &ed_key);
        if (ret == 0) {
            ret = wc_ed25519_make_public(&ed_key, ed_key.p,
                                         ED25519_PUB_KEY_SIZE);
        }
    }
    else {
        ret = wc_ed25519_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    }
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    if (alg == PSA_ALG_ED25519PH) {
        /* HashEdDSA: verify the prehash with optional context */
        ret = wc_ed25519ph_verify_hash(signature, (word32)signature_length,
                                       hash, (word32)hash_length,
                                       &verify_res, &ed_key, ctx_ptr, ctx_len);
    }
    else {
        /* PURE_EDDSA (Ed25519, no context) or EDDSA_CTX (Ed25519ctx, with
         * optional context): use the _ex variant selecting the right type. */
        byte wc_type = (alg == PSA_ALG_EDDSA_CTX) ? Ed25519ctx : Ed25519;
        ret = wc_ed25519_verify_msg_ex(signature, (word32)signature_length,
                                       hash, (word32)hash_length,
                                       &verify_res, &ed_key, wc_type,
                                       ctx_ptr, ctx_len);
    }

    wc_ed25519_free(&ed_key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

/* Generate an ED25519 key pair */
psa_status_t psa_asymmetric_generate_key_ed25519(psa_key_type_t key_type,
                                                size_t key_bits,
                                                uint8_t *private_key,
                                                size_t private_key_size,
                                                size_t *private_key_length,
                                                uint8_t *public_key,
                                                size_t public_key_size,
                                                size_t *public_key_length)
{
    int ret;
    ed25519_key ed_key;
    WC_RNG rng;
    word32 priv_len32;
    word32 pub_len32;

    /* Check if key type is ED25519 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize ED25519 key */
    ret = wc_ed25519_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Initialize RNG */
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Generate key pair */
    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed_key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* An offload device may report success while keeping the scalar, which
     * leaves privKeySet clear. wc_ed25519_export_private_only() refuses that,
     * but only as BAD_FUNC_ARG, which maps to PSA_ERROR_INVALID_ARGUMENT and
     * blames the caller for a device fault. Report it the way the ECC path
     * does. The device still holds a key this path cannot reclaim, so an
     * integrator whose backend keeps the scalar has to free the backend slot
     * itself. */
    if (!ed_key.privKeySet) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Export private key */
    priv_len32 = (word32)private_key_size;
    ret = wc_ed25519_export_private_only(&ed_key, private_key, &priv_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Export public key */
    pub_len32 = (word32)public_key_size;
    ret = wc_ed25519_export_public(&ed_key, public_key, &pub_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    wc_FreeRng(&rng);
    wc_ed25519_free(&ed_key);

    *private_key_length = (size_t)priv_len32;
    *public_key_length = (size_t)pub_len32;

    return PSA_SUCCESS;
}

/* Export an ED25519 public key or the public part of an ED25519 key pair */
psa_status_t psa_asymmetric_export_public_key_ed25519(psa_key_type_t key_type,
                                                     size_t key_bits,
                                                     const uint8_t *key_buffer,
                                                     size_t key_buffer_size,
                                                     uint8_t *output,
                                                     size_t output_size,
                                                     size_t *output_length)
{
    int ret;
    ed25519_key ed_key;
    word32 out_len32;

    /* Check if key type is ED25519 */
    if ((key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) &&
         key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) ||
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Same contract as the SECP and Montgomery exporters: a too-small buffer
     * is BUFFER_TOO_SMALL, including the (NULL, 0) probe. Passing NULL on to
     * the backend would surface as INVALID_ARGUMENT instead. */
    if (key_buffer == NULL || output_length == NULL ||
        (output == NULL && output_size != 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (output_size < ED25519_PUB_KEY_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Initialize ED25519 key */
    ret = wc_ed25519_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Import key */
    if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        ret = wc_ed25519_import_private_only(key_buffer, (word32)key_buffer_size,
                                             &ed_key);
        if (ret == 0) {
            ret = wc_ed25519_make_public(&ed_key, ed_key.p,
                                         ED25519_PUB_KEY_SIZE);
        }
    }
    else {
        ret = wc_ed25519_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    }

    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Export public key */
    out_len32 = (word32)output_size;
    ret = wc_ed25519_export_public(&ed_key, output, &out_len32);

    wc_ed25519_free(&ed_key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *output_length = (size_t)out_len32;

    return PSA_SUCCESS;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_ED448
/* Sign a hash or short message with an ED448 private key */
psa_status_t psa_asymmetric_sign_ed448(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      uint8_t *signature,
                                      size_t signature_size,
                                      size_t *signature_length,
                                      const uint8_t *context,
                                      size_t context_length)
{
    int ret;
    ed448_key ed_key;
    word32 sig_len32;
    const byte *ctx_ptr;
    byte ctx_len;

    if (alg != PSA_ALG_PURE_EDDSA &&
        alg != PSA_ALG_EDDSA_CTX  &&
        alg != PSA_ALG_ED448PH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* context must fit in a byte for all Ed448 variants */
    if (context_length > 255u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if key type is ED448 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* HashEdDSA (Ed448ph) signs the 64-byte SHAKE256 prehash
     * (PSA_HASH_LENGTH(PSA_ALG_SHAKE256_512)). */
    if (alg == PSA_ALG_ED448PH && hash_length != 64u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg == PSA_ALG_PURE_EDDSA) {
        /* PureEdDSA is context-free; a non-empty context is rejected
         * (defense-in-depth: the API path enforces this in
         * wolfpsa_check_context()). */
        if (context_length != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ctx_ptr = NULL;
        ctx_len = 0;
    }
    else {
        ctx_ptr = (context_length > 0u) ? (const byte *)context : NULL;
        ctx_len = (byte)context_length;
    }

    /* Initialize ED448 key */
    ret = wc_ed448_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Import the stored private seed and derive the public component. */
    ret = wc_ed448_import_private_only(key_buffer, (word32)key_buffer_size,
                                       &ed_key);
    if (ret == 0) {
        ret = wc_ed448_make_public(&ed_key, ed_key.p, ED448_PUB_KEY_SIZE);
    }
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    sig_len32 = (word32)signature_size;

    if (alg == PSA_ALG_ED448PH) {
        /* HashEdDSA: sign the prehash with optional context */
        ret = wc_ed448ph_sign_hash(hash, (word32)hash_length, signature,
                                   &sig_len32, &ed_key, ctx_ptr, ctx_len);
    }
    else {
        /* PURE_EDDSA and EDDSA_CTX both map to Ed448 PureEdDSA with context
         * (RFC 8032: Ed448 has no separate ctx variant, context is always
         * part of the domain separation string). */
        ret = wc_ed448_sign_msg(hash, (word32)hash_length, signature,
                                &sig_len32, &ed_key, ctx_ptr, ctx_len);
    }

    wc_ed448_free(&ed_key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *signature_length = (size_t)sig_len32;

    return PSA_SUCCESS;
}

/* Verify a signature of a hash or short message with an ED448 public key */
psa_status_t psa_asymmetric_verify_ed448(psa_key_type_t key_type,
                                        size_t key_bits,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        const uint8_t *signature,
                                        size_t signature_length,
                                        const uint8_t *context,
                                        size_t context_length)
{
    int ret;
    ed448_key ed_key;
    int verify_res = 0;
    const byte *ctx_ptr;
    byte ctx_len;

    if (alg != PSA_ALG_PURE_EDDSA &&
        alg != PSA_ALG_EDDSA_CTX  &&
        alg != PSA_ALG_ED448PH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* context must fit in a byte for all Ed448 variants */
    if (context_length > 255u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if key type is ED448 */
    if ((key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) &&
         key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) ||
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* HashEdDSA (Ed448ph) verifies over the 64-byte SHAKE256 prehash
     * (PSA_HASH_LENGTH(PSA_ALG_SHAKE256_512)). */
    if (alg == PSA_ALG_ED448PH && hash_length != 64u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg == PSA_ALG_PURE_EDDSA) {
        /* PureEdDSA is context-free; a non-empty context is rejected
         * (defense-in-depth: the API path enforces this in
         * wolfpsa_check_context()). */
        if (context_length != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ctx_ptr = NULL;
        ctx_len = 0;
    }
    else {
        ctx_ptr = (context_length > 0u) ? (const byte *)context : NULL;
        ctx_len = (byte)context_length;
    }

    /* Initialize ED448 key */
    ret = wc_ed448_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Import the key material needed for verification. */
    if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        ret = wc_ed448_import_private_only(key_buffer, (word32)key_buffer_size,
                                           &ed_key);
        if (ret == 0) {
            ret = wc_ed448_make_public(&ed_key, ed_key.p, ED448_PUB_KEY_SIZE);
        }
    }
    else {
        ret = wc_ed448_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    }
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    if (alg == PSA_ALG_ED448PH) {
        /* HashEdDSA: verify the prehash with optional context */
        ret = wc_ed448ph_verify_hash(signature, (word32)signature_length,
                                     hash, (word32)hash_length,
                                     &verify_res, &ed_key, ctx_ptr, ctx_len);
    }
    else {
        /* PURE_EDDSA and EDDSA_CTX both map to Ed448 PureEdDSA with context. */
        ret = wc_ed448_verify_msg(signature, (word32)signature_length,
                                  hash, (word32)hash_length,
                                  &verify_res, &ed_key, ctx_ptr, ctx_len);
    }

    wc_ed448_free(&ed_key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

/* Generate an ED448 key pair */
psa_status_t psa_asymmetric_generate_key_ed448(psa_key_type_t key_type,
                                              size_t key_bits,
                                              uint8_t *private_key,
                                              size_t private_key_size,
                                              size_t *private_key_length,
                                              uint8_t *public_key,
                                              size_t public_key_size,
                                              size_t *public_key_length)
{
    int ret;
    ed448_key ed_key;
    WC_RNG rng;
    word32 priv_len32;
    word32 pub_len32;

    /* Check if key type is ED448 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize ED448 key */
    ret = wc_ed448_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Initialize RNG */
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Generate key pair */
    ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed_key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Deliberately no privKeySet check here, unlike the Ed25519 path above.
     * ed448.c dispatches Sign and Verify only, so wc_ed448_make_key() has no
     * crypto callback to offload to and always sets privKeySet on success.
     * Passing a devId to wc_ed448_init_ex() does not change that: an
     * initializer that accepts a devId is not the same as a dispatch. Add the
     * check if wolfCrypt ever gains a WC_PK_TYPE_ED448_KEYGEN. */

    /* Export private key */
    priv_len32 = (word32)private_key_size;
    ret = wc_ed448_export_private_only(&ed_key, private_key, &priv_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Export public key */
    pub_len32 = (word32)public_key_size;
    ret = wc_ed448_export_public(&ed_key, public_key, &pub_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    wc_FreeRng(&rng);
    wc_ed448_free(&ed_key);

    *private_key_length = (size_t)priv_len32;
    *public_key_length = (size_t)pub_len32;

    return PSA_SUCCESS;
}

/* Export an ED448 public key or the public part of an ED448 key pair */
psa_status_t psa_asymmetric_export_public_key_ed448(psa_key_type_t key_type,
                                                   size_t key_bits,
                                                   const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t *output,
                                                   size_t output_size,
                                                   size_t *output_length)
{
    int ret;
    ed448_key ed_key;
    word32 out_len32;

    /* Check if key type is ED448 */
    if ((key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) &&
         key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) ||
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Same contract as the SECP and Montgomery exporters: a too-small buffer
     * is BUFFER_TOO_SMALL, including the (NULL, 0) probe. Passing NULL on to
     * the backend would surface as INVALID_ARGUMENT instead. */
    if (key_buffer == NULL || output_length == NULL ||
        (output == NULL && output_size != 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (output_size < ED448_PUB_KEY_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Initialize ED448 key */
    ret = wc_ed448_init_ex(&ed_key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Import key */
    if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        ret = wc_ed448_import_private_only(key_buffer, (word32)key_buffer_size,
                                           &ed_key);
        if (ret == 0) {
            ret = wc_ed448_make_public(&ed_key, ed_key.p, ED448_PUB_KEY_SIZE);
        }
    }
    else {
        ret = wc_ed448_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    }

    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }

    /* Export public key */
    out_len32 = (word32)output_size;
    ret = wc_ed448_export_public(&ed_key, output, &out_len32);

    wc_ed448_free(&ed_key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *output_length = (size_t)out_len32;

    return PSA_SUCCESS;
}
#endif /* HAVE_ED448 */

#endif /* WOLFSSL_PSA_ENGINE && (HAVE_ED25519 || HAVE_ED448) */
