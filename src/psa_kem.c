/* psa_kem.c
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
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include "psa_pqc_internal.h"
#include "psa_trace.h"
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

/* Validate that an output-key attributes type is acceptable for a KEM shared
 * secret (32 bytes of unstructured key material) and that the requested bit
 * size is compatible (0 = let the import infer; 256 = explicit 32-byte key). */
static psa_status_t wolfpsa_kem_check_output_attributes(
        const psa_key_attributes_t *attributes)
{
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    if (!PSA_KEY_TYPE_IS_UNSTRUCTURED(type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (bits != 0 && bits != (WOLFPSA_MLKEM_SS_SIZE * 8u)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

/* Validate that the requested algorithm is a supported KEM algorithm.
 * Returns:
 *   PSA_SUCCESS               - alg == PSA_ALG_ML_KEM
 *   PSA_ERROR_NOT_SUPPORTED   - alg is a known KEM but not ML-KEM
 *   PSA_ERROR_INVALID_ARGUMENT - alg is not a KEM algorithm at all
 */
static psa_status_t wolfpsa_kem_check_alg(psa_algorithm_t alg)
{
    if (alg == PSA_ALG_ML_KEM) {
        return PSA_SUCCESS;
    }
    if (PSA_ALG_IS_KEY_ENCAPSULATION(alg)) {
        /* Other KEM algorithms (e.g. PSA_ALG_ECIES_SEC1) are not supported. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t psa_encapsulate(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const psa_key_attributes_t *attributes,
                             psa_key_id_t *output_key,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length)
{
    psa_key_attributes_t key_attr;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_key_type_t key_type;
    size_t key_bits;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    psa_status_t status;
    uint8_t ss[WOLFPSA_MLKEM_SS_SIZE];
    /* Staging buffer: ciphertext is written here before the output key is
     * successfully imported, so no partial results escape on failure. */
    uint8_t ct_buf[PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE];
    size_t ct_len = 0;

    wolfpsa_trace("psa_encapsulate(key=%u alg=0x%08x)",
                  (unsigned)key, (unsigned)alg);

    /* --- Argument validation ---
     * A NULL ciphertext pointer is only an error when the caller declared a
     * nonzero capacity; (NULL, 0) must reach the size check below. */
    if (output_key == NULL || ciphertext_length == NULL ||
        attributes == NULL || (ciphertext == NULL && ciphertext_size != 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *output_key = PSA_KEY_ID_NULL;
    *ciphertext_length = 0;

    status = wolfpsa_kem_check_alg(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_kem_check_output_attributes(attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* --- Load the KEM key and check policy --- */
    status = wolfpsa_get_key_data(key, &key_attr, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    key_type  = psa_get_key_type(&key_attr);
    key_bits  = psa_get_key_bits(&key_attr);
    key_usage = psa_get_key_usage_flags(&key_attr);
    key_alg   = psa_get_key_algorithm(&key_attr);

    if (key_type != PSA_KEY_TYPE_ML_KEM_KEY_PAIR &&
        key_type != PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((key_usage & PSA_KEY_USAGE_ENCRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (key_alg != alg && key_alg != PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (key_alg == PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Check caller buffer is large enough before invoking the backend. */
    {
        size_t needed = PSA_ENCAPSULATE_CIPHERTEXT_SIZE(key_type, key_bits, alg);
        if (ciphertext_size < needed) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }

#if defined(WOLFSSL_HAVE_MLKEM)
    /* Encapsulate into the local staging buffer. */
    status = wolfpsa_mlkem_encapsulate(key_bits, key_type,
                                       key_data, key_data_length,
                                       ct_buf, sizeof(ct_buf), &ct_len,
                                       ss);
#else
    status = PSA_ERROR_NOT_SUPPORTED;
    (void)ct_len;
#endif

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (status != PSA_SUCCESS) {
        wc_ForceZero(ss, sizeof(ss));
        return status;
    }

    /* Import the shared secret as the output key. */
    status = psa_import_key(attributes, ss, WOLFPSA_MLKEM_SS_SIZE, output_key);
    wc_ForceZero(ss, sizeof(ss));

    if (status != PSA_SUCCESS) {
        *output_key = PSA_KEY_ID_NULL;
        return status;
    }

    /* Only expose the ciphertext to the caller after the key import succeeded. */
    XMEMCPY(ciphertext, ct_buf, ct_len);
    *ciphertext_length = ct_len;

    return PSA_SUCCESS;
}

psa_status_t psa_decapsulate(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *ciphertext,
                             size_t ciphertext_length,
                             const psa_key_attributes_t *attributes,
                             psa_key_id_t *output_key)
{
    psa_key_attributes_t key_attr;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_key_type_t key_type;
    size_t key_bits;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    psa_status_t status;
    uint8_t ss[WOLFPSA_MLKEM_SS_SIZE];

    wolfpsa_trace("psa_decapsulate(key=%u alg=0x%08x ct_len=%zu)",
                  (unsigned)key, (unsigned)alg, ciphertext_length);

    /* --- Argument validation --- */
    if (output_key == NULL || ciphertext == NULL || attributes == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *output_key = PSA_KEY_ID_NULL;

    status = wolfpsa_kem_check_alg(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_kem_check_output_attributes(attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* --- Load the KEM key and check policy --- */
    status = wolfpsa_get_key_data(key, &key_attr, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    key_type  = psa_get_key_type(&key_attr);
    key_bits  = psa_get_key_bits(&key_attr);
    key_usage = psa_get_key_usage_flags(&key_attr);
    key_alg   = psa_get_key_algorithm(&key_attr);

    /* Decapsulate requires the key pair (private key). */
    if (key_type != PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((key_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (key_alg != alg && key_alg != PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (key_alg == PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Key pair is stored as the 64-byte d||z seed. */
    if (key_data_length != WOLFPSA_MLKEM_SEED_SIZE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(WOLFSSL_HAVE_MLKEM)
    status = wolfpsa_mlkem_decapsulate(key_bits, key_data,
                                       ciphertext, ciphertext_length,
                                       ss);
#else
    (void)key_bits;
    status = PSA_ERROR_NOT_SUPPORTED;
#endif

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (status != PSA_SUCCESS) {
        wc_ForceZero(ss, sizeof(ss));
        return status;
    }

    /* Import the shared secret as the output key. */
    status = psa_import_key(attributes, ss, WOLFPSA_MLKEM_SS_SIZE, output_key);
    wc_ForceZero(ss, sizeof(ss));

    if (status != PSA_SUCCESS) {
        *output_key = PSA_KEY_ID_NULL;
        return status;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
