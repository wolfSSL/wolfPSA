/* psa_asymmetric_api.c
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
#include "psa_trace.h"
#include "psa_pqc_internal.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/ecc.h>

extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);

#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT) && \
    defined(HAVE_CURVE25519_SHARED_SECRET)
psa_status_t psa_asymmetric_key_agreement_x25519(
    const uint8_t *private_key,
    size_t private_key_length,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);
#endif
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
    defined(HAVE_CURVE448_SHARED_SECRET)
psa_status_t psa_asymmetric_key_agreement_x448(
    const uint8_t *private_key,
    size_t private_key_length,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);
#endif

psa_status_t psa_asymmetric_sign_rsa(psa_key_type_t key_type,
                                    size_t key_bits,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length);
psa_status_t psa_asymmetric_verify_rsa(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length);
psa_status_t psa_asymmetric_encrypt_rsa(psa_key_type_t key_type,
                                       size_t key_bits,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *input,
                                       size_t input_length,
                                       const uint8_t *salt,
                                       size_t salt_length,
                                       uint8_t *output,
                                       size_t output_size,
                                       size_t *output_length);
psa_status_t psa_asymmetric_decrypt_rsa(psa_key_type_t key_type,
                                       size_t key_bits,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *input,
                                       size_t input_length,
                                       const uint8_t *salt,
                                       size_t salt_length,
                                       uint8_t *output,
                                       size_t output_size,
                                       size_t *output_length);
psa_status_t psa_asymmetric_sign_ecc(psa_key_type_t key_type,
                                    size_t key_bits,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length);
psa_status_t psa_asymmetric_verify_ecc(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length);
#ifdef HAVE_ED25519
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
                                        size_t context_length);
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
                                          size_t context_length);
#endif
#ifdef HAVE_ED448
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
                                      size_t context_length);
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
                                        size_t context_length);
#endif

/* Return non-zero if a key whose permitted-algorithm policy is the
 * key-agreement algorithm 'key_alg' may be used for the requested
 * key-agreement algorithm 'alg'. The base algorithm (e.g. ECDH) must match and
 * the embedded KDF must match exactly, except that a raw key-agreement policy
 * (no KDF) is the most permissive form and therefore permits any KDF. This
 * keeps the KDF embedded in the policy as a real domain-separation barrier:
 * a key restricted to e.g. ECDH+HKDF must not be usable for raw agreement or
 * for a different KDF. */
static int wolfpsa_key_agreement_alg_permitted(psa_algorithm_t key_alg,
                                               psa_algorithm_t alg)
{
    if (PSA_ALG_KEY_AGREEMENT_GET_BASE(key_alg) !=
        PSA_ALG_KEY_AGREEMENT_GET_BASE(alg)) {
        return 0;
    }
    if (PSA_ALG_IS_RAW_KEY_AGREEMENT(key_alg)) {
        return 1;
    }
    return PSA_ALG_KEY_AGREEMENT_GET_KDF(key_alg) ==
           PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
}

/* Return non-zero if a key whose permitted-algorithm policy is 'key_alg' may be
 * used for the requested signature/encryption algorithm 'alg' under the given
 * 'requested_usage'. The common case is exact equality. In addition:
 *  - A hash-and-sign policy whose hash component is PSA_ALG_ANY_HASH (e.g.
 *    PSA_ALG_ECDSA(PSA_ALG_ANY_HASH) or PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH))
 *    authorizes any concrete hash-and-sign algorithm of the same base family,
 *    as required by the PSA Crypto API.
 *  - A HashML-DSA/DeterministicHashML-DSA policy with PSA_ALG_ANY_HASH permits
 *    any concrete hash variant of the same family.
 *  - For VERIFY usages, PSA_ALG_ECDSA(h) in the policy permits
 *    PSA_ALG_DETERMINISTIC_ECDSA(h) requests and vice versa (same hash), per
 *    PSA 1.4 verify-equivalence. */
static int wolfpsa_sign_alg_permitted(psa_algorithm_t key_alg,
                                      psa_algorithm_t alg,
                                      psa_key_usage_t requested_usage)
{
    if (key_alg == alg) {
        return 1;
    }
    /* Standard PSA_ALG_ANY_HASH wildcard for hash-and-sign families */
    if (PSA_ALG_IS_SIGN_HASH(alg) &&
        PSA_ALG_SIGN_GET_HASH(key_alg) == PSA_ALG_ANY_HASH) {
        return (PSA_ALG_SIGN_GET_HASH(alg) != PSA_ALG_ANY_HASH) &&
               ((key_alg & ~PSA_ALG_HASH_MASK) == (alg & ~PSA_ALG_HASH_MASK));
    }
    /* PSA_ALG_ANY_HASH wildcard for HashML-DSA and DeterministicHashML-DSA */
    if (PSA_ALG_IS_HASH_ML_DSA(alg) &&
        PSA_ALG_IS_HASH_ML_DSA(key_alg) &&
        PSA_ALG_GET_HASH(key_alg) == PSA_ALG_ANY_HASH) {
        return (PSA_ALG_GET_HASH(alg) != PSA_ALG_ANY_HASH) &&
               ((key_alg & ~0x000001ffU) == (alg & ~0x000001ffU));
    }
    if (PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg) &&
        PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(key_alg) &&
        PSA_ALG_GET_HASH(key_alg) == PSA_ALG_ANY_HASH) {
        return (PSA_ALG_GET_HASH(alg) != PSA_ALG_ANY_HASH) &&
               ((key_alg & ~0x000000ffU) == (alg & ~0x000000ffU));
    }
    /* PSA 1.4 ECDSA verify-equivalence: for verify usages, ECDSA and
     * DETERMINISTIC_ECDSA with the same hash are interchangeable. */
    if ((requested_usage & (PSA_KEY_USAGE_VERIFY_HASH |
                            PSA_KEY_USAGE_VERIFY_MESSAGE)) != 0) {
        if (PSA_ALG_IS_ECDSA(alg) && PSA_ALG_IS_ECDSA(key_alg)) {
            /* Same hash, different determinism bit */
            if ((PSA_ALG_GET_HASH(alg) == PSA_ALG_GET_HASH(key_alg)) &&
                (PSA_ALG_GET_HASH(alg) != PSA_ALG_NONE)) {
                return 1;
            }
        }
    }
    return 0;
}

static psa_status_t wolfpsa_asymmetric_check_key(psa_key_id_t key,
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
    if (PSA_ALG_IS_KEY_AGREEMENT(alg) && PSA_ALG_IS_KEY_AGREEMENT(key_alg)) {
        if (!wolfpsa_key_agreement_alg_permitted(key_alg, alg)) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else if (!wolfpsa_sign_alg_permitted(key_alg, alg, usage)) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    return PSA_SUCCESS;
}

/* Validate context parameter against algorithm/key constraints.
 * context_length > 255 is always rejected (RFC 8032 / FIPS 204 limit).
 * A non-empty context is only permitted for:
 *   PSA_ALG_EDDSA_CTX, PSA_ALG_ED25519PH, PSA_ALG_ED448PH,
 *   PSA_ALG_PURE_EDDSA when the key is Ed448 (bits==448),
 *   PSA_ALG_IS_ML_DSA / PSA_ALG_IS_HASH_ML_DSA /
 *     PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA families.
 * All other algorithms with context_length != 0 return
 * PSA_ERROR_INVALID_ARGUMENT. */
static psa_status_t wolfpsa_check_context(psa_algorithm_t alg,
                                          psa_key_type_t key_type,
                                          size_t key_bits,
                                          const uint8_t *context,
                                          size_t context_length)
{
    (void)context;

    if (context_length > 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (context_length == 0) {
        return PSA_SUCCESS;
    }
    /* Non-empty context: check permitted algorithms */
    if (alg == PSA_ALG_EDDSA_CTX ||
        alg == PSA_ALG_ED25519PH  ||
        alg == PSA_ALG_ED448PH) {
        return PSA_SUCCESS;
    }
    if (alg == PSA_ALG_PURE_EDDSA) {
        /* Ed448 pure EdDSA accepts a context per RFC 8032 */
        if ((key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
             key_type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) &&
            key_bits == 448) {
            return PSA_SUCCESS;
        }
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#if defined(WOLFSSL_HAVE_MLDSA)
    if (PSA_ALG_IS_ML_DSA(alg) ||
        PSA_ALG_IS_HASH_ML_DSA(alg) ||
        PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg)) {
        return PSA_SUCCESS;
    }
#endif
    return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   const uint8_t *salt,
                                   size_t salt_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_ENCRYPT, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        if (output == NULL) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = psa_asymmetric_encrypt_rsa(attributes.type, attributes.bits,
                                            key_data, key_data_length,
                                            alg, input, input_length,
                                            salt, salt_length,
                                            output, output_size, output_length);
    }
    else {
        status = PSA_KEY_TYPE_IS_ASYMMETRIC(attributes.type) ?
            PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   const uint8_t *salt,
                                   size_t salt_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_DECRYPT, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        if (output == NULL) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = psa_asymmetric_decrypt_rsa(attributes.type, attributes.bits,
                                            key_data, key_data_length,
                                            alg, input, input_length,
                                            salt, salt_length,
                                            output, output_size, output_length);
    }
    else {
        status = PSA_KEY_TYPE_IS_ASYMMETRIC(attributes.type) ?
            PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

/* Internal worker: sign a pre-computed hash, with optional context. */
static psa_status_t wolfpsa_sign_hash_worker(psa_key_id_t key,
                                             psa_algorithm_t alg,
                                             const uint8_t *hash,
                                             size_t hash_length,
                                             const uint8_t *context,
                                             size_t context_length,
                                             uint8_t *signature,
                                             size_t signature_size,
                                             size_t *signature_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (hash == NULL || signature == NULL || signature_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_SIGN_HASH, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_check_context(alg, attributes.type, attributes.bits,
                                   context, context_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }

#if defined(WOLFSSL_HAVE_MLDSA)
    if (PSA_KEY_TYPE_IS_ML_DSA(attributes.type)) {
        /* Pure ML-DSA (sign_hash is not applicable for pure ML-DSA) */
        if (PSA_ALG_IS_ML_DSA(alg)) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        /* HashML-DSA variants: pass pre-computed hash directly */
        if (PSA_ALG_IS_HASH_ML_DSA(alg) ||
            PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg)) {
            if (attributes.type != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            status = wolfpsa_mldsa_sign(attributes.bits,
                                        key_data, key_data_length,
                                        alg, context, context_length,
                                        hash, hash_length, /*input_is_hash*/1,
                                        signature, signature_size,
                                        signature_length);
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return status;
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_LMS)
    if (attributes.type == PSA_KEY_TYPE_LMS_PUBLIC_KEY ||
        attributes.type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif
#if defined(WOLFSSL_HAVE_XMSS)
    if (attributes.type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY ||
        attributes.type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_sign_rsa(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_sign_ed25519(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_size,
                                                 signature_length,
                                                 context, context_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_sign_ed448(attributes.type, attributes.bits,
                                               key_data, key_data_length,
                                               alg, hash, hash_length,
                                               signature, signature_size,
                                               signature_length,
                                               context, context_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_sign_ecc(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

/* Internal worker: verify a signature over a pre-computed hash, with optional
 * context. */
static psa_status_t wolfpsa_verify_hash_worker(psa_key_id_t key,
                                               psa_algorithm_t alg,
                                               const uint8_t *hash,
                                               size_t hash_length,
                                               const uint8_t *context,
                                               size_t context_length,
                                               const uint8_t *signature,
                                               size_t signature_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (hash == NULL || signature == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_VERIFY_HASH, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_check_context(alg, attributes.type, attributes.bits,
                                   context, context_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }

#if defined(WOLFSSL_HAVE_MLDSA)
    if (PSA_KEY_TYPE_IS_ML_DSA(attributes.type)) {
        /* Pure ML-DSA (verify_hash is not applicable for pure ML-DSA) */
        if (PSA_ALG_IS_ML_DSA(alg)) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        /* HashML-DSA variants: pass pre-computed hash directly */
        if (PSA_ALG_IS_HASH_ML_DSA(alg) ||
            PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg)) {
            status = wolfpsa_mldsa_verify(attributes.bits, attributes.type,
                                          key_data, key_data_length,
                                          alg, context, context_length,
                                          hash, hash_length, /*input_is_hash*/1,
                                          signature, signature_length);
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return status;
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_LMS)
    if (attributes.type == PSA_KEY_TYPE_LMS_PUBLIC_KEY ||
        attributes.type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif
#if defined(WOLFSSL_HAVE_XMSS)
    if (attributes.type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY ||
        attributes.type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_verify_rsa(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
             attributes.type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_verify_ed25519(attributes.type, attributes.bits,
                                                   key_data, key_data_length,
                                                   alg, hash, hash_length,
                                                   signature, signature_length,
                                                   context, context_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_verify_ed448(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_length,
                                                 context, context_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_verify_ecc(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t *hash,
                           size_t hash_length,
                           uint8_t *signature,
                           size_t signature_size,
                           size_t *signature_length)
{
    wolfpsa_trace("psa_sign_hash(key=%u alg=0x%08x hash_len=%zu)",
                  (unsigned)key, (unsigned)alg, hash_length);
    return wolfpsa_sign_hash_worker(key, alg, hash, hash_length,
                                    NULL, 0,
                                    signature, signature_size,
                                    signature_length);
}

psa_status_t psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *hash,
                             size_t hash_length,
                             const uint8_t *signature,
                             size_t signature_length)
{
    wolfpsa_trace("psa_verify_hash(key=%u alg=0x%08x hash_len=%zu sig_len=%zu)",
                  (unsigned)key, (unsigned)alg, hash_length, signature_length);
    return wolfpsa_verify_hash_worker(key, alg, hash, hash_length,
                                      NULL, 0,
                                      signature, signature_length);
}

psa_status_t psa_sign_hash_with_context(psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        const uint8_t *context,
                                        size_t context_length,
                                        uint8_t *signature,
                                        size_t signature_size,
                                        size_t *signature_length)
{
    wolfpsa_trace("psa_sign_hash_with_context(key=%u alg=0x%08x hash_len=%zu ctx_len=%zu)",
                  (unsigned)key, (unsigned)alg, hash_length, context_length);
    return wolfpsa_sign_hash_worker(key, alg, hash, hash_length,
                                    context, context_length,
                                    signature, signature_size,
                                    signature_length);
}

psa_status_t psa_verify_hash_with_context(psa_key_id_t key,
                                          psa_algorithm_t alg,
                                          const uint8_t *hash,
                                          size_t hash_length,
                                          const uint8_t *context,
                                          size_t context_length,
                                          const uint8_t *signature,
                                          size_t signature_length)
{
    wolfpsa_trace("psa_verify_hash_with_context(key=%u alg=0x%08x hash_len=%zu ctx_len=%zu)",
                  (unsigned)key, (unsigned)alg, hash_length, context_length);
    return wolfpsa_verify_hash_worker(key, alg, hash, hash_length,
                                      context, context_length,
                                      signature, signature_length);
}

/* Internal worker: sign a message (hash-then-sign or pure EdDSA/ML-DSA),
 * with optional context. */
static psa_status_t wolfpsa_sign_message_worker(psa_key_id_t key,
                                                psa_algorithm_t alg,
                                                const uint8_t *input,
                                                size_t input_length,
                                                const uint8_t *context,
                                                size_t context_length,
                                                uint8_t *signature,
                                                size_t signature_size,
                                                size_t *signature_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_algorithm_t hash_alg;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t hash_length = 0;
    psa_status_t status;

    if (input == NULL || signature == NULL || signature_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_SIGN_MESSAGE, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_check_context(alg, attributes.type, attributes.bits,
                                   context, context_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }

#if defined(WOLFSSL_HAVE_MLDSA)
    if (PSA_KEY_TYPE_IS_ML_DSA(attributes.type)) {
        if (!PSA_ALG_IS_ML_DSA(alg) &&
            !PSA_ALG_IS_HASH_ML_DSA(alg) &&
            !PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg)) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (attributes.type != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (PSA_ALG_IS_ML_DSA(alg)) {
            /* Pure ML-DSA: sign the raw message */
            status = wolfpsa_mldsa_sign(attributes.bits,
                                        key_data, key_data_length,
                                        alg, context, context_length,
                                        input, input_length, /*input_is_hash*/0,
                                        signature, signature_size,
                                        signature_length);
        }
        else {
            /* HashML-DSA: pre-hash the message then pass digest */
            uint8_t mldsa_hash[PSA_HASH_MAX_SIZE];
            size_t mldsa_hash_length = 0;

            hash_alg = PSA_ALG_GET_HASH(alg);
            status = psa_hash_compute(hash_alg, input, input_length,
                                      mldsa_hash, sizeof(mldsa_hash),
                                      &mldsa_hash_length);
            if (status == PSA_SUCCESS) {
                status = wolfpsa_mldsa_sign(attributes.bits,
                                            key_data, key_data_length,
                                            alg, context, context_length,
                                            mldsa_hash, mldsa_hash_length,
                                            /*input_is_hash*/1,
                                            signature, signature_size,
                                            signature_length);
            }
            wc_ForceZero(mldsa_hash, sizeof(mldsa_hash));
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_LMS)
    if (attributes.type == PSA_KEY_TYPE_LMS_PUBLIC_KEY ||
        attributes.type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif
#if defined(WOLFSSL_HAVE_XMSS)
    if (attributes.type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY ||
        attributes.type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    /* For pure EdDSA (PSA_ALG_PURE_EDDSA and PSA_ALG_EDDSA_CTX), bypass
     * the pre-hash step and pass the raw message directly to the backend. */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if ((alg == PSA_ALG_PURE_EDDSA || alg == PSA_ALG_EDDSA_CTX) &&
        attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_sign_ed25519(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, input, input_length,
                                                 signature, signature_size,
                                                 signature_length,
                                                 context, context_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_sign_ed448(attributes.type, attributes.bits,
                                               key_data, key_data_length,
                                               alg, input, input_length,
                                               signature, signature_size,
                                               signature_length,
                                               context, context_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
#endif /* HAVE_ED25519 || HAVE_ED448 */

    if (alg == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
        hash_alg = 0;
        hash_length = input_length;
        if (hash_length > sizeof(hash)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        XMEMCPY(hash, input, hash_length);
    }
    else {
        hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
        if (hash_alg == 0) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }

        status = psa_hash_compute(hash_alg, input, input_length,
                                  hash, sizeof(hash), &hash_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_sign_rsa(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_sign_ed25519(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_size,
                                                 signature_length,
                                                 context, context_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_sign_ed448(attributes.type, attributes.bits,
                                               key_data, key_data_length,
                                               alg, hash, hash_length,
                                               signature, signature_size,
                                               signature_length,
                                               context, context_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_sign_ecc(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

cleanup:
    wc_ForceZero(hash, sizeof(hash));
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

/* Internal worker: verify a signature over a message, with optional context. */
static psa_status_t wolfpsa_verify_message_worker(psa_key_id_t key,
                                                  psa_algorithm_t alg,
                                                  const uint8_t *input,
                                                  size_t input_length,
                                                  const uint8_t *context,
                                                  size_t context_length,
                                                  const uint8_t *signature,
                                                  size_t signature_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_algorithm_t hash_alg;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t hash_length = 0;
    psa_status_t status;

    if (input == NULL || signature == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_VERIFY_MESSAGE, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_check_context(alg, attributes.type, attributes.bits,
                                   context, context_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }

#if defined(WOLFSSL_HAVE_MLDSA)
    if (PSA_KEY_TYPE_IS_ML_DSA(attributes.type)) {
        if (!PSA_ALG_IS_ML_DSA(alg) &&
            !PSA_ALG_IS_HASH_ML_DSA(alg) &&
            !PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg)) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (PSA_ALG_IS_ML_DSA(alg)) {
            /* Pure ML-DSA: verify the raw message */
            status = wolfpsa_mldsa_verify(attributes.bits, attributes.type,
                                          key_data, key_data_length,
                                          alg, context, context_length,
                                          input, input_length, /*input_is_hash*/0,
                                          signature, signature_length);
        }
        else {
            /* HashML-DSA: pre-hash the message then pass digest */
            uint8_t mldsa_hash[PSA_HASH_MAX_SIZE];
            size_t mldsa_hash_length = 0;

            hash_alg = PSA_ALG_GET_HASH(alg);
            status = psa_hash_compute(hash_alg, input, input_length,
                                      mldsa_hash, sizeof(mldsa_hash),
                                      &mldsa_hash_length);
            if (status == PSA_SUCCESS) {
                status = wolfpsa_mldsa_verify(attributes.bits, attributes.type,
                                              key_data, key_data_length,
                                              alg, context, context_length,
                                              mldsa_hash, mldsa_hash_length,
                                              /*input_is_hash*/1,
                                              signature, signature_length);
            }
            wc_ForceZero(mldsa_hash, sizeof(mldsa_hash));
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_LMS)
    if (attributes.type == PSA_KEY_TYPE_LMS_PUBLIC_KEY) {
        if (alg != PSA_ALG_LMS) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wolfpsa_lms_verify(key_data, key_data_length,
                                    input, input_length,
                                    signature, signature_length);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
    if (attributes.type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        if (alg != PSA_ALG_HSS) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wolfpsa_lms_verify(key_data, key_data_length,
                                    input, input_length,
                                    signature, signature_length);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
#endif /* WOLFSSL_HAVE_LMS */

#if defined(WOLFSSL_HAVE_XMSS)
    if (attributes.type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY) {
        if (alg != PSA_ALG_XMSS) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wolfpsa_xmss_verify(key_data, key_data_length,
                                     input, input_length,
                                     signature, signature_length);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
    if (attributes.type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        if (alg != PSA_ALG_XMSS_MT) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wolfpsa_xmss_verify(key_data, key_data_length,
                                     input, input_length,
                                     signature, signature_length);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
#endif /* WOLFSSL_HAVE_XMSS */

    /* For pure EdDSA (PSA_ALG_PURE_EDDSA and PSA_ALG_EDDSA_CTX), bypass
     * the pre-hash step and pass the raw message directly to the backend. */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if ((alg == PSA_ALG_PURE_EDDSA || alg == PSA_ALG_EDDSA_CTX) &&
        (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
         attributes.type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS))) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_verify_ed25519(attributes.type, attributes.bits,
                                                   key_data, key_data_length,
                                                   alg, input, input_length,
                                                   signature, signature_length,
                                                   context, context_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_verify_ed448(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, input, input_length,
                                                 signature, signature_length,
                                                 context, context_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }
#endif /* HAVE_ED25519 || HAVE_ED448 */

    if (alg == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
        hash_alg = 0;
        hash_length = input_length;
        if (hash_length > sizeof(hash)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        XMEMCPY(hash, input, hash_length);
    }
    else {
        hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
        if (hash_alg == 0) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }

        status = psa_hash_compute(hash_alg, input, input_length,
                                  hash, sizeof(hash), &hash_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_verify_rsa(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) ||
             attributes.type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_verify_ed25519(attributes.type, attributes.bits,
                                                   key_data, key_data_length,
                                                   alg, hash, hash_length,
                                                   signature, signature_length,
                                                   context, context_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_verify_ed448(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_length,
                                                 context, context_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_verify_ecc(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

cleanup:
    wc_ForceZero(hash, sizeof(hash));
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_sign_message(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *signature,
                              size_t signature_size,
                              size_t *signature_length)
{
    return wolfpsa_sign_message_worker(key, alg, input, input_length,
                                       NULL, 0,
                                       signature, signature_size,
                                       signature_length);
}

psa_status_t psa_verify_message(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                const uint8_t *signature,
                                size_t signature_length)
{
    return wolfpsa_verify_message_worker(key, alg, input, input_length,
                                         NULL, 0,
                                         signature, signature_length);
}

psa_status_t psa_sign_message_with_context(psa_key_id_t key,
                                           psa_algorithm_t alg,
                                           const uint8_t *input,
                                           size_t input_length,
                                           const uint8_t *context,
                                           size_t context_length,
                                           uint8_t *signature,
                                           size_t signature_size,
                                           size_t *signature_length)
{
    wolfpsa_trace("psa_sign_message_with_context(key=%u alg=0x%08x in_len=%zu ctx_len=%zu)",
                  (unsigned)key, (unsigned)alg, input_length, context_length);
    return wolfpsa_sign_message_worker(key, alg, input, input_length,
                                       context, context_length,
                                       signature, signature_size,
                                       signature_length);
}

psa_status_t psa_verify_message_with_context(psa_key_id_t key,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             const uint8_t *context,
                                             size_t context_length,
                                             const uint8_t *signature,
                                             size_t signature_length)
{
    wolfpsa_trace("psa_verify_message_with_context(key=%u alg=0x%08x in_len=%zu ctx_len=%zu)",
                  (unsigned)key, (unsigned)alg, input_length, context_length);
    return wolfpsa_verify_message_worker(key, alg, input, input_length,
                                         context, context_length,
                                         signature, signature_length);
}

/* Compute the raw ECDH shared secret after verifying that the private key's
 * policy permits the full key-agreement algorithm 'alg'. 'alg' is the complete
 * key-agreement algorithm requested by the caller (raw PSA_ALG_ECDH, or a
 * combined PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, kdf)) so that the KDF embedded
 * in the policy is enforced, not just the base algorithm. Shared by
 * psa_raw_key_agreement(), psa_key_agreement() and
 * psa_key_derivation_key_agreement(). */
psa_status_t wolfpsa_key_agreement_secret(psa_algorithm_t alg,
                                          psa_key_id_t private_key,
                                          const uint8_t *peer_key,
                                          size_t peer_key_length,
                                          uint8_t *output,
                                          size_t output_size,
                                          size_t *output_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
#ifdef HAVE_ECC
    int ret;
    ecc_key priv;
    ecc_key pub;
    int curve_id;
    word32 out_len;
#endif

    if (PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) != PSA_ALG_ECDH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = wolfpsa_asymmetric_check_key(private_key, PSA_KEY_USAGE_DERIVE, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes.type)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_data_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(peer_key_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_ECC_GET_FAMILY(attributes.type) ==
        PSA_ECC_FAMILY_MONTGOMERY) {
        if (attributes.bits == 255) {
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT) && \
    defined(HAVE_CURVE25519_SHARED_SECRET)
            status = psa_asymmetric_key_agreement_x25519(
                key_data, key_data_length, peer_key, peer_key_length, output,
                output_size, output_length);
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif
        }
        else if (attributes.bits == 448) {
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
    defined(HAVE_CURVE448_SHARED_SECRET)
            status = psa_asymmetric_key_agreement_x448(
                key_data, key_data_length, peer_key, peer_key_length, output,
                output_size, output_length);
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif
        }
        else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return status;
    }

#ifdef HAVE_ECC
    curve_id = wc_psa_get_ecc_curve_id(attributes.type, attributes.bits);
    if (curve_id == ECC_CURVE_INVALID) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_SUPPORTED;
    }

    {
        size_t expected_secret_len;

        expected_secret_len = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(attributes.type,
                                                                attributes.bits);
        if (expected_secret_len == 0) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (output_size < expected_secret_len) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }

    if (peer_key == NULL && peer_key_length > 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    {
        size_t coord_len = PSA_BITS_TO_BYTES(attributes.bits);
        size_t expected_peer_len = 1u + 2u * coord_len;

        if (peer_key_length != expected_peer_len ||
            peer_key[0] != 0x04) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    ret = wc_ecc_init(&priv);
    if (ret != 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return wc_error_to_psa_status(ret);
    }
    ret = wc_ecc_init(&pub);
    if (ret != 0) {
        wc_ecc_free(&priv);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return wc_error_to_psa_status(ret);
    }

    ret = wc_ecc_import_private_key_ex(key_data, (word32)key_data_length,
                                       NULL, 0, &priv, curve_id);
    if (ret == 0) {
        ret = wc_ecc_make_pub_ex(&priv, NULL, NULL);
    }
    if (ret == 0) {
        ret = wc_ecc_import_x963(peer_key, (word32)peer_key_length, &pub);
    }
    if (ret != 0) {
        wc_ecc_free(&pub);
        wc_ecc_free(&priv);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return wc_error_to_psa_status(ret);
    }

    out_len = (word32)output_size;
    ret = wc_ecc_shared_secret(&priv, &pub, output, &out_len);
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *output_length = (size_t)out_len;
    return PSA_SUCCESS;
#else
    /* Generic (Weierstrass) ECDH needs wolfCrypt ECC (HAVE_ECC), which this
     * build does not enable. Montgomery X25519/X448 is handled above. */
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* HAVE_ECC */
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t *peer_key,
                                   size_t peer_key_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    wolfpsa_trace("psa_raw_key_agreement(alg=0x%08x key=%u peer_len=%zu)",
                  (unsigned)alg, (unsigned)private_key, peer_key_length);

    if (output == NULL || output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return wolfpsa_key_agreement_secret(alg, private_key, peer_key,
                                        peer_key_length, output, output_size,
                                        output_length);
}

psa_status_t psa_key_agreement(psa_key_id_t private_key,
                               const uint8_t *peer_key,
                               size_t peer_key_length,
                               psa_algorithm_t alg,
                               const psa_key_attributes_t *attributes,
                               psa_key_id_t *key)
{
    uint8_t *secret = NULL;
    size_t secret_len;
    size_t output_len = 0;
    psa_status_t status;
    psa_algorithm_t kdf_alg;
    psa_key_attributes_t priv_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;

    if (attributes == NULL || key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *key = PSA_KEY_ID_NULL;

    if (!PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = psa_get_key_attributes(private_key, &priv_attr);
    if (status != PSA_SUCCESS) {
        return status;
    }

    secret_len = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(priv_attr.type,
                                                   priv_attr.bits);
    if (secret_len == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    secret = (uint8_t *)XMALLOC(secret_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secret == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = wolfpsa_key_agreement_secret(alg, private_key, peer_key,
                                          peer_key_length, secret, secret_len,
                                          &output_len);
    if (status != PSA_SUCCESS) {
        wc_ForceZero(secret, secret_len);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
    if (kdf_alg == PSA_ALG_CATEGORY_KEY_DERIVATION) {
        psa_key_type_t out_type = psa_get_key_type(attributes);

        if (out_type != PSA_KEY_TYPE_DERIVE &&
            out_type != PSA_KEY_TYPE_RAW_DATA) {
            wc_ForceZero(secret, secret_len);
            XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = psa_import_key(attributes, secret, output_len, key);
        wc_ForceZero(secret, secret_len);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    status = psa_key_derivation_setup(&kdf_op, kdf_alg);
    if (status != PSA_SUCCESS) {
        wc_ForceZero(secret, secret_len);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    if (PSA_ALG_IS_HKDF(kdf_alg) || PSA_ALG_IS_HKDF_EXTRACT(kdf_alg)) {
        status = psa_key_derivation_input_bytes(&kdf_op,
                                                PSA_KEY_DERIVATION_INPUT_SALT,
                                                NULL, 0);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(secret, secret_len);
            XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            psa_key_derivation_abort(&kdf_op);
            return status;
        }
    }

    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                            secret, output_len);
    wc_ForceZero(secret, secret_len);
    XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(&kdf_op);
        return status;
    }

    if (PSA_ALG_IS_HKDF(kdf_alg) || PSA_ALG_IS_HKDF_EXPAND(kdf_alg)) {
        status = psa_key_derivation_input_bytes(&kdf_op,
                                                PSA_KEY_DERIVATION_INPUT_INFO,
                                                NULL, 0);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&kdf_op);
            return status;
        }
    }

    status = psa_key_derivation_output_key(attributes, &kdf_op, key);
    psa_key_derivation_abort(&kdf_op);
    return status;
}

#endif /* WOLFSSL_PSA_ENGINE */
