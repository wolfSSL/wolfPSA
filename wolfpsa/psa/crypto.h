/* crypto.h
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

#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#define PSA_CRYPTO_API_VERSION_MAJOR 1
#define PSA_CRYPTO_API_VERSION_MINOR 4

#include <stddef.h>
#include "psa/error.h"
#include "crypto_types.h"
#include "crypto_values.h"
#include "crypto_config.h"
#include "crypto_sizes.h"
#include "crypto_struct.h"
#include "crypto-pqc.h"
#include "crypto_extra.h"


/* Types */

typedef struct psa_hash_operation_s psa_hash_operation_t;
typedef struct psa_mac_operation_s psa_mac_operation_t;
typedef struct psa_cipher_operation_s psa_cipher_operation_t;
typedef struct psa_aead_operation_s psa_aead_operation_t;
typedef struct psa_xof_operation_s psa_xof_operation_t;
typedef struct psa_key_derivation_s psa_key_derivation_operation_t;
typedef struct psa_sign_hash_interruptible_operation_s psa_sign_hash_interruptible_operation_t;
typedef struct psa_verify_hash_interruptible_operation_s psa_verify_hash_interruptible_operation_t;
typedef struct psa_key_agreement_iop_s psa_key_agreement_iop_t;
typedef struct psa_generate_key_iop_s psa_generate_key_iop_t;
typedef struct psa_export_public_key_iop_s psa_export_public_key_iop_t;

/* Constants */
#define PSA_KEY_DERIVATION_UNLIMITED_CAPACITY ((size_t) (-1))


/* Function prototypes */
psa_status_t psa_crypto_init(void);
static psa_key_attributes_t psa_key_attributes_init(void);

static void psa_set_key_id(psa_key_attributes_t *attributes,
                           psa_key_id_t key);

static void psa_set_key_lifetime(psa_key_attributes_t *attributes,
                                 psa_key_lifetime_t lifetime);

static psa_key_id_t psa_get_key_id(const psa_key_attributes_t *attributes);

static psa_key_lifetime_t psa_get_key_lifetime(
    const psa_key_attributes_t *attributes);

static void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
                                    psa_key_usage_t usage_flags);


static psa_key_usage_t psa_get_key_usage_flags(
    const psa_key_attributes_t *attributes);

static void psa_set_key_algorithm(psa_key_attributes_t *attributes,
                                  psa_algorithm_t alg);

static psa_algorithm_t psa_get_key_algorithm(
    const psa_key_attributes_t *attributes);

static void psa_set_key_type(psa_key_attributes_t *attributes,
                             psa_key_type_t type);

static void psa_set_key_bits(psa_key_attributes_t *attributes,
                             size_t bits);

static psa_key_type_t psa_get_key_type(const psa_key_attributes_t *attributes);

static size_t psa_get_key_bits(const psa_key_attributes_t *attributes);

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t *attributes);

void psa_reset_key_attributes(psa_key_attributes_t *attributes);

psa_status_t psa_purge_key(psa_key_id_t key);

/* Check whether a key supports a given algorithm and usage combination. */
psa_status_t psa_check_key_usage(psa_key_id_t key,
                                 psa_algorithm_t alg,
                                 psa_key_usage_t usage);

psa_status_t psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t *attributes,
                          psa_key_id_t *target_key);

psa_status_t psa_destroy_key(psa_key_id_t key);

psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key);

psa_status_t psa_export_key(psa_key_id_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length);

psa_status_t psa_export_public_key(psa_key_id_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length);

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length);

psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              const uint8_t *hash,
                              size_t hash_length);


static psa_hash_operation_t psa_hash_operation_init(void);

psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg);

psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length);

psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length);

psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length);

psa_status_t psa_hash_abort(psa_hash_operation_t *operation);

psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation);

/* Suspend an in-progress hash operation, saving state to a caller buffer. */
psa_status_t psa_hash_suspend(psa_hash_operation_t *operation,
                              uint8_t *hash_state,
                              size_t hash_state_size,
                              size_t *hash_state_length);

/* Restore a hash operation from a previously suspended state buffer. */
psa_status_t psa_hash_resume(psa_hash_operation_t *operation,
                             const uint8_t *hash_state,
                             size_t hash_state_length);

/* XOF (extendable-output function) multi-part operation. */
static psa_xof_operation_t psa_xof_operation_init(void);

psa_status_t psa_xof_setup(psa_xof_operation_t *operation,
                           psa_algorithm_t alg);

psa_status_t psa_xof_set_context(psa_xof_operation_t *operation,
                                 const uint8_t *context,
                                 size_t context_length);

psa_status_t psa_xof_update(psa_xof_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length);

psa_status_t psa_xof_output(psa_xof_operation_t *operation,
                            uint8_t *output,
                            size_t output_length);

psa_status_t psa_xof_abort(psa_xof_operation_t *operation);

psa_status_t psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length);

psa_status_t psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t *input,
                            size_t input_length,
                            const uint8_t *mac,
                            size_t mac_length);


static psa_mac_operation_t psa_mac_operation_init(void);

psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg);

psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg);

psa_status_t psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length);

psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation,
                                 uint8_t *mac,
                                 size_t mac_size,
                                 size_t *mac_length);

psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
                                   const uint8_t *mac,
                                   size_t mac_length);

psa_status_t psa_mac_abort(psa_mac_operation_t *operation);

psa_status_t psa_cipher_encrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length);

psa_status_t psa_cipher_decrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length);


static psa_cipher_operation_t psa_cipher_operation_init(void);

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg);

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg);

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
                                    uint8_t *iv,
                                    size_t iv_size,
                                    size_t *iv_length);

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
                               const uint8_t *iv,
                               size_t iv_length);

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length);

psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length);

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation);

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
                              size_t *ciphertext_length);

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
                              size_t *plaintext_length);


static psa_aead_operation_t psa_aead_operation_init(void);

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg);

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg);

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
                                     uint8_t *nonce,
                                     size_t nonce_size,
                                     size_t *nonce_length);

psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
                                const uint8_t *nonce,
                                size_t nonce_length);

psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
                                  size_t ad_length,
                                  size_t plaintext_length);

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length);

psa_status_t psa_aead_update(psa_aead_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *output,
                             size_t output_size,
                             size_t *output_length);

psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length,
                             uint8_t *tag,
                             size_t tag_size,
                             size_t *tag_length);

psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
                             uint8_t *plaintext,
                             size_t plaintext_size,
                             size_t *plaintext_length,
                             const uint8_t *tag,
                             size_t tag_length);

psa_status_t psa_aead_abort(psa_aead_operation_t *operation);

psa_status_t psa_sign_message(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *signature,
                              size_t signature_size,
                              size_t *signature_length);

psa_status_t psa_verify_message(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                const uint8_t *signature,
                                size_t signature_length);

psa_status_t psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t *hash,
                           size_t hash_length,
                           uint8_t *signature,
                           size_t signature_size,
                           size_t *signature_length);

psa_status_t psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *hash,
                             size_t hash_length,
                             const uint8_t *signature,
                             size_t signature_length);

/* PSA 1.4: sign/verify with an explicit context string (e.g. Ed25519ctx). */
psa_status_t psa_sign_message_with_context(psa_key_id_t key,
                                           psa_algorithm_t alg,
                                           const uint8_t *input,
                                           size_t input_length,
                                           const uint8_t *context,
                                           size_t context_length,
                                           uint8_t *signature,
                                           size_t signature_size,
                                           size_t *signature_length);

psa_status_t psa_verify_message_with_context(psa_key_id_t key,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             const uint8_t *context,
                                             size_t context_length,
                                             const uint8_t *signature,
                                             size_t signature_length);

psa_status_t psa_sign_hash_with_context(psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        const uint8_t *context,
                                        size_t context_length,
                                        uint8_t *signature,
                                        size_t signature_size,
                                        size_t *signature_length);

psa_status_t psa_verify_hash_with_context(psa_key_id_t key,
                                          psa_algorithm_t alg,
                                          const uint8_t *hash,
                                          size_t hash_length,
                                          const uint8_t *context,
                                          size_t context_length,
                                          const uint8_t *signature,
                                          size_t signature_length);

psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length);

psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length);


static psa_key_derivation_operation_t psa_key_derivation_operation_init(void);

psa_status_t psa_key_derivation_setup(
    psa_key_derivation_operation_t *operation,
    psa_algorithm_t alg);

psa_status_t psa_key_derivation_get_capacity(
    const psa_key_derivation_operation_t *operation,
    size_t *capacity);

psa_status_t psa_key_derivation_set_capacity(
    psa_key_derivation_operation_t *operation,
    size_t capacity);


psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length);

psa_status_t psa_key_derivation_input_integer(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    uint64_t value);

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_id_t key);

psa_status_t psa_key_derivation_key_agreement(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length);

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation,
    uint8_t *output,
    size_t output_length);

psa_status_t psa_key_derivation_output_key(
    const psa_key_attributes_t *attributes,
    psa_key_derivation_operation_t *operation,
    psa_key_id_t *key);

psa_status_t psa_key_derivation_output_key_custom(
    const psa_key_attributes_t *attributes,
    psa_key_derivation_operation_t *operation,
    const psa_custom_key_parameters_t *custom,
    const uint8_t *custom_data,
    size_t custom_data_length,
    psa_key_id_t *key);

psa_status_t psa_key_derivation_verify_bytes(
    psa_key_derivation_operation_t *operation,
    const uint8_t *expected,
    size_t expected_length);

psa_status_t psa_key_derivation_verify_key(
    psa_key_derivation_operation_t *operation,
    psa_key_id_t expected);

psa_status_t psa_key_derivation_abort(
    psa_key_derivation_operation_t *operation);

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t *peer_key,
                                   size_t peer_key_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length);

psa_status_t psa_key_agreement(psa_key_id_t private_key,
                               const uint8_t *peer_key,
                               size_t peer_key_length,
                               psa_algorithm_t alg,
                               const psa_key_attributes_t *attributes,
                               psa_key_id_t *key);

/* PSA 1.4: KEM encapsulate/decapsulate (e.g. ML-KEM). */
psa_status_t psa_encapsulate(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const psa_key_attributes_t *attributes,
                             psa_key_id_t *output_key,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length);

psa_status_t psa_decapsulate(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *ciphertext,
                             size_t ciphertext_length,
                             const psa_key_attributes_t *attributes,
                             psa_key_id_t *output_key);

psa_status_t psa_generate_random(uint8_t *output,
                                 size_t output_size);

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
                              psa_key_id_t *key);

psa_status_t psa_generate_key_custom(const psa_key_attributes_t *attributes,
                                     const psa_custom_key_parameters_t *custom,
                                     const uint8_t *custom_data,
                                     size_t custom_data_length,
                                     psa_key_id_t *key);

/* PSA 1.4: key wrapping and hardware-bound key attachment. */
psa_status_t psa_wrap_key(psa_key_id_t wrapping_key,
                          psa_algorithm_t alg,
                          psa_key_id_t key,
                          uint8_t *data,
                          size_t data_size,
                          size_t *data_length);

psa_status_t psa_unwrap_key(const psa_key_attributes_t *attributes,
                            psa_key_id_t wrapping_key,
                            psa_algorithm_t alg,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key);

psa_status_t psa_attach_key(const psa_key_attributes_t *attributes,
                            const uint8_t *label,
                            size_t label_length,
                            psa_key_id_t *key);


void psa_interruptible_set_max_ops(uint32_t max_ops);

uint32_t psa_interruptible_get_max_ops(void);

uint32_t psa_sign_hash_get_num_ops(
    const psa_sign_hash_interruptible_operation_t *operation);

uint32_t psa_verify_hash_get_num_ops(
    const psa_verify_hash_interruptible_operation_t *operation);

psa_status_t psa_sign_hash_start(
    psa_sign_hash_interruptible_operation_t *operation,
    psa_key_id_t key, psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length);

psa_status_t psa_sign_hash_complete(
    psa_sign_hash_interruptible_operation_t *operation,
    uint8_t *signature, size_t signature_size,
    size_t *signature_length);

psa_status_t psa_sign_hash_abort(
    psa_sign_hash_interruptible_operation_t *operation);

psa_status_t psa_verify_hash_start(
    psa_verify_hash_interruptible_operation_t *operation,
    psa_key_id_t key, psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length);

psa_status_t psa_verify_hash_complete(
    psa_verify_hash_interruptible_operation_t *operation);

psa_status_t psa_verify_hash_abort(
    psa_verify_hash_interruptible_operation_t *operation);


uint32_t psa_key_agreement_iop_get_num_ops(psa_key_agreement_iop_t *operation);

psa_status_t psa_key_agreement_iop_setup(
    psa_key_agreement_iop_t *operation,
    psa_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length,
    psa_algorithm_t alg,
    const psa_key_attributes_t *attributes);

psa_status_t psa_key_agreement_iop_complete(
    psa_key_agreement_iop_t *operation,
    psa_key_id_t *key);

psa_status_t psa_key_agreement_iop_abort(
    psa_key_agreement_iop_t *operation);
uint32_t psa_generate_key_iop_get_num_ops(psa_generate_key_iop_t *operation);

psa_status_t psa_generate_key_iop_setup(
    psa_generate_key_iop_t *operation,
    const psa_key_attributes_t *attributes);

psa_status_t psa_generate_key_iop_complete(
    psa_generate_key_iop_t *operation,
    psa_key_id_t *key);

psa_status_t psa_generate_key_iop_abort(
    psa_generate_key_iop_t *operation);
uint32_t psa_export_public_key_iop_get_num_ops(psa_export_public_key_iop_t *operation);
psa_status_t psa_export_public_key_iop_setup(psa_export_public_key_iop_t *operation,
                                             psa_key_id_t key);

psa_status_t psa_export_public_key_iop_complete(psa_export_public_key_iop_t *operation,
                                                uint8_t *data,
                                                size_t data_size,
                                                size_t *data_length);

psa_status_t psa_export_public_key_iop_abort(psa_export_public_key_iop_t *operation);

psa_pake_cipher_suite_t psa_pake_cipher_suite_init(void);
psa_algorithm_t psa_pake_cs_get_algorithm(const psa_pake_cipher_suite_t *cipher_suite);
void psa_pake_cs_set_algorithm(psa_pake_cipher_suite_t *cipher_suite,
                               psa_algorithm_t alg);
psa_pake_primitive_t psa_pake_cs_get_primitive(const psa_pake_cipher_suite_t *cipher_suite);
void psa_pake_cs_set_primitive(psa_pake_cipher_suite_t *cipher_suite,
                               psa_pake_primitive_t primitive);
uint32_t psa_pake_cs_get_key_confirmation(const psa_pake_cipher_suite_t *cipher_suite);
void psa_pake_cs_set_key_confirmation(psa_pake_cipher_suite_t *cipher_suite,
                                      uint32_t key_confirmation);

psa_pake_operation_t psa_pake_operation_init(void);
psa_status_t psa_pake_setup(psa_pake_operation_t *operation,
                            psa_key_id_t password_key,
                            const psa_pake_cipher_suite_t *cipher_suite);
psa_status_t psa_pake_set_role(psa_pake_operation_t *operation,
                               psa_pake_role_t role);
psa_status_t psa_pake_set_user(psa_pake_operation_t *operation,
                               const uint8_t *user_id,
                               size_t user_id_len);
psa_status_t psa_pake_set_peer(psa_pake_operation_t *operation,
                               const uint8_t *peer_id,
                               size_t peer_id_len);
psa_status_t psa_pake_set_context(psa_pake_operation_t *operation,
                                  const uint8_t *context,
                                  size_t context_len);
psa_status_t psa_pake_output(psa_pake_operation_t *operation,
                             psa_pake_step_t step,
                             uint8_t *output,
                             size_t output_size,
                             size_t *output_length);
psa_status_t psa_pake_input(psa_pake_operation_t *operation,
                            psa_pake_step_t step,
                            const uint8_t *input,
                            size_t input_length);
psa_status_t psa_pake_get_shared_key(psa_pake_operation_t *operation,
                                     const psa_key_attributes_t *attributes,
                                     psa_key_id_t *key);
psa_status_t psa_pake_abort(psa_pake_operation_t *operation);
#endif 
