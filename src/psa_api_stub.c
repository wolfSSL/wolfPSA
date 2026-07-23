/* psa_api_stub.c
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

#include <psa/crypto.h>

extern int wolfPSA_CryptoIsInitialized(void);

static psa_status_t wolfPSA_StubNotSupported(void)
{
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_pake_abort(psa_pake_operation_t *operation) {
    (void)operation;
    return wolfPSA_StubNotSupported();
}

psa_algorithm_t psa_pake_cs_get_algorithm(const psa_pake_cipher_suite_t *cipher_suite) {
    (void)cipher_suite;
    return 0;
}

void psa_pake_cs_set_algorithm(psa_pake_cipher_suite_t *cipher_suite, psa_algorithm_t alg) {
    (void)cipher_suite;
    (void)alg;
}

psa_pake_primitive_t psa_pake_cs_get_primitive(const psa_pake_cipher_suite_t *cipher_suite) {
    (void)cipher_suite;
    return 0;
}

void psa_pake_cs_set_primitive(psa_pake_cipher_suite_t *cipher_suite,
                               psa_pake_primitive_t primitive) {
    (void)cipher_suite;
    (void)primitive;
}

uint32_t psa_pake_cs_get_key_confirmation(const psa_pake_cipher_suite_t *cipher_suite) {
    (void)cipher_suite;
    return PSA_PAKE_UNCONFIRMED_KEY;
}

void psa_pake_cs_set_key_confirmation(psa_pake_cipher_suite_t *cipher_suite,
                                      uint32_t key_confirmation) {
    (void)cipher_suite;
    (void)key_confirmation;
}

psa_status_t psa_pake_get_shared_key(psa_pake_operation_t *operation, const psa_key_attributes_t *attributes, psa_key_id_t *key) {
    (void)operation;
    (void)attributes;
    (void)key;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_input(psa_pake_operation_t *operation, psa_pake_step_t step, const uint8_t *input, size_t input_length) {
    (void)operation;
    (void)step;
    (void)input;
    (void)input_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_output(psa_pake_operation_t *operation, psa_pake_step_t step, uint8_t *output, size_t output_size, size_t *output_length) {
    (void)operation;
    (void)step;
    (void)output;
    (void)output_size;
    (void)output_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_context(psa_pake_operation_t *operation, const uint8_t *context, size_t context_len) {
    (void)operation;
    (void)context;
    (void)context_len;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_peer(psa_pake_operation_t *operation, const uint8_t *peer_id, size_t peer_id_len) {
    (void)operation;
    (void)peer_id;
    (void)peer_id_len;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_role(psa_pake_operation_t *operation, psa_pake_role_t role) {
    (void)operation;
    (void)role;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_user(psa_pake_operation_t *operation, const uint8_t *user_id, size_t user_id_len) {
    (void)operation;
    (void)user_id;
    (void)user_id_len;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_setup(psa_pake_operation_t *operation, psa_key_id_t password_key, const psa_pake_cipher_suite_t *cipher_suite) {
    (void)operation;
    (void)password_key;
    (void)cipher_suite;
    return wolfPSA_StubNotSupported();
}

/* --- Key attachment (hardware-bound keys) --- */

psa_status_t psa_attach_key(const psa_key_attributes_t *attributes,
                             const uint8_t *label,
                             size_t label_length,
                             psa_key_id_t *key) {
    (void)attributes;
    (void)label;
    (void)label_length;
    (void)key;
    return wolfPSA_StubNotSupported();
}

/* --- Hash suspend/resume --- */

psa_status_t psa_hash_suspend(psa_hash_operation_t *operation,
                               uint8_t *hash_state,
                               size_t hash_state_size,
                               size_t *hash_state_length) {
    (void)operation;
    (void)hash_state;
    (void)hash_state_size;
    (void)hash_state_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_hash_resume(psa_hash_operation_t *operation,
                              const uint8_t *hash_state,
                              size_t hash_state_length) {
    (void)operation;
    (void)hash_state;
    (void)hash_state_length;
    return wolfPSA_StubNotSupported();
}

/* --- Interruptible max-ops configuration --- */

static uint32_t wolfPSA_interruptible_max_ops = PSA_INTERRUPTIBLE_MAX_OPS_UNLIMITED;

void psa_interruptible_set_max_ops(uint32_t max_ops) {
    wolfPSA_interruptible_max_ops = max_ops;
}

uint32_t psa_interruptible_get_max_ops(void) {
    return wolfPSA_interruptible_max_ops;
}

/* --- Interruptible sign/verify hash --- */

psa_status_t psa_sign_hash_start(
    psa_sign_hash_interruptible_operation_t *operation,
    psa_key_id_t key, psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length) {
    (void)operation;
    (void)key;
    (void)alg;
    (void)hash;
    (void)hash_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_sign_hash_complete(
    psa_sign_hash_interruptible_operation_t *operation,
    uint8_t *signature, size_t signature_size,
    size_t *signature_length) {
    (void)operation;
    (void)signature;
    (void)signature_size;
    (void)signature_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_sign_hash_abort(
    psa_sign_hash_interruptible_operation_t *operation) {
    (void)operation;
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_SUCCESS;
}

uint32_t psa_sign_hash_get_num_ops(
    const psa_sign_hash_interruptible_operation_t *operation) {
    (void)operation;
    return 0;
}

psa_status_t psa_verify_hash_start(
    psa_verify_hash_interruptible_operation_t *operation,
    psa_key_id_t key, psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length) {
    (void)operation;
    (void)key;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_verify_hash_complete(
    psa_verify_hash_interruptible_operation_t *operation) {
    (void)operation;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_verify_hash_abort(
    psa_verify_hash_interruptible_operation_t *operation) {
    (void)operation;
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_SUCCESS;
}

uint32_t psa_verify_hash_get_num_ops(
    const psa_verify_hash_interruptible_operation_t *operation) {
    (void)operation;
    return 0;
}

/* --- Interruptible key agreement (IOP) --- */

psa_status_t psa_key_agreement_iop_setup(
    psa_key_agreement_iop_t *operation,
    psa_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length,
    psa_algorithm_t alg,
    const psa_key_attributes_t *attributes) {
    (void)operation;
    (void)private_key;
    (void)peer_key;
    (void)peer_key_length;
    (void)alg;
    (void)attributes;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_key_agreement_iop_complete(
    psa_key_agreement_iop_t *operation,
    psa_key_id_t *key) {
    (void)operation;
    (void)key;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_key_agreement_iop_abort(
    psa_key_agreement_iop_t *operation) {
    (void)operation;
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_SUCCESS;
}

uint32_t psa_key_agreement_iop_get_num_ops(psa_key_agreement_iop_t *operation) {
    (void)operation;
    return 0;
}

/* --- Interruptible key generation (IOP) --- */

psa_status_t psa_generate_key_iop_setup(
    psa_generate_key_iop_t *operation,
    const psa_key_attributes_t *attributes) {
    (void)operation;
    (void)attributes;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_generate_key_iop_complete(
    psa_generate_key_iop_t *operation,
    psa_key_id_t *key) {
    (void)operation;
    (void)key;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_generate_key_iop_abort(
    psa_generate_key_iop_t *operation) {
    (void)operation;
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_SUCCESS;
}

uint32_t psa_generate_key_iop_get_num_ops(psa_generate_key_iop_t *operation) {
    (void)operation;
    return 0;
}

/* --- Interruptible export public key (IOP) --- */

psa_status_t psa_export_public_key_iop_setup(
    psa_export_public_key_iop_t *operation,
    psa_key_id_t key) {
    (void)operation;
    (void)key;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_export_public_key_iop_complete(
    psa_export_public_key_iop_t *operation,
    uint8_t *data,
    size_t data_size,
    size_t *data_length) {
    (void)operation;
    (void)data;
    (void)data_size;
    (void)data_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_export_public_key_iop_abort(
    psa_export_public_key_iop_t *operation) {
    (void)operation;
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_SUCCESS;
}

uint32_t psa_export_public_key_iop_get_num_ops(
    psa_export_public_key_iop_t *operation) {
    (void)operation;
    return 0;
}

/* --- Custom key parameter wrappers (delegating) --- */

psa_status_t psa_generate_key_custom(const psa_key_attributes_t *attributes,
                                      const psa_custom_key_parameters_t *custom,
                                      const uint8_t *custom_data,
                                      size_t custom_data_length,
                                      psa_key_id_t *key) {
    if (custom == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (custom->flags != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (custom_data_length != 0) {
        (void)custom_data;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)custom_data;
    return psa_generate_key(attributes, key);
}

psa_status_t psa_key_derivation_output_key_custom(
    const psa_key_attributes_t *attributes,
    psa_key_derivation_operation_t *operation,
    const psa_custom_key_parameters_t *custom,
    const uint8_t *custom_data,
    size_t custom_data_length,
    psa_key_id_t *key) {
    if (custom == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (custom->flags != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (custom_data_length != 0) {
        (void)custom_data;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)custom_data;
    return psa_key_derivation_output_key(attributes, operation, key);
}

void psa_reset_key_attributes(psa_key_attributes_t *attributes) {
    if (attributes == NULL) {
        return;
    }

    *attributes = psa_key_attributes_init();
}
