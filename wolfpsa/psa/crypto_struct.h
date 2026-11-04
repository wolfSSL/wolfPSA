/* crypto_struct.h
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

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#include <stddef.h>
#include <stdint.h>

#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct psa_hash_operation_s {
    uintptr_t opaque;
} psa_hash_operation_t;
#define PSA_HASH_OPERATION_INIT { 0 }
static inline psa_hash_operation_t psa_hash_operation_init(void)
{
    const psa_hash_operation_t v = PSA_HASH_OPERATION_INIT;
    return v;
}

typedef struct psa_xof_operation_s {
    uintptr_t opaque;
} psa_xof_operation_t;
#define PSA_XOF_OPERATION_INIT { 0 }
static inline psa_xof_operation_t psa_xof_operation_init(void)
{
    const psa_xof_operation_t v = PSA_XOF_OPERATION_INIT;
    return v;
}

typedef struct psa_cipher_operation_s {
    uintptr_t opaque;
} psa_cipher_operation_t;
#define PSA_CIPHER_OPERATION_INIT { 0 }
static inline psa_cipher_operation_t psa_cipher_operation_init(void)
{
    const psa_cipher_operation_t v = PSA_CIPHER_OPERATION_INIT;
    return v;
}

typedef struct psa_mac_operation_s {
    uintptr_t opaque;
} psa_mac_operation_t;
#define PSA_MAC_OPERATION_INIT { 0 }
static inline psa_mac_operation_t psa_mac_operation_init(void)
{
    const psa_mac_operation_t v = PSA_MAC_OPERATION_INIT;
    return v;
}

typedef struct psa_aead_operation_s {
    uintptr_t opaque;
} psa_aead_operation_t;
#define PSA_AEAD_OPERATION_INIT { 0 }
static inline psa_aead_operation_t psa_aead_operation_init(void)
{
    const psa_aead_operation_t v = PSA_AEAD_OPERATION_INIT;
    return v;
}

typedef struct psa_key_derivation_s {
    uintptr_t opaque;
} psa_key_derivation_operation_t;
#define PSA_KEY_DERIVATION_OPERATION_INIT { 0 }
static inline psa_key_derivation_operation_t psa_key_derivation_operation_init(void)
{
    const psa_key_derivation_operation_t v = PSA_KEY_DERIVATION_OPERATION_INIT;
    return v;
}

typedef struct psa_pake_operation_s {
    uintptr_t opaque;
} psa_pake_operation_t;
#define PSA_PAKE_OPERATION_INIT { 0 }
static inline psa_pake_operation_t psa_pake_operation_init(void)
{
    const psa_pake_operation_t v = PSA_PAKE_OPERATION_INIT;
    return v;
}

typedef struct psa_sign_hash_interruptible_operation_s {
    uintptr_t opaque;
} psa_sign_hash_interruptible_operation_t;
#define PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
static inline psa_sign_hash_interruptible_operation_t
psa_sign_hash_interruptible_operation_init(void)
{
    const psa_sign_hash_interruptible_operation_t v =
        PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT;
    return v;
}

struct psa_pake_cipher_suite_s {
    psa_algorithm_t alg;
    psa_pake_primitive_t primitive;
    uint32_t key_confirmation;
};

#define PSA_PAKE_CIPHER_SUITE_INIT { 0, 0, 0 }
static inline psa_pake_cipher_suite_t psa_pake_cipher_suite_init(void)
{
    const psa_pake_cipher_suite_t v = PSA_PAKE_CIPHER_SUITE_INIT;
    return v;
}

typedef struct psa_verify_hash_interruptible_operation_s {
    uintptr_t opaque;
} psa_verify_hash_interruptible_operation_t;
#define PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
static inline psa_verify_hash_interruptible_operation_t
psa_verify_hash_interruptible_operation_init(void)
{
    const psa_verify_hash_interruptible_operation_t v =
        PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT;
    return v;
}

typedef struct psa_key_agreement_iop_s {
    uintptr_t opaque;
} psa_key_agreement_iop_t;
#define PSA_KEY_AGREEMENT_IOP_INIT { 0 }
static inline psa_key_agreement_iop_t psa_key_agreement_iop_init(void)
{
    const psa_key_agreement_iop_t v = PSA_KEY_AGREEMENT_IOP_INIT;
    return v;
}

typedef struct psa_generate_key_iop_s {
    uintptr_t opaque;
} psa_generate_key_iop_t;
#define PSA_GENERATE_KEY_IOP_INIT { 0 }
static inline psa_generate_key_iop_t psa_generate_key_iop_init(void)
{
    const psa_generate_key_iop_t v = PSA_GENERATE_KEY_IOP_INIT;
    return v;
}

typedef struct psa_export_public_key_iop_s {
    uintptr_t opaque;
} psa_export_public_key_iop_t;
#define PSA_EXPORT_PUBLIC_KEY_IOP_INIT { 0 }
static inline psa_export_public_key_iop_t psa_export_public_key_iop_init(void)
{
    const psa_export_public_key_iop_t v = PSA_EXPORT_PUBLIC_KEY_IOP_INIT;
    return v;
}

struct psa_custom_key_parameters_s {
    uint32_t flags;
};

#define PSA_CUSTOM_KEY_PARAMETERS_INIT { 0 }

typedef struct psa_key_policy_s {
    psa_key_usage_t usage;
    psa_algorithm_t alg;
    psa_algorithm_t alg2;
} psa_key_policy_t;

#define PSA_KEY_POLICY_INIT { 0, 0, 0 }
static inline psa_key_policy_t psa_key_policy_init(void)
{
    const psa_key_policy_t v = PSA_KEY_POLICY_INIT;
    return v;
}


typedef uint16_t psa_key_bits_t;
#define PSA_KEY_BITS_TOO_LARGE          ((psa_key_bits_t) -1)
#define PSA_MAX_KEY_BITS 0xfff8

struct psa_key_attributes_s {
    psa_key_type_t type;
    psa_key_bits_t bits;
    psa_key_lifetime_t lifetime;
    psa_key_policy_t policy;
    psa_key_id_t id;
};

#define PSA_KEY_ATTRIBUTES_INIT { PSA_KEY_TYPE_NONE, 0,            \
                                  PSA_KEY_LIFETIME_VOLATILE,       \
                                  PSA_KEY_POLICY_INIT,             \
                                  PSA_KEY_ID_NULL }

static inline psa_key_attributes_t psa_key_attributes_init(void)
{
    const psa_key_attributes_t v = PSA_KEY_ATTRIBUTES_INIT;
    return v;
}

static inline void psa_set_key_id(psa_key_attributes_t *attributes,
                                  psa_key_id_t key)
{
    psa_key_lifetime_t lifetime = attributes->lifetime;

    attributes->id = key;

    if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        attributes->lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
            PSA_KEY_LIFETIME_PERSISTENT,
            PSA_KEY_LIFETIME_GET_LOCATION(lifetime));
    }
}

static inline psa_key_id_t psa_get_key_id(const psa_key_attributes_t *attributes)
{
    return attributes->id;
}

static inline void psa_set_key_lifetime(psa_key_attributes_t *attributes,
                                        psa_key_lifetime_t lifetime)
{
    attributes->lifetime = lifetime;
    if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        attributes->id = PSA_KEY_ID_NULL;
    }
}

static inline psa_key_lifetime_t psa_get_key_lifetime(
    const psa_key_attributes_t *attributes)
{
    return attributes->lifetime;
}

static inline void psa_extend_key_usage_flags(psa_key_usage_t *usage_flags)
{
    if (*usage_flags & PSA_KEY_USAGE_SIGN_HASH) {
        *usage_flags |= PSA_KEY_USAGE_SIGN_MESSAGE;
    }

    if (*usage_flags & PSA_KEY_USAGE_VERIFY_HASH) {
        *usage_flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
    }
}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
                                           psa_key_usage_t usage_flags)
{
    psa_extend_key_usage_flags(&usage_flags);
    attributes->policy.usage = usage_flags;
}

static inline psa_key_usage_t psa_get_key_usage_flags(
    const psa_key_attributes_t *attributes)
{
    return attributes->policy.usage;
}

static inline void psa_set_key_algorithm(psa_key_attributes_t *attributes,
                                         psa_algorithm_t alg)
{
    attributes->policy.alg = alg;
}

static inline psa_algorithm_t psa_get_key_algorithm(
    const psa_key_attributes_t *attributes)
{
    return attributes->policy.alg;
}

/* Mbed TLS second permitted algorithm, honored with WOLFPSA_ENROLLMENT_ALG */
static inline void psa_set_key_enrollment_algorithm(
    psa_key_attributes_t *attributes, psa_algorithm_t alg2)
{
    attributes->policy.alg2 = alg2;
}

static inline psa_algorithm_t psa_get_key_enrollment_algorithm(
    const psa_key_attributes_t *attributes)
{
    return attributes->policy.alg2;
}

static inline void psa_set_key_type(psa_key_attributes_t *attributes,
                                    psa_key_type_t type)
{
    attributes->type = type;
}

static inline psa_key_type_t psa_get_key_type(
    const psa_key_attributes_t *attributes)
{
    return attributes->type;
}

static inline void psa_set_key_bits(psa_key_attributes_t *attributes,
                                    size_t bits)
{
    if (bits > PSA_MAX_KEY_BITS) {
        attributes->bits = PSA_KEY_BITS_TOO_LARGE;
    } else {
        attributes->bits = (psa_key_bits_t) bits;
    }
}

static inline size_t psa_get_key_bits(const psa_key_attributes_t *attributes)
{
    return attributes->bits;
}

#ifdef __cplusplus
}
#endif

#endif 
