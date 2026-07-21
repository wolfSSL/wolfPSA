/* psa_key_storage.c
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
#include <psa_key_storage.h>
#include <psa_store.h>
#include "psa_trace.h"
#include "psa_size.h"
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <limits.h>
#include <psa/crypto-pqc.h>
#include "psa_pqc_internal.h"

#ifdef WOLFPSA_DEBUG_IMPORT
#include <stdio.h>
#endif
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* Key storage state */
static int g_key_storage_initialized = 0;
static psa_key_id_t g_next_key_id = PSA_KEY_ID_VENDOR_MIN;

typedef struct wolfpsa_volatile_key_node {
    psa_key_id_t id;
    psa_key_attributes_t attributes;
    uint8_t* data;
    size_t data_length;
    struct wolfpsa_volatile_key_node* next;
} wolfpsa_volatile_key_node;

static wolfpsa_volatile_key_node* g_volatile_keys = NULL;

/* Internal init state from psa_crypto_init() */
extern int wolfPSA_CryptoIsInitialized(void);
extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);
psa_status_t psa_asymmetric_generate_key_rsa(psa_key_type_t key_type,
                                            size_t key_bits,
                                            uint8_t *private_key,
                                            size_t private_key_size,
                                            size_t *private_key_length,
                                            uint8_t *public_key,
                                            size_t public_key_size,
                                            size_t *public_key_length);
psa_status_t psa_asymmetric_generate_key_ecc(psa_key_type_t key_type,
                                            size_t key_bits,
                                            uint8_t *private_key,
                                            size_t private_key_size,
                                            size_t *private_key_length,
                                            uint8_t *public_key,
                                            size_t public_key_size,
                                            size_t *public_key_length);
#ifdef HAVE_ED25519
psa_status_t psa_asymmetric_generate_key_ed25519(psa_key_type_t key_type,
                                                size_t key_bits,
                                                uint8_t *private_key,
                                                size_t private_key_size,
                                                size_t *private_key_length,
                                                uint8_t *public_key,
                                                size_t public_key_size,
                                                size_t *public_key_length);
psa_status_t psa_asymmetric_export_public_key_ed25519(psa_key_type_t key_type,
                                                     size_t key_bits,
                                                     const uint8_t *key_buffer,
                                                     size_t key_buffer_size,
                                                     uint8_t *output,
                                                     size_t output_size,
                                                     size_t *output_length);
#endif
#ifdef HAVE_ED448
psa_status_t psa_asymmetric_generate_key_ed448(psa_key_type_t key_type,
                                              size_t key_bits,
                                              uint8_t *private_key,
                                              size_t private_key_size,
                                              size_t *private_key_length,
                                              uint8_t *public_key,
                                              size_t public_key_size,
                                              size_t *public_key_length);
psa_status_t psa_asymmetric_export_public_key_ed448(psa_key_type_t key_type,
                                                   size_t key_bits,
                                                   const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t *output,
                                                   size_t output_size,
                                                   size_t *output_length);
#endif
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT) && \
    defined(HAVE_CURVE25519_KEY_EXPORT)
psa_status_t psa_asymmetric_generate_key_x25519(psa_key_type_t key_type,
                                                size_t key_bits,
                                                uint8_t *private_key,
                                                size_t private_key_size,
                                                size_t *private_key_length,
                                                uint8_t *public_key,
                                                size_t public_key_size,
                                                size_t *public_key_length);
psa_status_t psa_asymmetric_export_public_key_x25519(psa_key_type_t key_type,
                                                     size_t key_bits,
                                                     const uint8_t *key_buffer,
                                                     size_t key_buffer_size,
                                                     uint8_t *output,
                                                     size_t output_size,
                                                     size_t *output_length);
#endif
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
    defined(HAVE_CURVE448_KEY_EXPORT)
psa_status_t psa_asymmetric_generate_key_x448(psa_key_type_t key_type,
                                              size_t key_bits,
                                              uint8_t *private_key,
                                              size_t private_key_size,
                                              size_t *private_key_length,
                                              uint8_t *public_key,
                                              size_t public_key_size,
                                              size_t *public_key_length);
psa_status_t psa_asymmetric_export_public_key_x448(psa_key_type_t key_type,
                                                   size_t key_bits,
                                                   const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t *output,
                                                   size_t output_size,
                                                   size_t *output_length);
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && defined(HAVE_ECC_KEY_IMPORT)
psa_status_t psa_asymmetric_export_public_key_ecc(psa_key_type_t key_type,
                                                  size_t key_bits,
                                                  const uint8_t *key_buffer,
                                                  size_t key_buffer_size,
                                                  uint8_t *output,
                                                  size_t output_size,
                                                  size_t *output_length);
#endif

static psa_status_t psa_wc_error_to_psa_status(int ret)
{
    psa_status_t status;

    if (ret == 0) {
        return PSA_SUCCESS;
    }

    switch (ret) {
        case BAD_FUNC_ARG:
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case BUFFER_E:
        case RSA_BUFFER_E:
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            break;
        case MEMORY_E:
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
            break;
        case NOT_COMPILED_IN:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        case BAD_STATE_E:
            status = PSA_ERROR_BAD_STATE;
            break;
        default:
            status = PSA_ERROR_GENERIC_ERROR;
            break;
    }

    return status;
}

static psa_status_t wolfpsa_validate_stored_key_data_length(size_t key_data_length)
{
    if (key_data_length == 0 || key_data_length > (size_t)INT_MAX) {
        return PSA_ERROR_DATA_INVALID;
    }

    return PSA_SUCCESS;
}

static psa_key_bits_t wolfpsa_ecc_bits_from_length(psa_ecc_family_t family,
                                                   size_t length_bytes)
{
    switch (family) {
        case PSA_ECC_FAMILY_SECP_R1:
            switch (length_bytes) {
                case 24: return 192;
                case 28: return 224;
                case 32: return 256;
                case 48: return 384;
                case 66: return 521;
                default: return 0;
            }

        case PSA_ECC_FAMILY_SECP_K1:
            switch (length_bytes) {
                case 24: return 192;
                case 28: return 224;
                case 32: return 256;
                default: return 0;
            }

        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch (length_bytes) {
                case 32: return 256;
                case 48: return 384;
                case 64: return 512;
                default: return 0;
            }

        case PSA_ECC_FAMILY_MONTGOMERY:
        case PSA_ECC_FAMILY_TWISTED_EDWARDS:
            switch (length_bytes) {
                case 32: return 255;
                case 56: return 448;
                case 57: return 448;
                default: return 0;
            }

        default:
            return 0;
    }
}

static int wolfpsa_usage_flags_valid(psa_key_usage_t usage)
{
    psa_key_usage_t mask = PSA_KEY_USAGE_EXPORT |
                           PSA_KEY_USAGE_COPY |
                           PSA_KEY_USAGE_ENCRYPT |
                           PSA_KEY_USAGE_DECRYPT |
                           PSA_KEY_USAGE_SIGN_MESSAGE |
                           PSA_KEY_USAGE_VERIFY_MESSAGE |
                           PSA_KEY_USAGE_SIGN_HASH |
                           PSA_KEY_USAGE_VERIFY_HASH |
                           PSA_KEY_USAGE_DERIVE |
                           PSA_KEY_USAGE_VERIFY_DERIVATION |
                           PSA_KEY_USAGE_WRAP |
                           PSA_KEY_USAGE_UNWRAP;

    return (usage & ~mask) == 0;
}

static wolfpsa_volatile_key_node* wolfpsa_volatile_find(psa_key_id_t key_id)
{
    wolfpsa_volatile_key_node* cur = g_volatile_keys;

    while (cur != NULL) {
        if (cur->id == key_id) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

static psa_status_t wolfpsa_volatile_store(psa_key_id_t key_id,
                                           const psa_key_attributes_t* attributes,
                                           const uint8_t* data,
                                           size_t data_length)
{
    wolfpsa_volatile_key_node* node;

    if (attributes == NULL || data == NULL || data_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (wolfpsa_volatile_find(key_id) != NULL) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    node = (wolfpsa_volatile_key_node*)XMALLOC(sizeof(*node), NULL,
                                               DYNAMIC_TYPE_TMP_BUFFER);
    if (node == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(node, 0, sizeof(*node));

    node->data = (uint8_t*)XMALLOC(data_length, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (node->data == NULL) {
        XFREE(node, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    XMEMCPY(node->data, data, data_length);
    node->data_length = data_length;
    node->attributes = *attributes;
    node->id = key_id;

    node->next = g_volatile_keys;
    g_volatile_keys = node;

    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_volatile_remove(psa_key_id_t key_id)
{
    wolfpsa_volatile_key_node* cur = g_volatile_keys;
    wolfpsa_volatile_key_node* prev = NULL;

    while (cur != NULL) {
        if (cur->id == key_id) {
            if (prev != NULL) {
                prev->next = cur->next;
            }
            else {
                g_volatile_keys = cur->next;
            }
            if (cur->data != NULL) {
                wc_ForceZero(cur->data, cur->data_length);
                XFREE(cur->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
            XMEMSET(cur, 0, sizeof(*cur));
            XFREE(cur, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_SUCCESS;
        }
        prev = cur;
        cur = cur->next;
    }

    return PSA_ERROR_INVALID_HANDLE;
}

static psa_status_t wolfpsa_volatile_get(psa_key_id_t key_id,
                                        psa_key_attributes_t* attributes,
                                        uint8_t** key_data,
                                        size_t* key_data_length)
{
    wolfpsa_volatile_key_node* node;

    if (key_data == NULL || key_data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *key_data = NULL;
    *key_data_length = 0;

    node = wolfpsa_volatile_find(key_id);
    if (node == NULL) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    if (attributes != NULL) {
        *attributes = node->attributes;
    }

    if (node->data_length == 0 || node->data == NULL) {
        return PSA_ERROR_DATA_INVALID;
    }

    *key_data = (uint8_t*)XMALLOC(node->data_length, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (*key_data == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    XMEMCPY(*key_data, node->data, node->data_length);
    *key_data_length = node->data_length;

    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_volatile_get_attributes(psa_key_id_t key_id,
                                                    psa_key_attributes_t* attributes)
{
    wolfpsa_volatile_key_node* node;

    if (attributes == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    node = wolfpsa_volatile_find(key_id);
    if (node == NULL) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    *attributes = node->attributes;
    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_infer_key_bits(psa_key_attributes_t* attr,
                                           const uint8_t* data,
                                           size_t data_length)
{
    if (attr == NULL || data == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (attr->bits != 0) {
        return PSA_SUCCESS;
    }

    if (attr->type == PSA_KEY_TYPE_AES ||
        attr->type == PSA_KEY_TYPE_DES ||
        attr->type == PSA_KEY_TYPE_HMAC ||
        attr->type == PSA_KEY_TYPE_RAW_DATA ||
        attr->type == PSA_KEY_TYPE_CHACHA20 ||
        attr->type == PSA_KEY_TYPE_XCHACHA20 ||
        attr->type == PSA_KEY_TYPE_DERIVE ||
        attr->type == PSA_KEY_TYPE_PASSWORD ||
        attr->type == PSA_KEY_TYPE_PASSWORD_HASH ||
        attr->type == PSA_KEY_TYPE_PEPPER) {
        attr->bits = (psa_key_bits_t)(data_length * 8U);
        return PSA_SUCCESS;
    }

    if (PSA_KEY_TYPE_IS_ECC(attr->type)) {
        psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(attr->type);
        psa_key_bits_t inferred_bits;

        if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(attr->type)) {
            if (family == PSA_ECC_FAMILY_MONTGOMERY ||
                family == PSA_ECC_FAMILY_TWISTED_EDWARDS) {
                inferred_bits = wolfpsa_ecc_bits_from_length(family,
                                                             data_length);
            }
            else {
                if (data_length < 2u || ((data_length - 1u) & 1u) != 0u) {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }
                inferred_bits = wolfpsa_ecc_bits_from_length(family,
                                                             (data_length - 1u) / 2u);
            }
        }
        else {
            inferred_bits = wolfpsa_ecc_bits_from_length(family, data_length);
        }

        if (inferred_bits == 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        attr->bits = inferred_bits;
        return PSA_SUCCESS;
    }

#ifndef NO_RSA
    if (PSA_KEY_TYPE_IS_RSA(attr->type)) {
        RsaKey rsa;
        word32 idx = 0;
        int ret;
        int size;

        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) {
            return psa_wc_error_to_psa_status(ret);
        }

        if (attr->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
            ret = wc_RsaPublicKeyDecode(data, &idx, &rsa, (word32)data_length);
        }
        else {
            ret = wc_RsaPrivateKeyDecode(data, &idx, &rsa, (word32)data_length);
        }

        if (ret == 0) {
            size = wc_RsaEncryptSize(&rsa);
            if (size <= 0) {
                ret = BAD_FUNC_ARG;
            }
            else {
                attr->bits = (psa_key_bits_t)((size_t)size * 8U);
            }
        }

        wc_FreeRsaKey(&rsa);
        return ret == 0 ? PSA_SUCCESS : psa_wc_error_to_psa_status(ret);
    }
#endif

    if (PSA_KEY_TYPE_IS_DH(attr->type)) {
        attr->bits = (psa_key_bits_t)(data_length * 8U);
        return PSA_SUCCESS;
    }

    /* ML-DSA: key pairs store a 32-byte seed — ambiguous across parameter sets,
     * caller must set bits explicitly. Public keys have unambiguous sizes. */
    if (PSA_KEY_TYPE_IS_ML_DSA(attr->type)) {
        if (attr->type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
            switch (data_length) {
                case 1312: attr->bits = 128; return PSA_SUCCESS;
                case 1952: attr->bits = 192; return PSA_SUCCESS;
                case 2592: attr->bits = 256; return PSA_SUCCESS;
                default:   return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        /* Key pair: 32-byte seed is ambiguous — bits must be set by caller. */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* ML-KEM: key pairs store a 64-byte seed — ambiguous. Public key sizes
     * are unambiguous. */
    if (PSA_KEY_TYPE_IS_ML_KEM(attr->type)) {
        if (attr->type == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY) {
            switch (data_length) {
                case  800: attr->bits =  512; return PSA_SUCCESS;
                case 1184: attr->bits =  768; return PSA_SUCCESS;
                case 1568: attr->bits = 1024; return PSA_SUCCESS;
                default:   return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        /* Key pair: 64-byte seed is ambiguous — bits must be set by caller. */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* LMS / HSS / XMSS / XMSS^MT — public-key-only types, infer bits from
     * blob length (hash-output length: 192-bit or 256-bit parameter sets). */
    if (attr->type == PSA_KEY_TYPE_LMS_PUBLIC_KEY) {
        switch (data_length) {
            case 48: attr->bits = 192; return PSA_SUCCESS;
            case 56: attr->bits = 256; return PSA_SUCCESS;
            default: return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    if (attr->type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        switch (data_length) {
            case 52: attr->bits = 192; return PSA_SUCCESS;
            case 60: attr->bits = 256; return PSA_SUCCESS;
            default: return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    if (attr->type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY ||
        attr->type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        switch (data_length) {
            case 52: attr->bits = 192; return PSA_SUCCESS;
            case 68: attr->bits = 256; return PSA_SUCCESS;
            default: return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

#ifndef NO_RSA
static size_t psa_der_len_size(size_t len)
{
    size_t size = 1;

    if (len < 128) {
        return size;
    }

    while (len > 0) {
        size++;
        len >>= 8;
    }

    return size;
}

static size_t psa_der_write_len(uint8_t* out, size_t len)
{
    if (len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    }
    else {
        size_t i = 0;
        size_t tmp = len;

        while (tmp > 0) {
            i++;
            tmp >>= 8;
        }

        out[0] = (uint8_t)(0x80 | i);
        while (i > 0) {
            out[i] = (uint8_t)(len & 0xFF);
            len >>= 8;
            i--;
        }

        return (size_t)out[0] - 0x80 + 1;
    }
}

static size_t psa_der_int_size(const uint8_t* val, size_t len)
{
    size_t offset = 0;
    size_t value_len;
    int add_zero = 0;

    while (offset < len && val[offset] == 0x00) {
        offset++;
    }

    if (offset == len) {
        return 3;
    }

    value_len = len - offset;
    if (val[offset] & 0x80) {
        add_zero = 1;
    }

    return 1 + psa_der_len_size(value_len + (size_t)add_zero) +
           value_len + (size_t)add_zero;
}

static size_t psa_der_write_int(uint8_t* out, const uint8_t* val, size_t len)
{
    size_t offset = 0;
    size_t value_len;
    size_t len_bytes;
    int add_zero = 0;

    while (offset < len && val[offset] == 0x00) {
        offset++;
    }

    out[0] = 0x02;
    if (offset == len) {
        out[1] = 0x01;
        out[2] = 0x00;
        return 3;
    }

    value_len = len - offset;
    if (val[offset] & 0x80) {
        add_zero = 1;
    }

    len_bytes = psa_der_write_len(out + 1, value_len + (size_t)add_zero);
    if (add_zero) {
        out[1 + len_bytes] = 0x00;
        XMEMCPY(out + 1 + len_bytes + 1, val + offset, value_len);
        return 1 + len_bytes + 1 + value_len;
    }

    XMEMCPY(out + 1 + len_bytes, val + offset, value_len);
    return 1 + len_bytes + value_len;
}
#endif /* !NO_RSA */

/* Initialize the PSA key storage subsystem */
psa_status_t psa_key_storage_init(const wc_KeyVault_Callbacks* callbacks)
{
    (void)callbacks;
    g_key_storage_initialized = 1;
    return PSA_SUCCESS;
}

/* Cleanup the PSA key storage subsystem */
void psa_key_storage_cleanup(void)
{
    wolfpsa_volatile_key_node* cur = g_volatile_keys;
    while (cur != NULL) {
        wolfpsa_volatile_key_node* next = cur->next;
        if (cur->data != NULL) {
            wc_ForceZero(cur->data, cur->data_length);
            XFREE(cur->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XMEMSET(cur, 0, sizeof(*cur));
        XFREE(cur, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        cur = next;
    }
    g_volatile_keys = NULL;
    g_key_storage_initialized = 0;
}

psa_key_id_t wolfpsa_test_get_next_key_id(void)
{
    return g_next_key_id;
}

void wolfpsa_test_set_next_key_id(psa_key_id_t key_id)
{
    g_next_key_id = key_id;
}

/* Check if the key storage is initialized */
static psa_status_t psa_key_storage_check_init(void)
{
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!g_key_storage_initialized) {
        (void)psa_key_storage_init(NULL);
    }
    
    return PSA_SUCCESS;
}

#ifdef WOLFPSA_DEBUG_IMPORT
static void wolfpsa_debug_import_reason(const char* reason,
                                        const psa_key_attributes_t* attr,
                                        size_t data_length)
{
    if (attr == NULL) {
        fprintf(stderr, "wolfpsa_import_key: %s (null attributes)\n", reason);
        return;
    }
    fprintf(stderr,
            "wolfpsa_import_key: %s type=0x%08x bits=%u alg=0x%08x usage=0x%08x data_len=%zu\n",
            reason,
            (unsigned)attr->type,
            (unsigned)attr->bits,
            (unsigned)attr->policy.alg,
            (unsigned)attr->policy.usage,
            data_length);
}
#else
#define wolfpsa_debug_import_reason(reason, attr, data_length) ((void)0)
#endif

/* Serialize key attributes to a buffer */
static psa_status_t psa_key_attributes_serialize(
    const psa_key_attributes_t* attributes,
    uint8_t* buffer,
    size_t buffer_size,
    size_t* buffer_length)
{
    size_t required_size;
    
    /* Check parameters */
    if (attributes == NULL || buffer == NULL || buffer_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Calculate required size */
    required_size = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                    sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                    sizeof(psa_key_lifetime_t);
    
    /* Check buffer size */
    if (buffer_size < required_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Serialize key attributes */
    XMEMCPY(buffer, &attributes->type, sizeof(psa_key_type_t));
    buffer += sizeof(psa_key_type_t);
    
    XMEMCPY(buffer, &attributes->bits, sizeof(psa_key_bits_t));
    buffer += sizeof(psa_key_bits_t);
    
    XMEMCPY(buffer, &attributes->policy.usage,
            sizeof(psa_key_usage_t));
    buffer += sizeof(psa_key_usage_t);
    
    XMEMCPY(buffer, &attributes->policy.alg,
            sizeof(psa_algorithm_t));
    buffer += sizeof(psa_algorithm_t);
    
    XMEMCPY(buffer, &attributes->lifetime, sizeof(psa_key_lifetime_t));
    
    *buffer_length = required_size;
    
    return PSA_SUCCESS;
}

/* Deserialize key attributes from a buffer */
static psa_status_t psa_key_attributes_deserialize(
    const uint8_t* buffer,
    size_t buffer_length,
    psa_key_attributes_t* attributes)
{
    size_t required_size;
    
    /* Check parameters */
    if (buffer == NULL || attributes == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Calculate required size */
    required_size = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                    sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                    sizeof(psa_key_lifetime_t);
    
    /* Check buffer length */
    if (buffer_length < required_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Deserialize key attributes */
    XMEMCPY(&attributes->type, buffer, sizeof(psa_key_type_t));
    buffer += sizeof(psa_key_type_t);
    
    XMEMCPY(&attributes->bits, buffer, sizeof(psa_key_bits_t));
    buffer += sizeof(psa_key_bits_t);
    
    XMEMCPY(&attributes->policy.usage, buffer,
            sizeof(psa_key_usage_t));
    buffer += sizeof(psa_key_usage_t);
    
    XMEMCPY(&attributes->policy.alg, buffer,
            sizeof(psa_algorithm_t));
    buffer += sizeof(psa_algorithm_t);
    
    XMEMCPY(&attributes->lifetime, buffer, sizeof(psa_key_lifetime_t));
    
    return PSA_SUCCESS;
}

psa_status_t wolfpsa_get_key_data(psa_key_id_t key_id,
                                 psa_key_attributes_t* attributes,
                                 uint8_t** key_data,
                                 size_t* key_data_length)
{
    psa_status_t status;
    uint8_t header[sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                   sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                   sizeof(psa_key_lifetime_t) + sizeof(size_t)];
    size_t attr_length;
    int ret;
    void* store = NULL;

    if (key_data == NULL || key_data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *key_data = NULL;
    *key_data_length = 0;

    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_volatile_get(key_id, attributes, key_data, key_data_length);
    if (status == PSA_SUCCESS) {
        return PSA_SUCCESS;
    }

    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                  sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                  sizeof(psa_key_lifetime_t);

    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1, &store);
    if (ret == -4) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    ret = wolfPSA_Store_Read(store, header, (int)(attr_length + sizeof(size_t)));
    if (ret != (int)(attr_length + sizeof(size_t))) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_STORAGE_FAILURE;
    }

    if (attributes != NULL) {
        status = psa_key_attributes_deserialize(header, attr_length, attributes);
        if (status != PSA_SUCCESS) {
            wolfPSA_Store_Close(store);
            return status;
        }
    }

    XMEMCPY(key_data_length, header + attr_length, sizeof(size_t));
    status = wolfpsa_validate_stored_key_data_length(*key_data_length);
    if (status != PSA_SUCCESS) {
        wolfPSA_Store_Close(store);
        return status;
    }

    *key_data = (uint8_t*)XMALLOC(*key_data_length, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (*key_data == NULL) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    ret = wolfPSA_Store_Read(store, *key_data, (int)*key_data_length);
    wolfPSA_Store_Close(store);
    store = NULL;
    if (ret != (int)*key_data_length) {
        wc_ForceZero(*key_data, *key_data_length);
        XFREE(*key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_STORAGE_FAILURE;
    }

    return PSA_SUCCESS;
}

void wolfpsa_forcezero_free_key_data(uint8_t* key_data, size_t key_data_length)
{
    if (key_data != NULL) {
        wc_ForceZero(key_data, key_data_length);
        XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}

/* Import a key into the PSA key storage */
psa_status_t psa_import_key(
    const psa_key_attributes_t* attributes,
    const uint8_t* data,
    size_t data_length,
    psa_key_id_t* key_id)
{
    wolfpsa_trace("psa_import_key(type=0x%08x bits=%u data_len=%zu)",
                  attributes ? (unsigned)attributes->type : 0U,
                  attributes ? (unsigned)attributes->bits : 0U,
                  data_length);
    psa_status_t status;
    uint8_t* buffer = NULL;
    size_t buffer_size;
    size_t attr_length;
    int ret = 0;
    void* store = NULL;
    psa_key_attributes_t attr;
    
    /* Check parameters */
    if (attributes == NULL || data == NULL || key_id == NULL) {
        wolfpsa_debug_import_reason("invalid parameters", attributes, data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Always treat key_id as output-only. */
    *key_id = PSA_KEY_ID_NULL;

    /* Reject lengths that do not fit the int-based storage API or that would
     * overflow the serialized buffer_size computation below. */
    if (data_length > (size_t)INT_MAX) {
        wolfpsa_debug_import_reason("key data length too large", attributes,
                                    data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    attr = *attributes;

    /* Local storage is the only location this build implements. A key whose
     * lifetime names any other location (for example a secure element or
     * vendor location) must be rejected rather than silently written to
     * plaintext local storage. This choke point also covers psa_generate_key,
     * psa_copy_key and psa_key_derivation_output_key, which all store through
     * psa_import_key. */
    if (PSA_KEY_LIFETIME_GET_LOCATION(attr.lifetime) !=
        PSA_KEY_LOCATION_LOCAL_STORAGE) {
        wolfpsa_debug_import_reason("unsupported key lifetime location", &attr,
                                    data_length);
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (attr.policy.alg2 != PSA_ALG_NONE) {
        wolfpsa_debug_import_reason("unsupported secondary algorithm", &attr,
                                    data_length);
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (!wolfpsa_usage_flags_valid(psa_get_key_usage_flags(&attr))) {
        wolfpsa_debug_import_reason("invalid usage flags", &attr, data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (attr.type == PSA_KEY_TYPE_NONE) {
        wolfpsa_debug_import_reason("unsupported key type", &attr, data_length);
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (attr.bits == 0) {
        status = wolfpsa_infer_key_bits(&attr, data, data_length);
        if (status != PSA_SUCCESS) {
            wolfpsa_debug_import_reason("missing key bits", &attr, data_length);
            return status;
        }
    }
    if (attr.type == PSA_KEY_TYPE_CHACHA20 ||
        attr.type == PSA_KEY_TYPE_XCHACHA20) {
        if (attr.bits != 256) {
            wolfpsa_debug_import_reason("invalid ChaCha20/XChaCha20 key bits", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != 32) {
            wolfpsa_debug_import_reason("ChaCha20/XChaCha20 key length must be 32", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (attr.type == PSA_KEY_TYPE_AES) {
        if (attr.bits != 128 && attr.bits != 192 &&
            attr.bits != 256) {
            wolfpsa_debug_import_reason("invalid AES key bits", &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != 16 && data_length != 24 && data_length != 32) {
            wolfpsa_debug_import_reason("invalid AES key length", &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (attr.bits != (psa_key_bits_t)(data_length * 8U)) {
            wolfpsa_debug_import_reason("AES bits/length mismatch", &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (attr.type == PSA_KEY_TYPE_DES) {
        if (data_length == 16) {
            wolfpsa_debug_import_reason("2-key 3DES is not supported", &attr,
                                        data_length);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (data_length != 24) {
            wolfpsa_debug_import_reason("invalid DES key length", &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (attr.bits != (psa_key_bits_t)(data_length * 8U)) {
            wolfpsa_debug_import_reason("DES bits/length mismatch", &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_KEY_TYPE_IS_ML_DSA(attr.type)) {
        if (attr.type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
            if (attr.bits != 128 && attr.bits != 192 && attr.bits != 256) {
                wolfpsa_debug_import_reason("invalid ML-DSA key pair bits", &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != 32) {
                wolfpsa_debug_import_reason("ML-DSA key pair must be 32-byte seed",
                                            &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else {
            /* PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY */
            size_t expected;
            switch (attr.bits) {
                case 128: expected = 1312; break;
                case 192: expected = 1952; break;
                case 256: expected = 2592; break;
                default:
                    wolfpsa_debug_import_reason("invalid ML-DSA public key bits", &attr,
                                                data_length);
                    return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != expected) {
                wolfpsa_debug_import_reason("ML-DSA public key length mismatch", &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    else if (PSA_KEY_TYPE_IS_ML_KEM(attr.type)) {
        if (attr.type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
            if (attr.bits != 512 && attr.bits != 768 && attr.bits != 1024) {
                wolfpsa_debug_import_reason("invalid ML-KEM key pair bits", &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != 64) {
                wolfpsa_debug_import_reason("ML-KEM key pair must be 64-byte seed",
                                            &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else {
            /* PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY */
            size_t expected;
            switch (attr.bits) {
                case  512: expected =  800; break;
                case  768: expected = 1184; break;
                case 1024: expected = 1568; break;
                default:
                    wolfpsa_debug_import_reason("invalid ML-KEM public key bits", &attr,
                                                data_length);
                    return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != expected) {
                wolfpsa_debug_import_reason("ML-KEM public key length mismatch", &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    else if (attr.type == PSA_KEY_TYPE_LMS_PUBLIC_KEY) {
        size_t expected;
        switch (attr.bits) {
            case 192: expected = 48; break;
            case 256: expected = 56; break;
            default:
                wolfpsa_debug_import_reason("invalid LMS public key bits", &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != expected) {
            wolfpsa_debug_import_reason("LMS public key length mismatch", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (attr.type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        size_t expected;
        switch (attr.bits) {
            case 192: expected = 52; break;
            case 256: expected = 60; break;
            default:
                wolfpsa_debug_import_reason("invalid HSS public key bits", &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != expected) {
            wolfpsa_debug_import_reason("HSS public key length mismatch", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (attr.type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY ||
             attr.type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        size_t expected;
        switch (attr.bits) {
            case 192: expected = 52; break;
            case 256: expected = 68; break;
            default:
                wolfpsa_debug_import_reason("invalid XMSS/XMSS^MT public key bits",
                                            &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != expected) {
            wolfpsa_debug_import_reason("XMSS/XMSS^MT public key length mismatch",
                                        &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    /* Check if the key storage is initialized */
    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }
    
    {
        psa_key_id_t attr_id = (psa_key_id_t)psa_get_key_id(&attr);
        if (attr_id != PSA_KEY_ID_NULL) {
            *key_id = attr_id;
        }
        else {
            /* Auto-assign implementation key ids from the vendor range so
             * they cannot collide with caller-specified persistent ids, which
             * the PSA API reserves to the user range. A collision would let an
             * auto-assigned volatile key shadow a persistent record on read and
             * survive psa_destroy_key() on disk. */
            if (g_next_key_id < PSA_KEY_ID_VENDOR_MIN ||
                g_next_key_id > PSA_KEY_ID_VENDOR_MAX) {
                return PSA_ERROR_INSUFFICIENT_STORAGE;
            }
            *key_id = g_next_key_id++;
        }
    }

    /* Allocate buffer for key data and attributes */
    buffer_size = data_length + sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                 sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                 sizeof(psa_key_lifetime_t) + sizeof(size_t);
    
    buffer = (uint8_t*)XMALLOC(buffer_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    
    /* Serialize key attributes */
    status = psa_key_attributes_serialize(&attr, buffer, buffer_size, &attr_length);
    if (status != PSA_SUCCESS) {
        XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }
    
    /* Store key data length */
    XMEMCPY(buffer + attr_length, &data_length, sizeof(size_t));
    
    /* Store key data */
    XMEMCPY(buffer + attr_length + sizeof(size_t), data, data_length);
    
    if (PSA_KEY_LIFETIME_IS_VOLATILE(attr.lifetime)) {
        status = wolfpsa_volatile_store(*key_id, &attr, data, data_length);
        if (status == PSA_SUCCESS) {
            ret = (int)(attr_length + sizeof(size_t) + data_length);
        }
    }
    else {
        /* The PSA Crypto API requires psa_import_key() to fail with
         * PSA_ERROR_ALREADY_EXISTS when a persistent key already exists with
         * the requested id; the volatile path enforces the same above. Probe
         * for an existing record before opening a write handle, otherwise the
         * atomic rename in wolfPSA_Store_Close() would silently destroy the
         * previously stored key. */
        ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)*key_id, 0,
                                 1, &store);
        if (ret == 0) {
            wolfPSA_Store_Close(store);
            store = NULL;
            wc_ForceZero(buffer, buffer_size);
            XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *key_id = PSA_KEY_ID_NULL;
            return PSA_ERROR_ALREADY_EXISTS;
        }

        /* Open and write key to persistent storage */
        ret = wolfPSA_Store_OpenSz(WOLFPSA_STORE_KEY, (unsigned long)*key_id, 0,
                                  0, (int)data_length, &store);
        if (ret == 0) {
            ret = wolfPSA_Store_Write(store, buffer,
                                      (int)(attr_length + sizeof(size_t) + data_length));
            wolfPSA_Store_Close(store);
            store = NULL;
        }
    }
    
    wc_ForceZero(buffer, buffer_size);
    XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (status != PSA_SUCCESS) {
        *key_id = PSA_KEY_ID_NULL;
        return status;
    }
    
    if (ret < 0 || (size_t)ret != (attr_length + sizeof(size_t) + data_length)) {
        *key_id = PSA_KEY_ID_NULL;
        return PSA_ERROR_STORAGE_FAILURE;
    }
    
    return PSA_SUCCESS;
}

/* Generate a key and store it in the PSA key storage */
psa_status_t psa_generate_key(
    const psa_key_attributes_t* attributes,
    psa_key_id_t* key_id)
{
    wolfpsa_trace("psa_generate_key(type=0x%08x bits=%u)",
                  attributes ? (unsigned)attributes->type : 0U,
                  attributes ? (unsigned)attributes->bits : 0U);
    psa_status_t status;
    psa_key_type_t key_type;
    psa_key_bits_t key_bits;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;

    if (attributes == NULL || key_id == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = attributes->type;
    key_bits = attributes->bits;

    if (key_bits == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!wolfpsa_usage_flags_valid(psa_get_key_usage_flags(attributes))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type) ||
        key_type == PSA_KEY_TYPE_HMAC ||
        key_type == PSA_KEY_TYPE_AES ||
        key_type == PSA_KEY_TYPE_DES ||
        key_type == PSA_KEY_TYPE_CHACHA20 ||
        key_type == PSA_KEY_TYPE_XCHACHA20) {
        key_data_length = PSA_BITS_TO_BYTES(key_bits);
        if (key_data_length == 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        key_data = (uint8_t *)XMALLOC(key_data_length, NULL,
                                      DYNAMIC_TYPE_TMP_BUFFER);
        if (key_data == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        status = psa_generate_random(key_data, key_data_length);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(key_data, key_data_length);
            XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return status;
        }

        status = psa_import_key(attributes, key_data, key_data_length, key_id);
        wc_ForceZero(key_data, key_data_length);
        XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    if (key_type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
#ifndef NO_RSA
        size_t priv_buf_size = PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits);
        size_t priv_len = 0;

        key_data = (uint8_t *)XMALLOC(priv_buf_size, NULL,
                                      DYNAMIC_TYPE_TMP_BUFFER);
        if (key_data == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        status = psa_asymmetric_generate_key_rsa(key_type, key_bits,
                                                 key_data, priv_buf_size,
                                                 &priv_len,
                                                 NULL, 0, NULL);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(key_data, priv_buf_size);
            XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return status;
        }

        status = psa_import_key(attributes, key_data, priv_len, key_id);
        wc_ForceZero(key_data, priv_buf_size);
        XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
#ifdef HAVE_ECC
        psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
        size_t priv_buf_size = PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits);
        size_t pub_buf_size = PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits);
        size_t priv_len = 0;
        size_t pub_len = 0;
        uint8_t *pub_buf = NULL;

        if (family == PSA_ECC_FAMILY_TWISTED_EDWARDS) {
            if (key_bits == 255) {
#ifdef HAVE_ED25519
                priv_buf_size = PSA_BITS_TO_BYTES(key_bits) + 1U;
#else
                return PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else if (key_bits == 448) {
#ifdef HAVE_ED448
                priv_buf_size = PSA_BITS_TO_BYTES(key_bits) + 1U;
#else
                return PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else if (family == PSA_ECC_FAMILY_MONTGOMERY) {
            if (key_bits != 255 && key_bits != 448) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            pub_buf_size = PSA_BITS_TO_BYTES(key_bits);
        }

        key_data = (uint8_t *)XMALLOC(priv_buf_size, NULL,
                                      DYNAMIC_TYPE_TMP_BUFFER);
        if (key_data == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        pub_buf = (uint8_t *)XMALLOC(pub_buf_size, NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
        if (pub_buf == NULL) {
            wc_ForceZero(key_data, priv_buf_size);
            XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        if (family == PSA_ECC_FAMILY_TWISTED_EDWARDS) {
            if (key_bits == 255) {
#ifdef HAVE_ED25519
                status = psa_asymmetric_generate_key_ed25519(key_type, key_bits,
                                                             key_data, priv_buf_size,
                                                             &priv_len,
                                                             pub_buf, pub_buf_size,
                                                             &pub_len);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else if (key_bits == 448) {
#ifdef HAVE_ED448
                status = psa_asymmetric_generate_key_ed448(key_type, key_bits,
                                                           key_data, priv_buf_size,
                                                           &priv_len,
                                                           pub_buf, pub_buf_size,
                                                           &pub_len);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else if (family == PSA_ECC_FAMILY_MONTGOMERY) {
            if (key_bits == 255) {
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT) && \
    defined(HAVE_CURVE25519_KEY_EXPORT)
                status = psa_asymmetric_generate_key_x25519(
                    key_type, key_bits, key_data, priv_buf_size, &priv_len,
                    pub_buf, pub_buf_size, &pub_len);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else if (key_bits == 448) {
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
    defined(HAVE_CURVE448_KEY_EXPORT)
                status = psa_asymmetric_generate_key_x448(
                    key_type, key_bits, key_data, priv_buf_size, &priv_len,
                    pub_buf, pub_buf_size, &pub_len);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else {
            status = psa_asymmetric_generate_key_ecc(key_type, key_bits,
                                                     key_data, priv_buf_size,
                                                     &priv_len,
                                                     pub_buf, pub_buf_size,
                                                     &pub_len);
        }
        XFREE(pub_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(key_data, priv_buf_size);
            XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return status;
        }

        status = psa_import_key(attributes, key_data, priv_len, key_id);
        wc_ForceZero(key_data, priv_buf_size);
        XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

#if defined(WOLFSSL_HAVE_MLDSA)
    if (key_type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        uint8_t seed[WOLFPSA_MLDSA_SEED_SIZE];

        if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        status = wolfpsa_mldsa_generate_seed((size_t)key_bits, seed);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(seed, sizeof(seed));
            return status;
        }

        status = psa_import_key(attributes, seed, sizeof(seed), key_id);
        wc_ForceZero(seed, sizeof(seed));
        return status;
    }
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_MLKEM)
    if (key_type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
        uint8_t seed[WOLFPSA_MLKEM_SEED_SIZE];

        if (key_bits != 512 && key_bits != 768 && key_bits != 1024) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        status = wolfpsa_mlkem_generate_seed((size_t)key_bits, seed);
        if (status != PSA_SUCCESS) {
            wc_ForceZero(seed, sizeof(seed));
            return status;
        }

        status = psa_import_key(attributes, seed, sizeof(seed), key_id);
        wc_ForceZero(seed, sizeof(seed));
        return status;
    }
#endif /* WOLFSSL_HAVE_MLKEM */

    return PSA_ERROR_NOT_SUPPORTED;
}

/* Destroy a key from the PSA key storage */
psa_status_t psa_destroy_key(psa_key_id_t key_id)
{
    psa_status_t status;
    int ret;

    if (key_id == PSA_KEY_ID_NULL) {
        return PSA_SUCCESS;
    }
    
    /* Check if the key storage is initialized */
    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_volatile_remove(key_id);
    if (status == PSA_SUCCESS) {
        return PSA_SUCCESS;
    }

    /* Remove key from persistent storage */
    ret = wolfPSA_Store_Remove(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0);
    if (ret == -4) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    
    return PSA_SUCCESS;
}

/* Export a key from the PSA key storage */
psa_status_t psa_export_key(
    psa_key_id_t key_id,
    uint8_t* data,
    size_t data_size,
    size_t* data_length)
{
    psa_status_t status;
    uint8_t header[sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                   sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                   sizeof(psa_key_lifetime_t) + sizeof(size_t)];
    size_t key_data_length;
    size_t attr_length;
    int ret;
    void* store = NULL;
    
    /* Check parameters */
    if (data == NULL || data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Check if the key storage is initialized */
    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    {
        psa_key_attributes_t vol_attr = PSA_KEY_ATTRIBUTES_INIT;
        uint8_t* vol_data = NULL;
        size_t vol_len = 0;

        status = wolfpsa_volatile_get(key_id, &vol_attr, &vol_data, &vol_len);
        if (status == PSA_SUCCESS) {
            if ((psa_get_key_usage_flags(&vol_attr) &
                 PSA_KEY_USAGE_EXPORT) == 0) {
                wolfpsa_forcezero_free_key_data(vol_data, vol_len);
                return PSA_ERROR_NOT_PERMITTED;
            }
            if (data_size < vol_len) {
                wolfpsa_forcezero_free_key_data(vol_data, vol_len);
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            XMEMCPY(data, vol_data, vol_len);
            *data_length = vol_len;
            wolfpsa_forcezero_free_key_data(vol_data, vol_len);
            return PSA_SUCCESS;
        }
    }
    
    /* Get key info */
    psa_key_attributes_t attributes;
    status = psa_get_key_attributes(key_id, &attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }
    
    /* Check if the key can be exported */
    if ((psa_get_key_usage_flags(&attributes) &
         PSA_KEY_USAGE_EXPORT) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    
    /* Calculate attribute length */
    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                 sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                 sizeof(psa_key_lifetime_t);
    
    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1, &store);
    if (ret == -4) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    ret = wolfPSA_Store_Read(store, header, (int)(attr_length + sizeof(size_t)));
    if (ret != (int)(attr_length + sizeof(size_t))) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_STORAGE_FAILURE;
    }

    /* Get key data length */
    XMEMCPY(&key_data_length, header + attr_length, sizeof(size_t));
    status = wolfpsa_validate_stored_key_data_length(key_data_length);
    if (status != PSA_SUCCESS) {
        wolfPSA_Store_Close(store);
        return status;
    }
    
    /* Check if the output buffer is large enough */
    if (data_size < key_data_length) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Read key data */
    ret = wolfPSA_Store_Read(store, data, (int)key_data_length);
    wolfPSA_Store_Close(store);
    store = NULL;
    if (ret != (int)key_data_length) {
        /* A short/failed read may have left partial key material in the
         * caller-owned buffer; zeroize it like the sibling read paths. */
        wc_ForceZero(data, key_data_length);
        *data_length = 0;
        return PSA_ERROR_STORAGE_FAILURE;
    }
    *data_length = key_data_length;
    
    return PSA_SUCCESS;
}

/* Export a public key from the PSA key storage */
psa_status_t psa_export_public_key(
    psa_key_id_t key_id,
    uint8_t* data,
    size_t data_size,
    size_t* data_length)
{
    wolfpsa_trace("psa_export_public_key(key=%u)", (unsigned)key_id);
    psa_status_t status;
    uint8_t header[sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                   sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                   sizeof(psa_key_lifetime_t) + sizeof(size_t)];
    psa_key_attributes_t attributes;
    size_t key_data_length;
    size_t attr_length;
    uint8_t* key_data = NULL;
    int ret;
    void* store = NULL;
    int use_volatile = 0;

    if (data == NULL || data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    {
        psa_key_attributes_t vol_attr = PSA_KEY_ATTRIBUTES_INIT;
        size_t vol_len = 0;

        status = wolfpsa_volatile_get(key_id, &vol_attr, &key_data, &vol_len);
        if (status == PSA_SUCCESS) {
            attributes = vol_attr;
            key_data_length = vol_len;
            use_volatile = 1;
        }
        else {
            status = psa_get_key_attributes(key_id, &attributes);
            if (status != PSA_SUCCESS) {
                return status;
            }
        }
    }

    if (!PSA_KEY_TYPE_IS_RSA(attributes.type) &&
        !PSA_KEY_TYPE_IS_ECC(attributes.type) &&
        !PSA_KEY_TYPE_IS_ML_DSA(attributes.type) &&
        !PSA_KEY_TYPE_IS_ML_KEM(attributes.type) &&
        attributes.type != PSA_KEY_TYPE_LMS_PUBLIC_KEY &&
        attributes.type != PSA_KEY_TYPE_HSS_PUBLIC_KEY &&
        attributes.type != PSA_KEY_TYPE_XMSS_PUBLIC_KEY &&
        attributes.type != PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        if (use_volatile) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        }
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!use_volatile) {
        attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                      sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                      sizeof(psa_key_lifetime_t);

        ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1,
                                 &store);
        if (ret == -4) {
            return PSA_ERROR_INVALID_HANDLE;
        }
        if (ret != 0) {
            return PSA_ERROR_STORAGE_FAILURE;
        }

        ret = wolfPSA_Store_Read(store, header,
                                 (int)(attr_length + sizeof(size_t)));
        if (ret != (int)(attr_length + sizeof(size_t))) {
            wolfPSA_Store_Close(store);
            return PSA_ERROR_STORAGE_FAILURE;
        }

        XMEMCPY(&key_data_length, header + attr_length, sizeof(size_t));
        status = wolfpsa_validate_stored_key_data_length(key_data_length);
        if (status != PSA_SUCCESS) {
            wolfPSA_Store_Close(store);
            return status;
        }
        key_data = (uint8_t*)XMALLOC(key_data_length, NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
        if (key_data == NULL) {
            wolfPSA_Store_Close(store);
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        ret = wolfPSA_Store_Read(store, key_data, (int)key_data_length);
        wolfPSA_Store_Close(store);
        store = NULL;
        if (ret != (int)key_data_length) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_STORAGE_FAILURE;
        }
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
    #ifndef NO_RSA
        if (attributes.type == PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
            if (data_size < key_data_length) {
                status = PSA_ERROR_BUFFER_TOO_SMALL;
            }
            else {
                XMEMCPY(data, key_data, key_data_length);
                *data_length = key_data_length;
                status = PSA_SUCCESS;
            }
        }
        else {
            RsaKey* rsa = NULL;
            word32 idx = 0;
            word32 n_sz = 0;
            word32 e_sz = 0;
            byte* n = NULL;
            byte* e = NULL;
            size_t n_int_size;
            size_t e_int_size;
            size_t seq_len;
            size_t total_len;
            uint8_t* out = data;

            rsa = wc_NewRsaKey(NULL, wolfPSA_GetDefaultDevID(), &ret);
            if (rsa == NULL) {
                if (ret == 0) {
                    ret = MEMORY_E;
                }
                status = psa_wc_error_to_psa_status(ret);
            }
            else {
                ret = wc_RsaPrivateKeyDecode(key_data, &idx, rsa,
                                             (word32)key_data_length);
                if (ret != 0) {
                    wc_DeleteRsaKey(rsa, &rsa);
                    status = psa_wc_error_to_psa_status(ret);
                }
                else {
                    n_sz = (word32)wc_RsaEncryptSize(rsa);
                    e_sz = n_sz;
                    n = (byte*)XMALLOC(n_sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    e = (byte*)XMALLOC(e_sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    if (n == NULL || e == NULL) {
                        if (n != NULL) {
                            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        }
                        if (e != NULL) {
                            XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        }
                        wc_DeleteRsaKey(rsa, &rsa);
                        status = PSA_ERROR_INSUFFICIENT_MEMORY;
                    }
                    else {
                        ret = wc_RsaFlattenPublicKey(rsa, e, &e_sz, n, &n_sz);
                        wc_DeleteRsaKey(rsa, &rsa);
                        if (ret != 0) {
                            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            status = psa_wc_error_to_psa_status(ret);
                        }
                        else {
                            n_int_size = psa_der_int_size(n, (size_t)n_sz);
                            e_int_size = psa_der_int_size(e, (size_t)e_sz);
                            seq_len = n_int_size + e_int_size;
                            total_len = 1 + psa_der_len_size(seq_len) + seq_len;
                            if (data_size < total_len) {
                                status = PSA_ERROR_BUFFER_TOO_SMALL;
                            }
                            else {
                                *out++ = 0x30;
                                out += psa_der_write_len(out, seq_len);
                                out += psa_der_write_int(out, n, (size_t)n_sz);
                                out += psa_der_write_int(out, e, (size_t)e_sz);
                                *data_length = total_len;
                                status = PSA_SUCCESS;
                            }

                            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        }
                    }
                }
            }
        }
    #else
        status = PSA_ERROR_NOT_SUPPORTED;
    #endif
    }
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
    #if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && defined(HAVE_ECC_KEY_IMPORT)
        if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(attributes.type)) {
            if (data_size < key_data_length) {
                status = PSA_ERROR_BUFFER_TOO_SMALL;
            }
            else {
                XMEMCPY(data, key_data, key_data_length);
                *data_length = key_data_length;
                status = PSA_SUCCESS;
            }
        }
        else {
            psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(attributes.type);

            if (family == PSA_ECC_FAMILY_TWISTED_EDWARDS) {
            #ifdef HAVE_ED25519
                if (attributes.bits == 255) {
                    status = psa_asymmetric_export_public_key_ed25519(
                        attributes.type, attributes.bits, key_data,
                        key_data_length, data, data_size, data_length);
                }
                else
            #endif
            #ifdef HAVE_ED448
                if (attributes.bits == 448) {
                    status = psa_asymmetric_export_public_key_ed448(
                        attributes.type, attributes.bits, key_data,
                        key_data_length, data, data_size, data_length);
                }
                else
            #endif
                {
                    status = PSA_ERROR_NOT_SUPPORTED;
                }
            }
            else if (family == PSA_ECC_FAMILY_MONTGOMERY) {
            #if defined(HAVE_CURVE25519) && \
                defined(HAVE_CURVE25519_KEY_IMPORT) && \
                defined(HAVE_CURVE25519_KEY_EXPORT)
                if (attributes.bits == 255) {
                    status = psa_asymmetric_export_public_key_x25519(
                        attributes.type, attributes.bits, key_data,
                        key_data_length, data, data_size, data_length);
                }
                else
            #endif
            #if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
                defined(HAVE_CURVE448_KEY_EXPORT)
                if (attributes.bits == 448) {
                    status = psa_asymmetric_export_public_key_x448(
                        attributes.type, attributes.bits, key_data,
                        key_data_length, data, data_size, data_length);
                }
                else
            #endif
                {
                    status = PSA_ERROR_NOT_SUPPORTED;
                }
            }
            else {
                status = psa_asymmetric_export_public_key_ecc(
                    attributes.type, attributes.bits, key_data,
                    key_data_length, data, data_size, data_length);
            }
        }
    #else
        status = PSA_ERROR_NOT_SUPPORTED;
    #endif
    }
    else {
        /* PQC key types — reached when neither RSA nor ECC matched the type
         * gate above. */
#if defined(WOLFSSL_HAVE_MLDSA)
        if (PSA_KEY_TYPE_IS_ML_DSA(attributes.type)) {
            if (attributes.type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
                /* Public key already stored as raw bytes — copy directly. */
                if (data_size < key_data_length) {
                    status = PSA_ERROR_BUFFER_TOO_SMALL;
                }
                else {
                    XMEMCPY(data, key_data, key_data_length);
                    *data_length = key_data_length;
                    status = PSA_SUCCESS;
                }
            }
            else {
                /* Key pair: stored as 32-byte seed — derive public key. */
                status = wolfpsa_mldsa_export_public((size_t)attributes.bits,
                                                     key_data, data, data_size,
                                                     data_length);
            }
        }
        else
#endif /* WOLFSSL_HAVE_MLDSA */
#if defined(WOLFSSL_HAVE_MLKEM)
        if (PSA_KEY_TYPE_IS_ML_KEM(attributes.type)) {
            if (attributes.type == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY) {
                /* Public key already stored as raw bytes — copy directly. */
                if (data_size < key_data_length) {
                    status = PSA_ERROR_BUFFER_TOO_SMALL;
                }
                else {
                    XMEMCPY(data, key_data, key_data_length);
                    *data_length = key_data_length;
                    status = PSA_SUCCESS;
                }
            }
            else {
                /* Key pair: stored as 64-byte seed — derive public key. */
                status = wolfpsa_mlkem_export_public((size_t)attributes.bits,
                                                     key_data, data, data_size,
                                                     data_length);
            }
        }
        else
#endif /* WOLFSSL_HAVE_MLKEM */
        if (attributes.type == PSA_KEY_TYPE_LMS_PUBLIC_KEY ||
            attributes.type == PSA_KEY_TYPE_HSS_PUBLIC_KEY ||
            attributes.type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY ||
            attributes.type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
            /* Public-key-only types: stored bytes are the raw public key. */
            if (data_size < key_data_length) {
                status = PSA_ERROR_BUFFER_TOO_SMALL;
            }
            else {
                XMEMCPY(data, key_data, key_data_length);
                *data_length = key_data_length;
                status = PSA_SUCCESS;
            }
        }
        else {
            /* Key type admitted by the gate above but its backend is not
             * compiled in (for example ML-DSA/ML-KEM when the corresponding
             * WOLFSSL_HAVE_* macro is undefined). */
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

/* Get key attributes from the PSA key storage */
psa_status_t psa_get_key_attributes(
    psa_key_id_t key_id,
    psa_key_attributes_t* attributes)
{
    psa_status_t status;
    uint8_t buffer[sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                   sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                   sizeof(psa_key_lifetime_t) + sizeof(size_t)];
    size_t attr_length;
    int ret;
    void* store = NULL;
    
    /* Check parameters */
    if (attributes == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Check if the key storage is initialized */
    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_volatile_get_attributes(key_id, attributes);
    if (status == PSA_SUCCESS) {
        return PSA_SUCCESS;
    }
    
    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                  sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                  sizeof(psa_key_lifetime_t);

    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1, &store);
    if (ret == -4) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    ret = wolfPSA_Store_Read(store, buffer, (int)(attr_length + sizeof(size_t)));
    wolfPSA_Store_Close(store);
    store = NULL;
    if (ret != (int)(attr_length + sizeof(size_t))) {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    /* Deserialize key attributes */
    status = psa_key_attributes_deserialize(buffer, attr_length, attributes);
    return status;
}

/* Copy a key in the PSA key storage */
psa_status_t psa_copy_key(
    psa_key_id_t source_key,
    const psa_key_attributes_t* attributes,
    psa_key_id_t* target_key)
{
    psa_status_t status;
    uint8_t header[sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                   sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                   sizeof(psa_key_lifetime_t) + sizeof(size_t)];
    uint8_t* buffer = NULL;
    size_t key_data_length;
    size_t attr_length;
    int ret;
    void* store = NULL;
    psa_key_attributes_t src_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t dst_attr;
    
    /* Check parameters */
    if (attributes == NULL || target_key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Check if the key storage is initialized */
    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    {
        psa_key_attributes_t vol_attr = PSA_KEY_ATTRIBUTES_INIT;
        uint8_t* key_data = NULL;
        key_data_length = 0;

        status = wolfpsa_volatile_get(source_key, &vol_attr,
                                      &key_data, &key_data_length);
        if (status == PSA_SUCCESS) {
            dst_attr = *attributes;

            if ((psa_get_key_usage_flags(&vol_attr) &
                 PSA_KEY_USAGE_COPY) == 0) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_NOT_PERMITTED;
            }

            if (attributes->type != 0 && attributes->type != vol_attr.type) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (attributes->bits != 0 && attributes->bits != vol_attr.bits) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (attributes->policy.alg != psa_get_key_algorithm(&vol_attr)) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (attributes->lifetime != vol_attr.lifetime) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            dst_attr.type = (dst_attr.type == 0) ? vol_attr.type : dst_attr.type;
            dst_attr.bits = (dst_attr.bits == 0) ? vol_attr.bits : dst_attr.bits;
            dst_attr.policy.usage = psa_get_key_usage_flags(&vol_attr) &
                                    psa_get_key_usage_flags(&dst_attr);

            status = psa_import_key(&dst_attr, key_data,
                                    key_data_length, target_key);
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return status;
        }
    }
    
    /* Calculate attribute length */
    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                 sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                 sizeof(psa_key_lifetime_t);
    
    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)source_key, 0, 1, &store);
    if (ret == -4) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    ret = wolfPSA_Store_Read(store, header, (int)(attr_length + sizeof(size_t)));
    if (ret != (int)(attr_length + sizeof(size_t))) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_STORAGE_FAILURE;
    }

    status = psa_key_attributes_deserialize(header, attr_length, &src_attr);
    if (status != PSA_SUCCESS) {
        wolfPSA_Store_Close(store);
        return status;
    }

    if ((psa_get_key_usage_flags(&src_attr) & PSA_KEY_USAGE_COPY) == 0) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (attributes->type != 0 && attributes->type != src_attr.type) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (attributes->bits != 0 && attributes->bits != src_attr.bits) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (attributes->policy.alg != psa_get_key_algorithm(&src_attr)) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (attributes->lifetime != src_attr.lifetime) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    dst_attr = *attributes;
    dst_attr.type = (dst_attr.type == 0) ? src_attr.type : dst_attr.type;
    dst_attr.bits = (dst_attr.bits == 0) ? src_attr.bits : dst_attr.bits;
    dst_attr.policy.usage = psa_get_key_usage_flags(&src_attr) &
                            psa_get_key_usage_flags(&dst_attr);

    XMEMCPY(&key_data_length, header + attr_length, sizeof(size_t));
    status = wolfpsa_validate_stored_key_data_length(key_data_length);
    if (status != PSA_SUCCESS) {
        wolfPSA_Store_Close(store);
        return status;
    }
    buffer = (uint8_t*)XMALLOC(key_data_length, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    ret = wolfPSA_Store_Read(store, buffer, (int)key_data_length);
    wolfPSA_Store_Close(store);
    store = NULL;
    if (ret != (int)key_data_length) {
        wolfpsa_forcezero_free_key_data(buffer, key_data_length);
        return PSA_ERROR_STORAGE_FAILURE;
    }
    
    /* Import the key with new attributes */
    status = psa_import_key(&dst_attr, buffer, key_data_length, target_key);
    
    wolfpsa_forcezero_free_key_data(buffer, key_data_length);
    
    return status;
}

/* Check whether a key supports a given algorithm and usage combination.
 *
 * PSA Crypto API 1.4 semantics:
 *  - Returns PSA_SUCCESS iff the key exists and its policy permits using
 *    algorithm 'alg' with ALL of the requested usage flags.
 *  - alg == PSA_ALG_NONE: skip algorithm check (only usage is validated).
 *  - Wildcard-hash policy (PSA_ALG_ANY_HASH in key policy) authorises any
 *    concrete hash-and-sign algorithm of the same base family.
 *  - No key material is loaded.
 */
psa_status_t psa_check_key_usage(psa_key_id_t key,
                                 psa_algorithm_t alg,
                                 psa_key_usage_t usage)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;

    wolfpsa_trace("psa_check_key_usage(key=%u alg=0x%08x usage=0x%08x)",
                  (unsigned)key, (unsigned)alg, (unsigned)usage);

    status = psa_get_key_attributes(key, &attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & usage) != usage) {
        psa_reset_key_attributes(&attributes);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (alg != PSA_ALG_NONE) {
        key_alg = psa_get_key_algorithm(&attributes);

        /* A key with no permitted algorithm cannot be used for any
         * cryptographic operation. */
        if (key_alg == PSA_ALG_NONE) {
            psa_reset_key_attributes(&attributes);
            return PSA_ERROR_NOT_PERMITTED;
        }

        /* Exact match is always accepted. Otherwise apply the ANY_HASH
         * wildcard rule: a sign-hash policy using PSA_ALG_ANY_HASH authorises
         * any concrete hash-and-sign algorithm of the same base family. */
        if (key_alg != alg) {
            int alg_ok = 0;

            if (PSA_ALG_IS_SIGN_HASH(alg) &&
                PSA_ALG_SIGN_GET_HASH(key_alg) == PSA_ALG_ANY_HASH &&
                PSA_ALG_SIGN_GET_HASH(alg) != PSA_ALG_ANY_HASH &&
                ((key_alg & ~PSA_ALG_HASH_MASK) == (alg & ~PSA_ALG_HASH_MASK))) {
                alg_ok = 1;
            }

            if (!alg_ok) {
                psa_reset_key_attributes(&attributes);
                return PSA_ERROR_NOT_PERMITTED;
            }
        }
    }

    psa_reset_key_attributes(&attributes);
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
