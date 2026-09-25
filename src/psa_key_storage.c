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

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <psa_key_storage.h>
#include <psa_store.h>
#include "psa_trace.h"
#include "psa_lock.h"
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

/* Global lock guarding all shared key-store state above (g_volatile_keys,
 * g_next_key_id, g_key_storage_initialized). No-op unless WOLFPSA_THREAD_SAFE.
 * See psa_lock.h. */
WOLFPSA_DEFINE_LOCK();

#if defined(WOLFPSA_THREAD_SAFE)
/* One-time creation of the global key-store mutex (WOLFPSA_LOCK_INIT). The plain
 * flag guard is safe under the PSA contract that psa_crypto_init() runs before
 * any concurrent PSA use, so no two threads reach wc_InitMutex() at once. */
static int g_wolfpsa_lock_ready = 0;

int wolfpsa_lock_ensure_init(void)
{
    int ret = 0;

    if (!g_wolfpsa_lock_ready) {
        ret = wc_InitMutex(&wolfpsa_global_mutex);
        if (ret == 0) {
            g_wolfpsa_lock_ready = 1;
        }
    }
    return ret;
}
#endif /* WOLFPSA_THREAD_SAFE */

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
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && defined( \
    HAVE_ECC_KEY_IMPORT)
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

static psa_status_t wolfpsa_validate_stored_key_data_length(size_t
                                                            key_data_length)
{
    if (key_data_length == 0 || key_data_length > (size_t)INT_MAX) {
        return PSA_ERROR_DATA_INVALID;
    }

    return PSA_SUCCESS;
}

/* Map a failing wolfPSA_Store_Open()/wolfPSA_Store_OpenSz() return onto a PSA
 * status. A store context allocation failure (MEMORY_E) is runtime memory
 * exhaustion, not a loss of keystore integrity, so it must not be reported as
 * PSA_ERROR_STORAGE_FAILURE. Callers handle WOLFPSA_STORE_NOT_AVAILABLE (the
 * record is absent) themselves. */
static psa_status_t wolfpsa_store_open_status(int ret)
{
    if (ret == MEMORY_E) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    return PSA_ERROR_STORAGE_FAILURE;
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
        /* Raw x-coordinate only: Curve25519 is 32 bytes, X448 is 56 bytes
         * (RFC 7748 s.5). */
        switch (length_bytes) {
        case 32: return 255;
        case 56: return 448;
        default: return 0;
        }

    case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        /* Full point encoding: Ed25519 is 32 bytes, Ed448 is 57 bytes
         * (RFC 8032 s.5.2.5/s.5.2.6). The 57th byte carries the sign of x. */
        switch (length_bytes) {
        case 32: return 255;
        case 57: return 448;
        default: return 0;
        }

    default:
        return 0;
    }
}

/* The coordinate (public) or scalar (private) size in bytes for a curve, or 0
 * when wolfPSA has no entry for this family/size pair. The inverse of
 * wolfpsa_ecc_bits_from_length(): import needs it to tell "this curve is not
 * supported" (PSA_ERROR_NOT_SUPPORTED) from "the data does not match the
 * curve you declared" (PSA_ERROR_INVALID_ARGUMENT). */
static size_t wolfpsa_ecc_length_from_bits(psa_ecc_family_t family,
                                           psa_key_bits_t bits)
{
    switch (family) {
    case PSA_ECC_FAMILY_SECP_R1:
        switch (bits) {
        case 192: return 24;
        case 224: return 28;
        case 256: return 32;
        case 384: return 48;
        case 521: return 66;
        default: return 0;
        }

    case PSA_ECC_FAMILY_SECP_K1:
        switch (bits) {
        case 192: return 24;
        case 224: return 28;
        case 256: return 32;
        default: return 0;
        }

    case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
        switch (bits) {
        case 256: return 32;
        case 384: return 48;
        case 512: return 64;
        default: return 0;
        }

    case PSA_ECC_FAMILY_MONTGOMERY:
        switch (bits) {
        case 255: return 32;
        case 448: return 56;
        default: return 0;
        }

    case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        switch (bits) {
        case 255: return 32;
        case 448: return 57;
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
                                           const psa_key_attributes_t*
                                           attributes,
                                           const uint8_t* data,
                                           size_t data_length)
{
    wolfpsa_volatile_key_node* node;
    psa_status_t st = PSA_SUCCESS;

    WOLFPSA_LOCK();

    if (attributes == NULL || data == NULL || data_length == 0) {
        st = PSA_ERROR_INVALID_ARGUMENT;
    }
    else if (wolfpsa_volatile_find(key_id) != NULL) {
        st = PSA_ERROR_ALREADY_EXISTS;
    }
    else {
        node = (wolfpsa_volatile_key_node*)XMALLOC(sizeof(*node), NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
        if (node == NULL) {
            st = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        else {
            XMEMSET(node, 0, sizeof(*node));
            node->data = (uint8_t*)XMALLOC(data_length, NULL,
                                           DYNAMIC_TYPE_TMP_BUFFER);
            if (node->data == NULL) {
                XFREE(node, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                st = PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            else {
                XMEMCPY(node->data, data, data_length);
                node->data_length = data_length;
                node->attributes = *attributes;
                node->id = key_id;

                node->next = g_volatile_keys;
                g_volatile_keys = node;
            }
        }
    }

    WOLFPSA_UNLOCK();
    return st;
}

static psa_status_t wolfpsa_volatile_remove(psa_key_id_t key_id)
{
    wolfpsa_volatile_key_node* cur;
    wolfpsa_volatile_key_node* prev = NULL;
    psa_status_t st = PSA_ERROR_INVALID_HANDLE;

    WOLFPSA_LOCK();

    cur = g_volatile_keys;
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
            st = PSA_SUCCESS;
            break;
        }
        prev = cur;
        cur = cur->next;
    }

    WOLFPSA_UNLOCK();
    return st;
}

static psa_status_t wolfpsa_volatile_get(psa_key_id_t key_id,
                                         psa_key_attributes_t* attributes,
                                         uint8_t** key_data,
                                         size_t* key_data_length)
{
    wolfpsa_volatile_key_node* node;
    psa_status_t st = PSA_SUCCESS;

    if (key_data == NULL || key_data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *key_data = NULL;
    *key_data_length = 0;

    WOLFPSA_LOCK();

    node = wolfpsa_volatile_find(key_id);
    if (node == NULL) {
        st = PSA_ERROR_INVALID_HANDLE;
    }
    else {
        if (attributes != NULL) {
            *attributes = node->attributes;
        }

        if (node->data_length == 0 || node->data == NULL) {
            st = PSA_ERROR_DATA_INVALID;
        }
        else {
            *key_data = (uint8_t*)XMALLOC(node->data_length, NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
            if (*key_data == NULL) {
                st = PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            else {
                XMEMCPY(*key_data, node->data, node->data_length);
                *key_data_length = node->data_length;
            }
        }
    }

    WOLFPSA_UNLOCK();
    return st;
}

static psa_status_t wolfpsa_volatile_get_attributes(psa_key_id_t key_id,
                                                    psa_key_attributes_t*
                                                    attributes)
{
    wolfpsa_volatile_key_node* node;
    psa_status_t st = PSA_SUCCESS;

    if (attributes == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    WOLFPSA_LOCK();

    node = wolfpsa_volatile_find(key_id);
    if (node == NULL) {
        st = PSA_ERROR_INVALID_HANDLE;
    }
    else {
        *attributes = node->attributes;
    }

    WOLFPSA_UNLOCK();
    return st;
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
        /* Byte-string keys have no size of their own: the size is the
         * data length in bits. A zero-length import therefore has no
         * valid size, and the bit count must fit the 16-bit
         * psa_key_bits_t (e.g. 8192 bytes is 65536 bits, which would
         * truncate to 0). */
        if (data_length == 0 || data_length * 8U > PSA_MAX_KEY_BITS) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
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
                                                             (data_length - 1u)
                                                             / 2u);
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

        /* Parse-only key: no devId, because wc_RsaEncryptSize() answers a
         * hard-coded 2048 bits for a device that declines the call, which
         * would let a zero-modulus key past the size check below. */
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

/* DER INTEGER encoders. These branch on the value being serialized (leading
 * zero skip and high-bit pad), so they are variable-time and for public
 * integers only, such as the RSA modulus and public exponent. Serialize a
 * secret integer with a constant-time fixed-width encoder instead. */
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

/* Public integers only; see the note on psa_der_int_size above. This encoder
 * is variable-time with respect to the input bytes. */
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
    /* Publicly reachable before psa_crypto_init(); create the mutex first so
     * WOLFPSA_LOCK() never runs on an uninitialized lock. */
    if (WOLFPSA_LOCK_INIT() != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    WOLFPSA_LOCK();
    g_key_storage_initialized = 1;
    WOLFPSA_UNLOCK();
    return PSA_SUCCESS;
}

/* Cleanup the PSA key storage subsystem */
void psa_key_storage_cleanup(void)
{
    wolfpsa_volatile_key_node* cur;

    if (WOLFPSA_LOCK_INIT() != 0) {
        return;
    }
    WOLFPSA_LOCK();
    cur = g_volatile_keys;
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
    WOLFPSA_UNLOCK();
}

psa_key_id_t wolfpsa_test_get_next_key_id(void)
{
    psa_key_id_t id;
    if (WOLFPSA_LOCK_INIT() != 0) {
        return 0;
    }
    WOLFPSA_LOCK();
    id = g_next_key_id;
    WOLFPSA_UNLOCK();
    return id;
}

void wolfpsa_test_set_next_key_id(psa_key_id_t key_id)
{
    if (WOLFPSA_LOCK_INIT() != 0) {
        return;
    }
    WOLFPSA_LOCK();
    g_next_key_id = key_id;
    WOLFPSA_UNLOCK();
}

/* Check if the key storage is initialized */
static psa_status_t psa_key_storage_check_init(void)
{
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }

    /* psa_key_storage_init() is idempotent and takes the lock itself; call it
     * directly rather than nesting a second acquisition inside our own lock.
     * Avoiding the nested lock keeps the global mutex non-recursive, so
     * WOLFPSA_THREAD_SAFE works with a plain mutex off Zephyr too (see
     * psa_lock.h). */
    return psa_key_storage_init(NULL);
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
    status = wolfpsa_volatile_get(key_id, attributes, key_data,
                                  key_data_length);
    if (status == PSA_SUCCESS) {
        return PSA_SUCCESS;
    }
    if (status != PSA_ERROR_INVALID_HANDLE) {
        /* A volatile lookup failure (insufficient memory, invalid data) must
         * be reported, not masked by the persistent-store probe below. */
        return status;
    }

    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                  sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                  sizeof(psa_key_lifetime_t);
    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1,
                             &store);
    if (ret == WOLFPSA_STORE_NOT_AVAILABLE) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return wolfpsa_store_open_status(ret);
    }
    ret = wolfPSA_Store_Read(store, header,
                             (int)(attr_length + sizeof(size_t)));
    if (ret != (int)(attr_length + sizeof(size_t))) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_STORAGE_FAILURE;
    }

    if (attributes != NULL) {
        status = psa_key_attributes_deserialize(header, attr_length,
                                                attributes);
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
        wolfpsa_debug_import_reason("invalid parameters", attributes,
                                    data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Always treat key_id as output-only. */
    *key_id = PSA_KEY_ID_NULL;

    /* A zero-length blob is not a valid key of any type. Reject it up front:
     * the bits-inference path only rejects it when bits are not supplied, and
     * RSA/ECC/DH have no per-type length check, so a zero-length import with a
     * supplied bit count would otherwise be serialized and stored. */
    if (data_length == 0) {
        wolfpsa_debug_import_reason("empty key data", attributes, data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

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
            wolfpsa_debug_import_reason("invalid ChaCha20/XChaCha20 key bits",
                                        &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != 32) {
            wolfpsa_debug_import_reason(
                "ChaCha20/XChaCha20 key length must be 32", &attr,
                data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (attr.type == PSA_KEY_TYPE_AES) {
        if (attr.bits != 128 && attr.bits != 192 &&
            attr.bits != 256) {
            wolfpsa_debug_import_reason("invalid AES key bits", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (data_length != 16 && data_length != 24 && data_length != 32) {
            wolfpsa_debug_import_reason("invalid AES key length", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (attr.bits != (psa_key_bits_t)(data_length * 8U)) {
            wolfpsa_debug_import_reason("AES bits/length mismatch", &attr,
                                        data_length);
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
            wolfpsa_debug_import_reason("invalid DES key length", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (attr.bits != (psa_key_bits_t)(data_length * 8U)) {
            wolfpsa_debug_import_reason("DES bits/length mismatch", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (attr.type == PSA_KEY_TYPE_HMAC ||
               attr.type == PSA_KEY_TYPE_RAW_DATA ||
               attr.type == PSA_KEY_TYPE_DERIVE ||
               attr.type == PSA_KEY_TYPE_PASSWORD ||
               attr.type == PSA_KEY_TYPE_PASSWORD_HASH ||
               attr.type == PSA_KEY_TYPE_PEPPER) {
        /* Raw byte-string keys: the size is the data length in bits, so
         * the declared size must equal it, and it must fit the 16-bit
         * size type. */
        if (data_length * 8U > PSA_MAX_KEY_BITS ||
            attr.bits != (psa_key_bits_t)(data_length * 8U)) {
            wolfpsa_debug_import_reason("unstructured bits/length mismatch",
                                        &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_KEY_TYPE_IS_ML_DSA(attr.type)) {
        if (attr.type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
            if (attr.bits != 128 && attr.bits != 192 && attr.bits != 256) {
                wolfpsa_debug_import_reason("invalid ML-DSA key pair bits",
                                            &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != 32) {
                wolfpsa_debug_import_reason(
                    "ML-DSA key pair must be 32-byte seed",
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
            default: wolfpsa_debug_import_reason(
                "invalid ML-DSA public key bits", &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != expected) {
                wolfpsa_debug_import_reason("ML-DSA public key length mismatch",
                                            &attr,
                                            data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    else if (PSA_KEY_TYPE_IS_ML_KEM(attr.type)) {
        if (attr.type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
            if (attr.bits != 512 && attr.bits != 768 && attr.bits != 1024) {
                wolfpsa_debug_import_reason("invalid ML-KEM key pair bits",
                                            &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != 64) {
                wolfpsa_debug_import_reason(
                    "ML-KEM key pair must be 64-byte seed",
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
            default: wolfpsa_debug_import_reason(
                "invalid ML-KEM public key bits", &attr, data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (data_length != expected) {
                wolfpsa_debug_import_reason("ML-KEM public key length mismatch",
                                            &attr,
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
            wolfpsa_debug_import_reason(
                "XMSS/XMSS^MT public key length mismatch",
                &attr, data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(attr.type) ||
               PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attr.type)) {
        /* The declared bit count must match the curve implied by the key
         * data length: a mismatch means the caller is describing a
         * different curve than the one in the data. */
        psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(attr.type);
        size_t coord_len;
        size_t expected_len;

        if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(attr.type)) {
            if (family == PSA_ECC_FAMILY_MONTGOMERY ||
                family == PSA_ECC_FAMILY_TWISTED_EDWARDS) {
                /* Raw point (Montgomery/Twisted-Edwards): coord_len bytes,
                 * no prefix. */
                coord_len = data_length;
            }
            else {
                /* Uncompressed point: 0x04 || X || Y, where X and Y are each
                 * coordinate_size bytes (SEC 1 2.3.3). data_length must be
                 * exactly 1 + 2 * coordinate_size (odd, >= 3) and the prefix
                 * must be 0x04; flooring the length or skipping the prefix
                 * check would store malformed public keys. */
                if (data_length < 3 || (data_length % 2) == 0) {
                    wolfpsa_debug_import_reason(
                        "ECC public key length not 1 + 2*coord",
                        &attr, data_length);
                    return PSA_ERROR_INVALID_ARGUMENT;
                }
                if (data[0] != 0x04) {
                    wolfpsa_debug_import_reason(
                        "ECC public key missing 0x04 prefix",
                        &attr, data_length);
                    return PSA_ERROR_INVALID_ARGUMENT;
                }
                coord_len = (data_length - 1) / 2;
            }
        }
        else {
            /* Key pair: the private key is coord_len bytes. */
            coord_len = data_length;
        }
        /* attr.bits is non-zero by here: it was either supplied or inferred
         * above. A family/size pair with no table entry is a self-consistent
         * request for a curve wolfPSA does not implement, which PSA reports
         * as NOT_SUPPORTED; a length that contradicts a curve we do
         * implement is INVALID_ARGUMENT. */
        expected_len = wolfpsa_ecc_length_from_bits(family, attr.bits);
        if (expected_len == 0) {
            wolfpsa_debug_import_reason("unsupported ECC curve", &attr,
                                        data_length);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (coord_len != expected_len) {
            wolfpsa_debug_import_reason("ECC bits/curve mismatch", &attr,
                                        data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    /* Check if the key storage is initialized */
    status = psa_key_storage_check_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    {
        /* The PSA API ignores the key id in the attributes for a volatile
         * lifetime: the implementation always assigns a fresh one. Honouring it
         * would reject the output of psa_get_key_attributes(), which reports
         * the id of volatile keys too, with PSA_ERROR_ALREADY_EXISTS. Only a
         * persistent key takes its id from the caller. */
        psa_key_id_t attr_id = PSA_KEY_LIFETIME_IS_VOLATILE(attr.lifetime) ?
                               PSA_KEY_ID_NULL :
                               (psa_key_id_t)psa_get_key_id(&attr);
        if (attr_id != PSA_KEY_ID_NULL) {
            *key_id = attr_id;
        }
        else {
            /* Auto-assign implementation key ids from the vendor range so
             * they cannot collide with caller-specified persistent ids, which
             * the PSA API reserves to the user range. A collision would let an
             * auto-assigned volatile key shadow a persistent record on read and
             * survive psa_destroy_key() on disk. Guard the counter so concurrent
             * callers each get a distinct id. */
            WOLFPSA_LOCK();
            if (g_next_key_id < PSA_KEY_ID_VENDOR_MIN ||
                g_next_key_id > PSA_KEY_ID_VENDOR_MAX) {
                WOLFPSA_UNLOCK();
                return PSA_ERROR_INSUFFICIENT_STORAGE;
            }
            *key_id = g_next_key_id++;
            WOLFPSA_UNLOCK();
        }
    }

    /* Allocate buffer for key data and attributes */
    buffer_size = data_length + sizeof(psa_key_type_t) + sizeof(psa_key_bits_t)
                  +
                  sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                  sizeof(psa_key_lifetime_t) + sizeof(size_t);

    buffer = (uint8_t*)XMALLOC(buffer_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    /* Serialize key attributes */
    status = psa_key_attributes_serialize(&attr, buffer, buffer_size,
                                          &attr_length);
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
         * the requested id. Hold the key-store lock across the existence probe
         * and the write so two concurrent imports of the same id serialize: the
         * loser observes the winner's record and returns ALREADY_EXISTS instead
         * of both probing absent and both writing. Each store call is atomic on
         * its own; the lock adds the cross-thread atomicity the check-then-write
         * needs. Probing before the write handle also stops the atomic rename in
         * wolfPSA_Store_Close() from silently destroying the previous record. */
        WOLFPSA_LOCK();

        ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)*key_id, 0,
                                 1, &store);
        if (ret == 0) {
            wolfPSA_Store_Close(store);
            store = NULL;
            WOLFPSA_UNLOCK();
            wc_ForceZero(buffer, buffer_size);
            XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *key_id = PSA_KEY_ID_NULL;
            return PSA_ERROR_ALREADY_EXISTS;
        }
        if (ret != WOLFPSA_STORE_NOT_AVAILABLE) {
            /* The probe failed for a reason other than "not found" (an I/O
             * error, or a failed context allocation): do not proceed to the
             * write path, which would overwrite a record we could not
             * inspect. */
            WOLFPSA_UNLOCK();
            wc_ForceZero(buffer, buffer_size);
            XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *key_id = PSA_KEY_ID_NULL;
            return wolfpsa_store_open_status(ret);
        }

        /* Open and write key to persistent storage */
        ret = wolfPSA_Store_OpenSz(WOLFPSA_STORE_KEY, (unsigned long)*key_id, 0,
                                   0, (int)data_length, &store);
        if (ret == 0) {
            int closeRet;

            ret = wolfPSA_Store_Write(store, buffer,
                                      (int)(attr_length + sizeof(size_t) +
                                            data_length));
            closeRet = wolfPSA_Store_Close(store);
            store = NULL;
            /* A successful write returns the byte count, not zero: report a
             * failed commit only when the write itself did not already
             * fail. */
            if (ret >= 0 && closeRet != WOLFPSA_STORE_OK) {
                ret = closeRet;
            }
        }

        WOLFPSA_UNLOCK();
    }

    wc_ForceZero(buffer, buffer_size);
    XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (status != PSA_SUCCESS) {
        *key_id = PSA_KEY_ID_NULL;
        return status;
    }

    if (ret < 0) {
        /* The write path failed: a store context allocation failure is
         * reported as such, anything else as a storage failure. */
        *key_id = PSA_KEY_ID_NULL;
        return wolfpsa_store_open_status(ret);
    }

    if ((size_t)ret != (attr_length + sizeof(size_t) + data_length)) {
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
#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448) || \
        defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        /* Standalone EdDSA and Montgomery backends compile without generic
         * Weierstrass ECC, so only the default (Weierstrass) dispatch below
         * is gated on HAVE_ECC; each EdDSA/Montgomery arm is gated on its
         * own backend macros. */
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
                                                             key_data,
                                                             priv_buf_size,
                                                             &priv_len,
                                                             pub_buf,
                                                             pub_buf_size,
                                                             &pub_len);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            else if (key_bits == 448) {
#ifdef HAVE_ED448
                status = psa_asymmetric_generate_key_ed448(key_type, key_bits,
                                                           key_data,
                                                           priv_buf_size,
                                                           &priv_len,
                                                           pub_buf, pub_buf_size
                                                           ,
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
#ifdef HAVE_ECC
            status = psa_asymmetric_generate_key_ecc(key_type, key_bits,
                                                     key_data, priv_buf_size,
                                                     &priv_len,
                                                     pub_buf, pub_buf_size,
                                                     &pub_len);
#else
            status = PSA_ERROR_NOT_SUPPORTED;
#endif
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
    if (ret == WOLFPSA_STORE_NOT_AVAILABLE) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return wolfpsa_store_open_status(ret);
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
    psa_key_usage_t usage;
    int ret;
    void* store = NULL;

    /* Check parameters: a NULL data pointer is only an error when the
     * caller declared a nonzero capacity; (NULL, 0) is a valid
     * zero-capacity output buffer that must reach the size checks below. */
    if (data_length == NULL || (data == NULL && data_size != 0)) {
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
    if (status != PSA_ERROR_INVALID_HANDLE) {
        /* A volatile lookup failure must be reported, not masked by the
         * persistent-store probe below. */
        return status;
    }

    /* Calculate attribute length */
    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                  sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                  sizeof(psa_key_lifetime_t);
    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1,
                             &store);
    if (ret == WOLFPSA_STORE_NOT_AVAILABLE) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return wolfpsa_store_open_status(ret);
    }
    ret = wolfPSA_Store_Read(store, header,
                             (int)(attr_length + sizeof(size_t)));
    if (ret != (int)(attr_length + sizeof(size_t))) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_STORAGE_FAILURE;
    }

    /* Authorize the export from the same open handle as the data read below,
     * so a concurrent destroy/import of this key ID cannot swap in a
     * non-exportable replacement between the check and the read. */
    XMEMCPY(&usage, header + sizeof(psa_key_type_t) + sizeof(psa_key_bits_t),
            sizeof(psa_key_usage_t));
    if ((usage & PSA_KEY_USAGE_EXPORT) == 0) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_NOT_PERMITTED;
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

    /* A NULL data pointer is only an error when the caller declared a
     * nonzero capacity; (NULL, 0) must reach the size checks below. */
    if (data_length == NULL || (data == NULL && data_size != 0)) {
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
        else if (status != PSA_ERROR_INVALID_HANDLE) {
            return status;
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
        if (ret == WOLFPSA_STORE_NOT_AVAILABLE) {
            return PSA_ERROR_INVALID_HANDLE;
        }
        if (ret != 0) {
            return wolfpsa_store_open_status(ret);
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
        /* Standalone EdDSA and Montgomery exporters compile without generic
         * Weierstrass ECC, so only the default (Weierstrass) key-pair arm
         * below is gated on HAVE_ECC + the ECC key import/export macros; the
         * stored-public-key copy needs no backend at all. */
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
            psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(attributes.
                                                                  type);

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
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
                defined(HAVE_ECC_KEY_IMPORT)
                status = psa_asymmetric_export_public_key_ecc(
                    attributes.type, attributes.bits, key_data,
                    key_data_length, data, data_size, data_length);
#else
                status = PSA_ERROR_NOT_SUPPORTED;
#endif
            }
        }
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
                /* Key pair: stored as 32-byte seed — derive public key.
                 * The expansion helper reads exactly
                 * WOLFPSA_MLDSA_SEED_SIZE bytes, so a corrupted record
                 * with a shorter seed would read out of bounds. */
                if (key_data_length != WOLFPSA_MLDSA_SEED_SIZE) {
                    status = PSA_ERROR_DATA_INVALID;
                }
                else {
                    status = wolfpsa_mldsa_export_public(
                        (size_t)attributes.bits, key_data, data, data_size,
                        data_length);
                }
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
                /* Key pair: stored as 64-byte seed — derive public key.
                 * The expansion helper reads exactly
                 * WOLFPSA_MLKEM_SEED_SIZE bytes, so a corrupted record
                 * with a shorter seed would read out of bounds. */
                if (key_data_length != WOLFPSA_MLKEM_SEED_SIZE) {
                    status = PSA_ERROR_DATA_INVALID;
                }
                else {
                    status = wolfpsa_mlkem_export_public(
                        (size_t)attributes.bits, key_data, data, data_size,
                        data_length);
                }
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
    if (status != PSA_SUCCESS) {
        /* Not a volatile key: load the attributes from the persistent store. */
        attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                      sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                      sizeof(psa_key_lifetime_t);

        ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)key_id, 0, 1,
                                 &store);
        if (ret == WOLFPSA_STORE_NOT_AVAILABLE) {
            return PSA_ERROR_INVALID_HANDLE;
        }
        if (ret != 0) {
            return wolfpsa_store_open_status(ret);
        }

        ret = wolfPSA_Store_Read(store, buffer,
                                 (int)(attr_length + sizeof(size_t)));
        wolfPSA_Store_Close(store);
        store = NULL;
        if (ret != (int)(attr_length + sizeof(size_t))) {
            return PSA_ERROR_STORAGE_FAILURE;
        }
        status = psa_key_attributes_deserialize(buffer, attr_length,
                                                attributes);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    /* The key id is the storage locator (persistent) or the volatile handle,
     * not part of the serialized attributes, so restore it for both paths. Set
     * the field directly: both source paths already carry the correct lifetime,
     * and the accessor pair cannot express a volatile key's id (psa_set_key_id()
     * flips a volatile lifetime to persistent, and psa_set_key_lifetime() clears
     * the id when the lifetime is volatile). */
    attributes->id = key_id;
    return PSA_SUCCESS;
}

psa_status_t psa_purge_key(psa_key_id_t key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    /* wolfPSA keeps no in-RAM cache of persistent key material: persistent keys
     * are reloaded from the store on every use (see wolfpsa_get_key_data()),
     * and volatile keys must stay resident. There is therefore nothing to
     * purge. Confirm the key exists and report success, which matches the PSA
     * semantics for a key that has no purgeable cached copies. */
    status = psa_get_key_attributes(key, &attributes);
    psa_reset_key_attributes(&attributes);

    return status;
}

/* Return 1 if a MAC or AEAD tag of concrete_len bytes satisfies a wildcard
 * policy that requires at least min_len bytes. A length field of 0 is the
 * full, untruncated tag: it satisfies every minimum, and as a minimum only
 * the full length satisfies it. */
static int wolfpsa_tag_len_permitted(size_t concrete_len, size_t min_len)
{
    if (min_len == 0) {
        return concrete_len == 0;
    }
    return (concrete_len == 0) || (concrete_len >= min_len);
}

/* Return the more restrictive of two wildcard minimum lengths, where 0 is
 * the full length and therefore the longest. */
static size_t wolfpsa_tag_len_restrict(size_t len_a, size_t len_b)
{
    if (len_a == 0 || len_b == 0) {
        return 0;
    }
    return (len_a > len_b) ? len_a : len_b;
}

/* Compute the permitted algorithm of a copy: the intersection of the source
 * and destination policies, stored in *alg. Returns 0 when the policies have
 * no algorithm in common and the copy must be rejected. The policies
 * intersect when they are equal, when one is the ANY_HASH wildcard of the
 * other's concrete signature algorithm, or when a minimum-length MAC or
 * minimum-tag-length AEAD wildcard admits the other algorithm of the same
 * base family; two such length wildcards intersect in the more restrictive
 * of the two. */
static int wolfpsa_alg_intersect(psa_algorithm_t src_alg,
                                 psa_algorithm_t dst_alg,
                                 psa_algorithm_t* alg)
{
    int ok = 0;
    psa_algorithm_t src_hash;
    psa_algorithm_t dst_hash;
    psa_algorithm_t concrete_hash;
    size_t src_len;
    size_t dst_len;
    int src_wild;
    int dst_wild;

    *alg = PSA_ALG_NONE;

    if (src_alg == dst_alg) {
        *alg = src_alg;
        ok = 1;
    }
    else if ((src_alg & ~PSA_ALG_HASH_MASK) == (dst_alg & ~PSA_ALG_HASH_MASK)
               &&
               PSA_ALG_IS_SIGN_HASH(src_alg) && PSA_ALG_IS_SIGN_HASH(dst_alg)) {
        src_hash = PSA_ALG_GET_HASH(src_alg);
        dst_hash = PSA_ALG_GET_HASH(dst_alg);
        /* PSA_ALG_ANY_HASH is a signature-scheme wildcard in the PSA
        * supported key policies: it narrows to any concrete hash of the
        * same base family, mirroring wolfpsa_sign_alg_permitted().
        * HMAC(ANY_HASH) is not a valid policy. Exactly one side must be
        * the wildcard; two wildcards are the equality case above. */
        if ((src_hash == PSA_ALG_ANY_HASH) != (dst_hash == PSA_ALG_ANY_HASH)) {
            concrete_hash = (src_hash == PSA_ALG_ANY_HASH) ? dst_hash
                                                           : src_hash;
            if (concrete_hash != PSA_ALG_NONE) {
                ok = 1;
            }
            else {
                /* An empty hash field is a hashless algorithm, not a member
                 * of ANY_HASH: PSA_ALG_ECDSA_ANY is explicitly not covered
                 * by PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), so admitting it here
                 * would let a copy gain a forbidden policy.
                 * PSA_ALG_RSA_PKCS1V15_SIGN_RAW is the single exception the
                 * PSA Crypto API grants to that rule. */
                ok = ((src_alg & ~PSA_ALG_HASH_MASK) ==
                      PSA_ALG_RSA_PKCS1V15_SIGN_BASE);
            }
            if (ok) {
                /* Keep the concrete algorithm: it is the only one both
                 * policies allow. */
                *alg = (src_hash == PSA_ALG_ANY_HASH) ? dst_alg : src_alg;
            }
        }
    }
    else if (PSA_ALG_IS_MAC(src_alg) && PSA_ALG_IS_MAC(dst_alg) &&
               PSA_ALG_FULL_LENGTH_MAC(src_alg) ==
               PSA_ALG_FULL_LENGTH_MAC(dst_alg)) {
        src_len = PSA_MAC_TRUNCATED_LENGTH(src_alg);
        dst_len = PSA_MAC_TRUNCATED_LENGTH(dst_alg);
        src_wild = (src_alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0;
        dst_wild = (dst_alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0;
        if (src_wild && dst_wild) {
            *alg = (psa_algorithm_t)PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(src_alg,
                                                                     wolfpsa_tag_len_restrict
                                                                     (
                                                                         src_len,
                                                                         dst_len));
            ok = 1;
        }
        else if (src_wild) {
            ok = wolfpsa_tag_len_permitted(dst_len, src_len);
            *alg = ok ? dst_alg : PSA_ALG_NONE;
        }
        else if (dst_wild) {
            ok = wolfpsa_tag_len_permitted(src_len, dst_len);
            *alg = ok ? src_alg : PSA_ALG_NONE;
        }
    }
    else if (PSA_ALG_IS_AEAD(src_alg) && PSA_ALG_IS_AEAD(dst_alg) &&
               PSA_ALG_AEAD_WITH_SHORTENED_TAG(src_alg, 0) ==
               PSA_ALG_AEAD_WITH_SHORTENED_TAG(dst_alg, 0)) {
        src_len = PSA_ALG_AEAD_GET_TAG_LENGTH(src_alg);
        dst_len = PSA_ALG_AEAD_GET_TAG_LENGTH(dst_alg);
        src_wild = (src_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0;
        dst_wild = (dst_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0;
        if (src_wild && dst_wild) {
            *alg = (psa_algorithm_t)
                   PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(src_alg,
                                                              wolfpsa_tag_len_restrict
                                                                  (src_len,
                                                                  dst_len));
            ok = 1;
        }
        else if (src_wild) {
            ok = wolfpsa_tag_len_permitted(dst_len, src_len);
            *alg = ok ? dst_alg : PSA_ALG_NONE;
        }
        else if (dst_wild) {
            ok = wolfpsa_tag_len_permitted(src_len, dst_len);
            *alg = ok ? src_alg : PSA_ALG_NONE;
        }
    }

    return ok;
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
    psa_algorithm_t copy_alg = PSA_ALG_NONE;

    /* Check parameters */
    if (attributes == NULL || target_key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* The API guarantees PSA_KEY_ID_NULL on failure, so clear the output
     * before any fallible operation below. */
    *target_key = PSA_KEY_ID_NULL;

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

            if (!wolfpsa_alg_intersect(psa_get_key_algorithm(&vol_attr),
                                       attributes->policy.alg, &copy_alg)) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (attributes->lifetime != vol_attr.lifetime) {
                wolfpsa_forcezero_free_key_data(key_data, key_data_length);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            dst_attr.type = (dst_attr.type == 0) ? vol_attr.type
                                                 : dst_attr.type;
            dst_attr.bits = (
                dst_attr.bits == 0) ? vol_attr.bits : dst_attr.bits;
            dst_attr.policy.usage = psa_get_key_usage_flags(&vol_attr) &
                                    psa_get_key_usage_flags(&dst_attr);
            dst_attr.policy.alg = copy_alg;

            status = psa_import_key(&dst_attr, key_data,
                                    key_data_length, target_key);
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return status;
        }
    }
    if (status != PSA_ERROR_INVALID_HANDLE) {
        /* A volatile lookup failure must be reported, not masked by the
         * persistent-store probe below. */
        return status;
    }

    /* Calculate attribute length */
    attr_length = sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                  sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                  sizeof(psa_key_lifetime_t);

    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, (unsigned long)source_key, 0, 1,
                             &store);
    if (ret == WOLFPSA_STORE_NOT_AVAILABLE) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if (ret != 0) {
        return wolfpsa_store_open_status(ret);
    }
    ret = wolfPSA_Store_Read(store, header,
                             (int)(attr_length + sizeof(size_t)));
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

    if (!wolfpsa_alg_intersect(psa_get_key_algorithm(&src_attr),
                               attributes->policy.alg, &copy_alg)) {
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
    dst_attr.policy.alg = copy_alg;

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
                ((key_alg & ~PSA_ALG_HASH_MASK) == (alg & ~PSA_ALG_HASH_MASK)))
            {
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
