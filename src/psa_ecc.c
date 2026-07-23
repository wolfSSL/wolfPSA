/* psa_ecc.c
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

#if defined(WOLFSSL_PSA_ENGINE) && defined(HAVE_ECC)

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/ecc.h>

extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);
int wc_psa_get_hash_type(psa_algorithm_t alg);

/* Sign a hash or short message with an ECC private key */
psa_status_t psa_asymmetric_sign_ecc(psa_key_type_t key_type,
                                    size_t key_bits,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length)
{
    int ret;
    ecc_key ecc;
    int curve_id;
    WC_RNG rng;
    word32 sig_len;
    word32 der_len;
    word32 r_len;
    word32 s_len;
    size_t key_bytes;
    size_t raw_sig_len;
    byte* der_sig = NULL;
    byte* rs = NULL;
    
    /* Check if key type is ECC key pair */
    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (!PSA_ALG_IS_ECDSA(alg) && !PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (signature == NULL || signature_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Get curve ID */
    curve_id = wc_psa_get_ecc_curve_id(key_type, key_bits);
    if (curve_id == ECC_CURVE_INVALID) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_ecc_import_private_key_ex(key_buffer, (word32)key_buffer_size,
                                     NULL, 0, &ecc, curve_id);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    key_bytes = PSA_BITS_TO_BYTES(key_bits);
    raw_sig_len = key_bytes * 2u;
    if (signature_size < raw_sig_len) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
        int hash_type = wc_psa_get_hash_type(alg);
        if (hash_type == WC_HASH_TYPE_NONE) {
            wc_FreeRng(&rng);
            wc_ecc_free(&ecc);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        ret = wc_ecc_set_deterministic_ex(&ecc, 1, hash_type);
        if (ret != 0) {
            wc_FreeRng(&rng);
            wc_ecc_free(&ecc);
            return wc_error_to_psa_status(ret);
        }
#else
        /* Deterministic ECDSA needs WOLFSSL_ECDSA_DETERMINISTIC_K. */
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    sig_len = wc_ecc_sig_size(&ecc);
    der_sig = (byte*)XMALLOC(sig_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der_sig == NULL) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    /* Sign hash (DER signature) */
    der_len = sig_len;
    ret = wc_ecc_sign_hash(hash, (word32)hash_length, der_sig,
                           &der_len, &rng, &ecc);
    
    wc_FreeRng(&rng);
    wc_ecc_free(&ecc);
    
    if (ret != 0) {
        wc_ForceZero(der_sig, sig_len);
        XFREE(der_sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    rs = (byte*)XMALLOC(raw_sig_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rs == NULL) {
        wc_ForceZero(der_sig, sig_len);
        XFREE(der_sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    r_len = (word32)key_bytes;
    s_len = (word32)key_bytes;
    ret = wc_ecc_sig_to_rs(der_sig, der_len, rs, &r_len, rs + key_bytes, &s_len);
    wc_ForceZero(der_sig, sig_len);
    XFREE(der_sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0) {
        wc_ForceZero(rs, raw_sig_len);
        XFREE(rs, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }
    if (r_len > key_bytes || s_len > key_bytes) {
        wc_ForceZero(rs, raw_sig_len);
        XFREE(rs, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    XMEMSET(signature, 0, raw_sig_len);
    XMEMCPY(signature + (key_bytes - r_len), rs, r_len);
    XMEMCPY(signature + key_bytes + (key_bytes - s_len),
            rs + key_bytes, s_len);
    wc_ForceZero(rs, raw_sig_len);
    XFREE(rs, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    *signature_length = raw_sig_len;
    return PSA_SUCCESS;
}

/* Verify a signature of a hash or short message with an ECC public key */
psa_status_t psa_asymmetric_verify_ecc(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    int ret;
    ecc_key ecc;
    int curve_id;
    int verify_res = 0;
    size_t key_bytes;
    size_t raw_sig_len;
    byte* der_sig = NULL;
    word32 der_len;
    
    /* Check if key type is ECC public key or key pair */
    if (!PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type) &&
        !PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_ALG_IS_ECDSA(alg) && !PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Get curve ID */
    curve_id = wc_psa_get_ecc_curve_id(key_type, key_bits);
    if (curve_id == ECC_CURVE_INVALID) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import key */
    if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type)) {
        ret = wc_ecc_import_x963(key_buffer, (word32)key_buffer_size, &ecc);
    }
    else {
        ret = wc_ecc_import_private_key_ex(key_buffer, (word32)key_buffer_size,
                                           NULL, 0, &ecc, curve_id);
        if (ret == 0) {
            ret = wc_ecc_make_pub_ex(&ecc, NULL, NULL);
        }
    }
    if (ret != 0) {
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }

    key_bytes = PSA_BITS_TO_BYTES(key_bits);
    raw_sig_len = key_bytes * 2u;
    if (signature_length != raw_sig_len) {
        wc_ecc_free(&ecc);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    der_len = wc_ecc_sig_size(&ecc);
    der_sig = (byte*)XMALLOC(der_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der_sig == NULL) {
        wc_ecc_free(&ecc);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    ret = wc_ecc_rs_raw_to_sig(signature, (word32)key_bytes,
                               signature + key_bytes, (word32)key_bytes,
                               der_sig, &der_len);
    if (ret != 0) {
        XFREE(der_sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_ecc_free(&ecc);
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    /* Verify signature */
    ret = wc_ecc_verify_hash(der_sig, der_len,
                            hash, (word32)hash_length, &verify_res, &ecc);
    
    XFREE(der_sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_ecc_free(&ecc);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}

/* Generate an ECC key pair */
psa_status_t psa_asymmetric_generate_key_ecc(psa_key_type_t key_type,
                                            size_t key_bits,
                                            uint8_t *private_key,
                                            size_t private_key_size,
                                            size_t *private_key_length,
                                            uint8_t *public_key,
                                            size_t public_key_size,
                                            size_t *public_key_length)
{
    int ret;
    ecc_key ecc;
    WC_RNG rng;
    int curve_id;
    word32 priv_len;
    word32 pub_len;
    
    /* Check if key type is ECC key pair */
    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Get curve ID */
    curve_id = wc_psa_get_ecc_curve_id(key_type, key_bits);
    if (curve_id == ECC_CURVE_INVALID) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_ecc_make_key_ex(&rng, (int)PSA_BITS_TO_BYTES(key_bits), &ecc, curve_id);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    if (private_key == NULL || private_key_length == NULL ||
        public_key == NULL || public_key_length == NULL) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    priv_len = (word32)PSA_BITS_TO_BYTES(key_bits);
    if (private_key_size < priv_len) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    ret = mp_to_unsigned_bin_len(ecc.k, private_key, priv_len);
    if (ret != MP_OKAY) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    pub_len = (word32)public_key_size;
    ret = wc_ecc_export_x963(&ecc, public_key, &pub_len);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    wc_FreeRng(&rng);
    wc_ecc_free(&ecc);
    
    *private_key_length = (size_t)priv_len;
    *public_key_length = (size_t)pub_len;
    return PSA_SUCCESS;
}

/* Export an ECC public key or the public part of an ECC key pair */
psa_status_t psa_asymmetric_export_public_key_ecc(psa_key_type_t key_type,
                                                 size_t key_bits,
                                                 const uint8_t *key_buffer,
                                                 size_t key_buffer_size,
                                                 uint8_t *output,
                                                 size_t output_size,
                                                 size_t *output_length)
{
    int ret;
    ecc_key ecc;
    int curve_id;
    word32 out_len;
    
    /* Check if key type is ECC */
    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) && 
        !PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Get curve ID */
    curve_id = wc_psa_get_ecc_curve_id(key_type, key_bits);
    if (curve_id == ECC_CURVE_INVALID) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import key */
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
        ret = wc_ecc_import_private_key_ex(key_buffer, (word32)key_buffer_size,
                                         NULL, 0, &ecc, curve_id);
        if (ret == 0) {
            ret = wc_ecc_make_pub_ex(&ecc, NULL, NULL);
        }
    }
    else {
        ret = wc_ecc_import_x963(key_buffer, (word32)key_buffer_size, &ecc);
    }
    
    if (ret != 0) {
        wc_ecc_free(&ecc);
        return wc_error_to_psa_status(ret);
    }
    
    if (output == NULL || output_length == NULL) {
        wc_ecc_free(&ecc);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Export public key */
    out_len = (word32)output_size;
    ret = wc_ecc_export_x963(&ecc, output, &out_len);
    
    wc_ecc_free(&ecc);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    *output_length = (size_t)out_len;
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE && HAVE_ECC */
