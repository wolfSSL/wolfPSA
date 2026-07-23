/* psa_rsa.c
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

#if defined(WOLFSSL_PSA_ENGINE) && !defined(NO_RSA)

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

int wc_psa_get_rsa_padding(psa_algorithm_t alg);
int wc_psa_get_hash_type(psa_algorithm_t alg);

/* Only the PSS and OAEP paths use MGF1; guard the helper with the same
 * condition as its callers so a config with neither (e.g. RSA sign/verify with
 * PKCS#1 v1.5 only) does not trip -Werror=unused-function. */
#if defined(WC_RSA_PSS) || defined(WOLFSSL_RSA_OAEP)
static int wc_psa_get_mgf(int hash_type)
{
    switch (hash_type) {
        case WC_HASH_TYPE_SHA:
            return WC_MGF1SHA1;
        case WC_HASH_TYPE_SHA224:
            return WC_MGF1SHA224;
        case WC_HASH_TYPE_SHA256:
            return WC_MGF1SHA256;
        case WC_HASH_TYPE_SHA384:
            return WC_MGF1SHA384;
        case WC_HASH_TYPE_SHA512:
            return WC_MGF1SHA512;
        case WC_HASH_TYPE_SHA512_224:
            return WC_MGF1SHA512_224;
        case WC_HASH_TYPE_SHA512_256:
            return WC_MGF1SHA512_256;
        default:
            return WC_MGF1NONE;
    }
}
#endif /* WC_RSA_PSS || WOLFSSL_RSA_OAEP */

#ifdef WC_RSA_PSS
static int wc_psa_rsa_pss_check_padding(const byte* hash, word32 hash_length,
                                        const byte* encoded, word32 encoded_length,
                                        int hash_type, int salt_len,
                                        RsaKey* rsa_key)
{
#if (defined(HAVE_SELFTEST) && \
     (!defined(HAVE_SELFTEST_VERSION) || (HAVE_SELFTEST_VERSION < 2))) || \
    (defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
     (HAVE_FIPS_VERSION < 2))
    return wc_RsaPSS_CheckPadding_ex(hash, hash_length, encoded,
                                     encoded_length, hash_type, salt_len);
#elif (defined(HAVE_SELFTEST) && (HAVE_SELFTEST_VERSION == 2)) || \
      (defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
       (HAVE_FIPS_VERSION == 2))
    return wc_RsaPSS_CheckPadding_ex(hash, hash_length, encoded,
                                     encoded_length, hash_type, salt_len, 0);
#else
    return wc_RsaPSS_CheckPadding_ex2(hash, hash_length, encoded,
                                      encoded_length, hash_type, salt_len,
                                      mp_count_bits(&rsa_key->n), NULL);
#endif
}
#endif

/* Sign a hash or short message with an RSA private key */
psa_status_t psa_asymmetric_sign_rsa(psa_key_type_t key_type,
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
    RsaKey rsa_key;
    word32 idx = 0;
    int padding;
    int hash_type;
    int hash_oid;
    byte* sig_input = NULL;
    word32 sig_input_len = 0;
    word32 sig_input_alloc_len = 0;
    WC_RNG rng;
    
    (void)key_bits;

    /* Check if key type is RSA key pair */
    if (key_type != PSA_KEY_TYPE_RSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa_key, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Decode private key */
    ret = wc_RsaPrivateKeyDecode(key_buffer, &idx, &rsa_key, (word32)key_buffer_size);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Get padding type and hash type */
    padding = wc_psa_get_rsa_padding(alg);
    hash_type = wc_psa_get_hash_type(alg);
#ifndef WC_RSA_PSS
    (void)hash_type;
#endif
    
    /* Sign hash */
    if (padding == WC_RSA_PKCSV15_PAD) {
        if (alg == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
            sig_input = (byte*)hash;
            sig_input_len = (word32)hash_length;
        }
        else {
            hash_oid = wc_GetCTC_HashOID(hash_type);
            if (hash_oid <= 0) {
                wc_FreeRng(&rng);
                wc_FreeRsaKey(&rsa_key);
                return PSA_ERROR_NOT_SUPPORTED;
            }
            sig_input = (byte*)XMALLOC(PSA_HASH_MAX_SIZE + 32, NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (sig_input == NULL) {
                wc_FreeRng(&rng);
                wc_FreeRsaKey(&rsa_key);
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            sig_input_alloc_len = PSA_HASH_MAX_SIZE + 32;
            sig_input_len = wc_EncodeSignature(sig_input, hash,
                                               (word32)hash_length, hash_oid);
        }

        ret = wc_RsaSSL_Sign(sig_input, sig_input_len, signature,
                             (word32)signature_size, &rsa_key, &rng);
    }
    else if (padding == WC_RSA_PSS_PAD) {
        #ifdef WC_RSA_PSS
            ret = wc_RsaPSS_Sign(hash, (word32)hash_length, signature, 
                               (word32)signature_size, hash_type, 
                               wc_psa_get_mgf(hash_type), &rsa_key, &rng);
        #else
            ret = NOT_COMPILED_IN;
        #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    if (sig_input != NULL && sig_input != hash) {
        wc_ForceZero(sig_input, sig_input_alloc_len);
        XFREE(sig_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&rsa_key);
    
    if (ret < 0) {
        return wc_error_to_psa_status(ret);
    }
    
    *signature_length = (size_t)ret;
    
    return PSA_SUCCESS;
}

/* Verify a signature of a hash or short message with an RSA public key */
psa_status_t psa_asymmetric_verify_rsa(psa_key_type_t key_type,
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
    RsaKey rsa_key;
    word32 idx = 0;
    int padding;
    int hash_type;
    
    (void)key_bits;

    /* Check if key type is RSA public key or key pair */
    if (key_type != PSA_KEY_TYPE_RSA_PUBLIC_KEY &&
        key_type != PSA_KEY_TYPE_RSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(hash_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa_key, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Decode key */
    if (key_type == PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
        ret = wc_RsaPublicKeyDecode(key_buffer, &idx, &rsa_key,
                                    (word32)key_buffer_size);
    }
    else {
        ret = wc_RsaPrivateKeyDecode(key_buffer, &idx, &rsa_key,
                                     (word32)key_buffer_size);
    }
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Get padding type and hash type */
    padding = wc_psa_get_rsa_padding(alg);
    hash_type = wc_psa_get_hash_type(alg);
#ifndef WC_RSA_PSS
    (void)hash_type;
#endif
    
    /* Verify signature */
    if (padding == WC_RSA_PKCSV15_PAD) {
        byte decoded[RSA_MAX_SIZE/8];

        if (alg == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
            ret = wc_RsaSSL_Verify_ex(signature, (word32)signature_length,
                                      decoded, (word32)sizeof(decoded),
                                      &rsa_key, WC_RSA_PKCSV15_PAD);
        }
        else {
            ret = wc_RsaSSL_Verify_ex2(signature, (word32)signature_length,
                                       decoded, (word32)sizeof(decoded),
                                       &rsa_key, WC_RSA_PKCSV15_PAD,
                                       hash_type);
        }

        if (ret > 0) {
            if ((size_t)ret != hash_length ||
                ConstantCompare(decoded, hash, (int)hash_length) != 0) {
                ret = SIG_VERIFY_E;
            }
        }
        wc_ForceZero(decoded, sizeof(decoded));
    }
    else if (padding == WC_RSA_PSS_PAD) {
    #ifdef WC_RSA_PSS
        byte decoded[RSA_MAX_SIZE/8];
        int salt_len = RSA_PSS_SALT_LEN_DEFAULT;

    #ifdef WOLFSSL_PSS_SALT_LEN_DISCOVER
        if (PSA_ALG_IS_RSA_PSS_ANY_SALT(alg)) {
            salt_len = RSA_PSS_SALT_LEN_DISCOVER;
        }
    #else
        if (PSA_ALG_IS_RSA_PSS_ANY_SALT(alg)) {
            ret = NOT_COMPILED_IN;
            wc_ForceZero(decoded, sizeof(decoded));
            wc_FreeRsaKey(&rsa_key);
            return wc_error_to_psa_status(ret);
        }
    #endif

        ret = wc_RsaPSS_Verify_ex(signature, (word32)signature_length,
                                  decoded, (word32)sizeof(decoded),
                                  hash_type, wc_psa_get_mgf(hash_type),
                                  salt_len, &rsa_key);
        if (ret > 0) {
            ret = wc_psa_rsa_pss_check_padding(hash, (word32)hash_length,
                                               decoded, (word32)ret,
                                               hash_type, salt_len, &rsa_key);
            if (ret == 0) {
                ret = (int)hash_length;
            }
        }
        wc_ForceZero(decoded, sizeof(decoded));
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    wc_FreeRsaKey(&rsa_key);
    
    if (ret < 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if ((size_t)ret != hash_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}

/* Encrypt a short message with an RSA public key */
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
                                       size_t *output_length)
{
    int ret;
    RsaKey rsa_key;
    word32 idx = 0;
    WC_RNG rng;
    int padding;
    int hash_type;
    
    (void)key_bits;
    (void)salt;
    (void)salt_length;

    /* Check if key type is RSA public key or key pair */
    if (key_type != PSA_KEY_TYPE_RSA_PUBLIC_KEY &&
        key_type != PSA_KEY_TYPE_RSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(input_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(salt_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa_key, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Decode key (public or key pair) */
    if (key_type == PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
        ret = wc_RsaPublicKeyDecode(key_buffer, &idx, &rsa_key,
                                    (word32)key_buffer_size);
    }
    else {
        ret = wc_RsaPrivateKeyDecode(key_buffer, &idx, &rsa_key,
                                     (word32)key_buffer_size);
    }
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Get padding type and hash type */
    padding = wc_psa_get_rsa_padding(alg);
    hash_type = wc_psa_get_hash_type(alg);
#ifndef WOLFSSL_RSA_OAEP
    (void)hash_type;
#endif
    
    /* Encrypt message */
    if (padding == WC_RSA_PKCSV15_PAD) {
        ret = wc_RsaPublicEncrypt(input, (word32)input_length, output, 
                                (word32)output_size, &rsa_key, &rng);
    }
    else if (padding == WC_RSA_OAEP_PAD) {
        #ifdef WOLFSSL_RSA_OAEP
            int mgf = wc_psa_get_mgf(hash_type);
            if (mgf == WC_MGF1NONE) {
                ret = BAD_FUNC_ARG;
            }
            else {
                ret = wc_RsaPublicEncrypt_ex(input, (word32)input_length, output,
                                             (word32)output_size, &rsa_key, &rng,
                                             WC_RSA_OAEP_PAD, hash_type,
                                             mgf, (byte*)salt,
                                             (word32)salt_length);
            }
        #else
            ret = NOT_COMPILED_IN;
        #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&rsa_key);
    
    if (ret < 0) {
        return wc_error_to_psa_status(ret);
    }
    
    *output_length = (size_t)ret;
    
    return PSA_SUCCESS;
}

/* Decrypt a short message with an RSA private key */
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
                                       size_t *output_length)
{
    int ret;
    RsaKey rsa_key;
    word32 idx = 0;
    int padding;
    int hash_type;
#ifdef WC_RSA_BLINDING
    WC_RNG rng;
#endif

    (void)key_bits;
    (void)salt;
    (void)salt_length;

    /* Check if key type is RSA key pair */
    if (key_type != PSA_KEY_TYPE_RSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(input_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(salt_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa_key, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* Decode private key */
    ret = wc_RsaPrivateKeyDecode(key_buffer, &idx, &rsa_key, (word32)key_buffer_size);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }

#ifdef WC_RSA_BLINDING
    /* RSA blinding requires an RNG associated with the key. Unlike the signing
     * routines, wc_RsaPrivateDecrypt() takes no RNG argument, so set it here. */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    ret = wc_RsaSetRNG(&rsa_key, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
#endif

    /* Get padding type and hash type */
    padding = wc_psa_get_rsa_padding(alg);
    hash_type = wc_psa_get_hash_type(alg);
#ifndef WOLFSSL_RSA_OAEP
    (void)hash_type;
#endif
    
    /* Decrypt message */
    if (padding == WC_RSA_PKCSV15_PAD) {
        ret = wc_RsaPrivateDecrypt(input, (word32)input_length, output, 
                                 (word32)output_size, &rsa_key);
    }
    else if (padding == WC_RSA_OAEP_PAD) {
        #ifdef WOLFSSL_RSA_OAEP
            int mgf = wc_psa_get_mgf(hash_type);
            if (mgf == WC_MGF1NONE) {
                ret = BAD_FUNC_ARG;
            }
            else {
                ret = wc_RsaPrivateDecrypt_ex(input, (word32)input_length, output,
                                              (word32)output_size, &rsa_key,
                                              WC_RSA_OAEP_PAD, hash_type,
                                              mgf, (byte*)salt,
                                              (word32)salt_length);
            }
        #else
            ret = NOT_COMPILED_IN;
        #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }

#ifdef WC_RSA_BLINDING
    wc_FreeRng(&rng);
#endif
    wc_FreeRsaKey(&rsa_key);

    if (ret < 0) {
        return wc_error_to_psa_status(ret);
    }

    *output_length = (size_t)ret;

    return PSA_SUCCESS;
}

/* Generate an RSA key pair */
psa_status_t psa_asymmetric_generate_key_rsa(psa_key_type_t key_type,
                                            size_t key_bits,
                                            uint8_t *private_key,
                                            size_t private_key_size,
                                            size_t *private_key_length,
                                            uint8_t *public_key,
                                            size_t public_key_size,
                                            size_t *public_key_length)
{
#ifndef WOLFSSL_KEY_GEN
    (void)key_type;
    (void)key_bits;
    (void)private_key;
    (void)private_key_size;
    (void)private_key_length;
    (void)public_key;
    (void)public_key_size;
    (void)public_key_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    int ret;
    RsaKey rsa_key;
    WC_RNG rng;
    word32 priv_len;
    word32 pub_len;
    
    /* Check if key type is RSA key pair */
    if (key_type != PSA_KEY_TYPE_RSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa_key, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_MakeRsaKey(&rsa_key, (int)key_bits, 65537, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export private key */
    priv_len = (word32)private_key_size;
    ret = wc_RsaKeyToDer(&rsa_key, private_key, priv_len);
    if (ret < 0) {
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    *private_key_length = (size_t)ret;
    
    /* Export public key if requested */
    if (public_key != NULL && public_key_length != NULL &&
        public_key_size > 0) {
        pub_len = (word32)public_key_size;
        ret = wc_RsaKeyToPublicDer(&rsa_key, public_key, pub_len);
        if (ret < 0) {
            wc_FreeRng(&rng);
            wc_FreeRsaKey(&rsa_key);
            return wc_error_to_psa_status(ret);
        }
        *public_key_length = (size_t)ret;
    }
    else if (public_key_length != NULL) {
        *public_key_length = 0;
    }
    
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&rsa_key);
    
    return PSA_SUCCESS;
#endif
}

/* Export an RSA public key or the public part of an RSA key pair */
psa_status_t psa_asymmetric_export_public_key_rsa(psa_key_type_t key_type,
                                                 size_t key_bits,
                                                 const uint8_t *key_buffer,
                                                 size_t key_buffer_size,
                                                 uint8_t *output,
                                                 size_t output_size,
                                                 size_t *output_length)
{
    int ret;
    RsaKey rsa_key;
    word32 idx = 0;
    
    (void)key_bits;

    /* Check if key type is RSA */
    if (key_type != PSA_KEY_TYPE_RSA_KEY_PAIR && 
        key_type != PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(key_buffer_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa_key, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Decode key */
    if (key_type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
        ret = wc_RsaPrivateKeyDecode(key_buffer, &idx, &rsa_key, (word32)key_buffer_size);
    }
    else {
        ret = wc_RsaPublicKeyDecode(key_buffer, &idx, &rsa_key, (word32)key_buffer_size);
    }
    
    if (ret != 0) {
        wc_FreeRsaKey(&rsa_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    ret = wc_RsaKeyToPublicDer(&rsa_key, output, (word32)output_size);
    
    wc_FreeRsaKey(&rsa_key);
    
    if (ret < 0) {
        return wc_error_to_psa_status(ret);
    }
    
    *output_length = (size_t)ret;
    
    return PSA_SUCCESS;
}

#else /* WOLFSSL_PSA_ENGINE && NO_RSA */

#include <psa/crypto.h>

psa_status_t psa_asymmetric_sign_rsa(psa_key_type_t key_type,
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
    (void)key_type;
    (void)key_bits;
    (void)key_buffer;
    (void)key_buffer_size;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_size;
    if (signature_length != NULL) {
        *signature_length = 0;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_asymmetric_verify_rsa(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length)
{
    (void)key_type;
    (void)key_bits;
    (void)key_buffer;
    (void)key_buffer_size;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

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
                                       size_t *output_length)
{
    (void)key_type;
    (void)key_bits;
    (void)key_buffer;
    (void)key_buffer_size;
    (void)alg;
    (void)input;
    (void)input_length;
    (void)salt;
    (void)salt_length;
    (void)output;
    (void)output_size;
    if (output_length != NULL) {
        *output_length = 0;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

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
                                       size_t *output_length)
{
    (void)key_type;
    (void)key_bits;
    (void)key_buffer;
    (void)key_buffer_size;
    (void)alg;
    (void)input;
    (void)input_length;
    (void)salt;
    (void)salt_length;
    (void)output;
    (void)output_size;
    if (output_length != NULL) {
        *output_length = 0;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* WOLFSSL_PSA_ENGINE && !NO_RSA */
