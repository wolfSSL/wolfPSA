/* psa_chacha20_poly1305.c
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
#include "psa_want_gate.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_CHACHAPOLY)

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

/* Encrypt using ChaCha20-Poly1305 */
psa_status_t psa_chacha20_poly1305_encrypt(
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    int ret;
    size_t required_size;
    
    /* Check parameters */
    if (key == NULL || key_length != CHACHA20_POLY1305_AEAD_KEYSIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (alg != PSA_ALG_CHACHA20_POLY1305) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (nonce == NULL || nonce_length != CHACHA20_POLY1305_AEAD_IV_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Additional data can be NULL if length is 0 */
    if (additional_data == NULL && additional_data_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Plaintext can be NULL if length is 0 */
    if (plaintext == NULL && plaintext_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(additional_data_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(plaintext_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (plaintext_length > SIZE_MAX - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    required_size = plaintext_length + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;

    /* Check output buffer size */
    if (ciphertext_size < required_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Encrypt using ChaCha20-Poly1305 */
    ret = wc_ChaCha20Poly1305_Encrypt(
        key,
        nonce,
        additional_data, (word32)additional_data_length,
        plaintext, (word32)plaintext_length,
        ciphertext,
        ciphertext + plaintext_length
    );
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Set output length */
    *ciphertext_length = required_size;
    
    return PSA_SUCCESS;
}

/* Decrypt using ChaCha20-Poly1305 */
psa_status_t psa_chacha20_poly1305_decrypt(
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    int ret;
    
    /* Check parameters */
    if (key == NULL || key_length != CHACHA20_POLY1305_AEAD_KEYSIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (alg != PSA_ALG_CHACHA20_POLY1305) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (nonce == NULL || nonce_length != CHACHA20_POLY1305_AEAD_IV_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Additional data can be NULL if length is 0 */
    if (additional_data == NULL && additional_data_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Ciphertext must include authentication tag */
    if (ciphertext_length < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(additional_data_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ciphertext_length -
            CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Check output buffer size */
    if (plaintext_size < ciphertext_length - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Decrypt using ChaCha20-Poly1305 */
    ret = wc_ChaCha20Poly1305_Decrypt(
        key,
        nonce,
        additional_data, (word32)additional_data_length,
        ciphertext, (word32)(ciphertext_length - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE),
        ciphertext + (ciphertext_length - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE),
        plaintext
    );
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Set output length */
    *plaintext_length = ciphertext_length - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_CHACHAPOLY */
