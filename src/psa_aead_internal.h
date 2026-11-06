/* psa_aead_internal.h
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

#ifndef WOLFPSA_PSA_AEAD_INTERNAL_H
#define WOLFPSA_PSA_AEAD_INTERNAL_H

#include <stdint.h>

#include <wolfpsa/psa/crypto.h>

#include <wolfssl/wolfcrypt/aes.h>
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif

typedef struct wolfpsa_aead_ctx {
    psa_algorithm_t alg;
    psa_key_type_t key_type;
    size_t key_bits;
    int direction;
    uint8_t *key;
    size_t key_length;
    uint8_t nonce[PSA_AEAD_NONCE_MAX_SIZE];
    size_t nonce_length;
    uint8_t *aad;
    size_t aad_length;
    uint8_t *input;
    size_t input_length;
    size_t ad_expected;
    size_t plaintext_expected;
    size_t tag_length;
    int lengths_set;
    int ad_started;
    int body_started;

    /* Streaming state. Used when psa_aead_update() is called with a non-NULL
     * output: the payload is emitted from update() and only the tag (or, for
     * block-cipher AEAD, nothing) is left for finish()/verify(). The one-shot
     * path (update() with NULL output) buffers into input and leaves these
     * unused. */
    int streaming;
    /* One operation is GCM or CCM, never both, and sizeof(Aes) is over
     * 120 KB under WC_AES_BITSLICED, so the two share storage. */
#if (defined(HAVE_AESGCM) && defined(WOLFSSL_AESGCM_STREAM)) || \
    (defined(HAVE_AESCCM) && defined(WOLFSSL_AES_DIRECT))
    union {
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AESGCM_STREAM)
        Aes gcm;
#endif
#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_DIRECT)
        Aes ccm;
#endif
    } aes;
#endif
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AESGCM_STREAM)
    int gcm_inited;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ChaChaPoly_Aead chacha;
#endif
#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_DIRECT)
    /* Hand-rolled streaming CCM (wolfCrypt has no streaming CCM API): a CTR
     * for the ciphertext plus a running CBC-MAC for the tag. */
    int ccm_aes_inited;
    uint8_t ccm_ctr[16];
    uint8_t ccm_mac[16];
    uint8_t ccm_mblk[16];
    size_t ccm_mfill;
    uint8_t ccm_ks[16];
    size_t ccm_ks_off;
    size_t ccm_lenSz;
    size_t ccm_tag_len;
    int ccm_ks_valid;
#endif
} wolfpsa_aead_ctx_t;

static inline wolfpsa_aead_ctx_t*
wolfpsa_aead_get_ctx_ptr(psa_aead_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }

    return (wolfpsa_aead_ctx_t *)(uintptr_t)operation->opaque;
}

#endif /* WOLFPSA_PSA_AEAD_INTERNAL_H */
