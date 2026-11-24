/* psa_ccm_gated_test.c
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


/* CCM filtered out of PSA with wolfCrypt CCM kept: PSA refuses it, the
 * wolfPSA_AesCcm*() helpers report NOT_COMPILED_IN, and CCM* stays. */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfpsa/psa_ccm.h>

#if !defined(HAVE_AESCCM) || !defined(WOLFSSL_AES_DIRECT)
#error "this test needs wolfCrypt CCM and AES direct"
#endif
#if !defined(WOLFPSA_WANT_GATED) || defined(PSA_WANT_ALG_CCM)
#error "build the library with PSA_WANT_WITHOUT=PSA_WANT_ALG_CCM"
#endif
#ifndef PSA_WANT_ALG_CCM_STAR_NO_TAG
#error "CCM* is not in PSA_WANT_WITHOUT, so the generated config keeps it"
#endif

static int g_failures;

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

static psa_status_t ctr_run(psa_algorithm_t alg, const uint8_t *iv,
                            size_t iv_len, const uint8_t *in, uint8_t *out,
                            size_t len)
{
    static const uint8_t key[16] = { 0x3C };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_key_id_t k = PSA_KEY_ID_NULL;
    size_t out_len = 0;
    psa_status_t st;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, alg);
    st = psa_import_key(&attr, key, sizeof(key), &k);
    if (st == PSA_SUCCESS) {
        st = psa_cipher_encrypt_setup(&op, k, alg);
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_set_iv(&op, iv, iv_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_update(&op, in, len, out, len, &out_len);
    }
    if (st == PSA_SUCCESS && out_len != len) {
        st = PSA_ERROR_GENERIC_ERROR;
    }
    (void)psa_cipher_abort(&op);
    if (k != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(k);
    }
    return st;
}

/* CCM* without a tag is CTR from the counter block 0x01 || nonce || 0x0001. */
static void test_ccm_star_kept(void)
{
    static const uint8_t nonce[13] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
        0xAB, 0xAC
    };
    uint8_t ctr_iv[16];
    uint8_t in[32];
    uint8_t star[sizeof(in)];
    uint8_t ref[sizeof(in)];

    memset(in, 0x47, sizeof(in));
    ctr_iv[0] = 0x01;
    memcpy(ctr_iv + 1, nonce, sizeof(nonce));
    ctr_iv[14] = 0x00;
    ctr_iv[15] = 0x01;
    check(ctr_run(PSA_ALG_CCM_STAR_NO_TAG, nonce, sizeof(nonce), in, star,
                  sizeof(in)) == PSA_SUCCESS &&
          ctr_run(PSA_ALG_CTR, ctr_iv, sizeof(ctr_iv), in, ref,
                  sizeof(in)) == PSA_SUCCESS &&
          memcmp(star, ref, sizeof(ref)) == 0,
          "CCM* without a tag stays, equal to CTR on its counter block");
}

int main(void)
{
    static const uint8_t key[16] = { 0x5C };
    static const uint8_t nonce[13] = { 0x0B };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t k = PSA_KEY_ID_NULL;
    uint8_t pt[16];
    uint8_t ct[sizeof(pt) + 16];
    uint8_t tag[16];
    size_t len = 0;
    psa_status_t st;

    memset(pt, 0x61, sizeof(pt));
    check(psa_crypto_init() == PSA_SUCCESS, "psa_crypto_init");
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CCM);
    st = psa_import_key(&attr, key, sizeof(key), &k);
    if (st == PSA_SUCCESS) {
        st = psa_aead_encrypt(k, PSA_ALG_CCM, nonce, sizeof(nonce), NULL, 0,
                              pt, sizeof(pt), ct, sizeof(ct), &len);
        (void)psa_destroy_key(k);
    }
    check(st == PSA_ERROR_NOT_SUPPORTED, "PSA refuses CCM");
    check(wolfPSA_AesCcmEncrypt(key, sizeof(key), nonce, sizeof(nonce), NULL,
                                0, pt, sizeof(pt), ct, tag, sizeof(tag)) ==
          NOT_COMPILED_IN, "wolfPSA_AesCcmEncrypt reports NOT_COMPILED_IN");
    check(wolfPSA_AesCcmDecrypt(key, sizeof(key), nonce, sizeof(nonce), NULL,
                                0, ct, sizeof(pt), tag, sizeof(tag), pt) ==
          NOT_COMPILED_IN, "wolfPSA_AesCcmDecrypt reports NOT_COMPILED_IN");
    test_ccm_star_kept();
    printf("%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
