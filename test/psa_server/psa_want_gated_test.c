/* psa_want_gated_test.c
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

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfpsa/psa_gcm.h>

#if !defined(HAVE_AESGCM) || !defined(HAVE_AESCCM)
#error "this test needs wolfCrypt GCM and CCM"
#endif
#ifndef WOLFPSA_WANT_GATED
#error "build the library with PSA_WANT_WITHOUT=PSA_WANT_ALG_GCM"
#endif
#if defined(PSA_WANT_ALG_GCM) || defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC)
#error "GCM and SP800-108 HMAC should be filtered out of the generated config"
#endif

static int g_failures;

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

static psa_key_id_t aes_key(psa_algorithm_t alg)
{
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = PSA_KEY_ID_NULL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);
    if (psa_import_key(&attr, key, sizeof(key), &id) != PSA_SUCCESS) {
        id = PSA_KEY_ID_NULL;
    }
    return id;
}

static void test_gcm_refused(void)
{
    uint8_t nonce[12] = { 0 };
    uint8_t pt[16] = { 0 };
    uint8_t ct[32];
    size_t len = 0;
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t k = aes_key(PSA_ALG_GCM);
    psa_status_t st;

    st = psa_aead_encrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce), NULL, 0,
                          pt, sizeof(pt), ct, sizeof(ct), &len);
    check(st == PSA_ERROR_NOT_SUPPORTED, "one-shot GCM is not supported");
    st = psa_aead_encrypt_setup(&op, k, PSA_ALG_GCM);
    check(st == PSA_ERROR_NOT_SUPPORTED, "multipart GCM is not supported");
    (void)psa_aead_abort(&op);
    (void)psa_destroy_key(k);
}

static void test_ccm_kept(void)
{
    uint8_t nonce[12] = { 1 };
    uint8_t pt[24];
    uint8_t ct[40];
    uint8_t back[24];
    size_t clen = 0;
    size_t plen = 0;
    psa_key_id_t k = aes_key(PSA_ALG_CCM);
    int ok;

    (void)memset(pt, 0x5a, sizeof(pt));
    ok = k != PSA_KEY_ID_NULL &&
         psa_aead_encrypt(k, PSA_ALG_CCM, nonce, sizeof(nonce), NULL, 0,
                          pt, sizeof(pt), ct, sizeof(ct), &clen) == PSA_SUCCESS &&
         psa_aead_decrypt(k, PSA_ALG_CCM, nonce, sizeof(nonce), NULL, 0,
                          ct, clen, back, sizeof(back), &plen) == PSA_SUCCESS &&
         plen == sizeof(pt) && memcmp(back, pt, sizeof(pt)) == 0;
    check(ok, "CCM still encrypts and decrypts");
    (void)psa_destroy_key(k);
}

static void test_wolfcrypt_gcm_kept(void)
{
    static const uint8_t key[16] = { 0x11 };
    uint8_t iv[12] = { 0 };
    uint8_t pt[16] = { 0 };
    uint8_t ct[16];
    uint8_t tag[16];
    Aes aes;
    int ok;

    ok = wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
         wc_AesGcmSetKey(&aes, key, sizeof(key)) == 0 &&
         wc_AesGcmEncrypt(&aes, ct, pt, sizeof(pt), iv, sizeof(iv),
                          tag, sizeof(tag), NULL, 0) == 0;
    wc_AesFree(&aes);
    check(ok, "wolfCrypt one-shot GCM is still available");
#ifdef WOLFSSL_AESGCM_STREAM
    check(wolfPSA_AesGcmEncrypt(key, sizeof(key), iv, sizeof(iv), NULL, 0,
                                pt, sizeof(pt), ct, tag, sizeof(tag)) ==
          NOT_COMPILED_IN, "wolfPSA_AesGcmEncrypt reports NOT_COMPILED_IN");
    check(wolfPSA_AesGcmDecrypt(key, sizeof(key), iv, sizeof(iv), NULL, 0,
                                ct, sizeof(pt), tag, sizeof(tag), pt) ==
          NOT_COMPILED_IN, "wolfPSA_AesGcmDecrypt reports NOT_COMPILED_IN");
#endif
}

static psa_status_t kdf_run(psa_algorithm_t alg)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    static const uint8_t secret[16] = { 0x3c };
    uint8_t out[32];
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op,
            PSA_KEY_DERIVATION_INPUT_SECRET, secret, sizeof(secret));
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op,
            PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_bytes(&op, out, sizeof(out));
    }
    (void)psa_key_derivation_abort(&op);
    return st;
}

static void test_sp800_108_refused(void)
{
    check(kdf_run(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256)) ==
          PSA_ERROR_NOT_SUPPORTED, "SP800-108 HMAC is not supported");
    check(kdf_run(PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS,
          "HKDF on the same HMAC still derives");
}

int main(void)
{
    check(psa_crypto_init() == PSA_SUCCESS, "psa_crypto_init");
    test_gcm_refused();
    test_ccm_kept();
    test_wolfcrypt_gcm_kept();
    test_sp800_108_refused();
    printf("%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
