/* psa_aead_gcm_short_tag_test.c
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

/* A shortened GCM tag round trips and is verified, or is NOT_SUPPORTED
 * below WOLFSSL_MIN_AUTH_TAG_SZ. test/Makefile builds this test with the
 * library's user_settings.h, so the macro matches libwolfpsa. */

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int ok, const char* what, size_t tagLen)
{
    if (!ok) {
        printf("FAIL: %s, %u byte tag\n", what, (unsigned)tagLen);
        failures++;
    }
}

static void test_tag_length(psa_key_id_t key, size_t tagLen)
{
    static const uint8_t nonce[12] = { 0 };
    static const uint8_t plaintext[16] = { 0 };
    /* AES-128-GCM, all-zero key, nonce and plaintext: ciphertext, then the
     * full tag */
    static const uint8_t expected[sizeof(plaintext) + 16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    const psa_algorithm_t alg =
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tagLen);
    uint8_t out[sizeof(expected)];
    uint8_t dec[sizeof(plaintext)];
    size_t outLen = 0;
    size_t decLen = 0;
    psa_status_t st;

    st = psa_aead_encrypt(key, alg, nonce, sizeof(nonce), NULL, 0,
                          plaintext, sizeof(plaintext), out, sizeof(out),
                          &outLen);
    if (tagLen < WOLFSSL_MIN_AUTH_TAG_SZ) {
        expect(st == PSA_ERROR_NOT_SUPPORTED, "encrypt NOT_SUPPORTED",
               tagLen);
        st = psa_aead_decrypt(key, alg, nonce, sizeof(nonce), NULL, 0,
                              expected, sizeof(plaintext) + tagLen, dec,
                              sizeof(dec), &decLen);
        expect(st == PSA_ERROR_NOT_SUPPORTED, "decrypt NOT_SUPPORTED",
               tagLen);
        return;
    }

    expect(st == PSA_SUCCESS, "encrypt", tagLen);
    expect(outLen == sizeof(plaintext) + tagLen, "encrypt length", tagLen);
    expect(memcmp(out, expected, sizeof(plaintext) + tagLen) == 0,
           "encrypt output", tagLen);

    st = psa_aead_decrypt(key, alg, nonce, sizeof(nonce), NULL, 0,
                          expected, sizeof(plaintext) + tagLen, dec,
                          sizeof(dec), &decLen);
    expect(st == PSA_SUCCESS, "decrypt", tagLen);
    expect(decLen == sizeof(plaintext) &&
           memcmp(dec, plaintext, sizeof(plaintext)) == 0,
           "decrypt output", tagLen);

    memcpy(out, expected, sizeof(plaintext) + tagLen);
    out[sizeof(plaintext) + tagLen - 1] ^= 0x01;
    st = psa_aead_decrypt(key, alg, nonce, sizeof(nonce), NULL, 0, out,
                          sizeof(plaintext) + tagLen, dec, sizeof(dec),
                          &decLen);
    expect(st == PSA_ERROR_INVALID_SIGNATURE, "decrypt with a bad tag",
           tagLen);
}

int main(void)
{
    static const uint8_t keyBytes[16] = { 0 };
    static const size_t tagLengths[] = { 4, 8, 12, 16 };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;
    size_t i;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init: %d\n", (int)st);
        return 1;
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs,
        PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 4));
    st = psa_import_key(&attrs, keyBytes, sizeof(keyBytes), &key);
    if (st != PSA_SUCCESS) {
        printf("FAIL: psa_import_key: %d\n", (int)st);
        return 1;
    }

    for (i = 0; i < sizeof(tagLengths) / sizeof(tagLengths[0]); i++) {
        test_tag_length(key, tagLengths[i]);
    }

    psa_destroy_key(key);

    if (failures != 0) {
        printf("GCM short tag tests: %d failure(s), minimum %d\n", failures,
               WOLFSSL_MIN_AUTH_TAG_SZ);
        return 1;
    }
    printf("GCM short tag tests: all passed, minimum %d\n",
           WOLFSSL_MIN_AUTH_TAG_SZ);
    return 0;
}
