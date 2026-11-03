/* psa_rsa_status_test.c
 *
 * RSA operations report a bad input with the status PSA defines for the
 * operation: INVALID_SIGNATURE for a signature that does not verify,
 * INVALID_PADDING for a ciphertext that does not decrypt, INVALID_ARGUMENT
 * for a hash or message of the wrong length.
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

#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#define KEY_BITS  2048
#define KEY_BYTES (KEY_BITS / 8)
/* PKCS#1 v1.5 padding needs 11 bytes */
#define V15_TOO_LONG (KEY_BYTES - 10)

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got %d want %d\n", what, (int)got, (int)want);
        failures++;
    }
}

static psa_key_id_t import_pair(const uint8_t *der, size_t der_len,
                                psa_algorithm_t alg)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, alg);
    expect(psa_import_key(&attrs, der, der_len, &key), PSA_SUCCESS,
           "import key pair");
    return key;
}

static void check_v15_sign(const uint8_t *der, size_t der_len)
{
    const psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    psa_key_id_t key = import_pair(der, der_len, alg);
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    uint8_t sig[KEY_BYTES + 1];
    size_t sig_len = 0;
    psa_status_t status;

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));
    status = psa_sign_hash(key, alg, hash, sizeof(hash), sig, sizeof(sig),
                           &sig_len);
    expect(status, PSA_SUCCESS, "v1.5 sign");
    if (status == PSA_SUCCESS) {
        expect(psa_verify_hash(key, alg, hash, sizeof(hash), sig,
                               sig_len - 1),
               PSA_ERROR_INVALID_SIGNATURE, "v1.5 verify, signature short");
        expect(psa_verify_hash(key, alg, hash, sizeof(hash), sig,
                               sig_len + 1),
               PSA_ERROR_INVALID_SIGNATURE, "v1.5 verify, signature long");
    }
    psa_destroy_key(key);
}

static void check_v15_raw(const uint8_t *der, size_t der_len)
{
    const psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_SIGN_RAW;
    psa_key_id_t key = import_pair(der, der_len, alg);
    uint8_t msg[V15_TOO_LONG];
    uint8_t sig[KEY_BYTES];
    size_t sig_len = 0;

    memset(msg, 0x5c, sizeof(msg));
    expect(psa_sign_hash(key, alg, msg, sizeof(msg), sig, sizeof(sig),
                         &sig_len),
           PSA_ERROR_INVALID_ARGUMENT, "raw v1.5 sign, input too long");
    psa_destroy_key(key);
}

static void check_pss(const uint8_t *der, size_t der_len)
{
    const psa_algorithm_t alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
    psa_key_id_t key = import_pair(der, der_len, alg);
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    uint8_t sig[KEY_BYTES];
    size_t sig_len = 0;
    psa_status_t status;

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));
    expect(psa_sign_hash(key, alg, hash, sizeof(hash) - 1, sig, sizeof(sig),
                         &sig_len),
           PSA_ERROR_INVALID_ARGUMENT, "PSS sign, hash short");
    expect(psa_verify_hash(key, alg, hash, sizeof(hash) - 1, sig,
                           sizeof(sig)),
           PSA_ERROR_INVALID_ARGUMENT, "PSS verify, hash short");

    status = psa_sign_hash(key, alg, hash, sizeof(hash), sig, sizeof(sig),
                           &sig_len);
    expect(status, PSA_SUCCESS, "PSS sign");
    if (status == PSA_SUCCESS) {
        sig[sig_len - 1] ^= 0x01;
        expect(psa_verify_hash(key, alg, hash, sizeof(hash), sig, sig_len),
               PSA_ERROR_INVALID_SIGNATURE, "PSS verify, signature changed");
    }
    psa_destroy_key(key);
}

static void check_encrypt(const uint8_t *der, size_t der_len)
{
    const psa_algorithm_t v15 = PSA_ALG_RSA_PKCS1V15_CRYPT;
    const psa_algorithm_t oaep = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256);
    static const uint8_t label[] = { 'a', 'b', 'c' };
    psa_key_id_t key = import_pair(der, der_len, v15);
    uint8_t msg[V15_TOO_LONG];
    uint8_t out[KEY_BYTES];
    size_t out_len = 0;
    uint8_t plain[KEY_BYTES];
    size_t plain_len = 0;
    psa_status_t status;

    memset(msg, 0x5c, sizeof(msg));
    expect(psa_asymmetric_encrypt(key, v15, msg, sizeof(msg), NULL, 0, out,
                                  sizeof(out), &out_len),
           PSA_ERROR_INVALID_ARGUMENT, "v1.5 encrypt, input too long");
    psa_destroy_key(key);

    key = import_pair(der, der_len, oaep);
    status = psa_asymmetric_encrypt(key, oaep, msg, 16, label, sizeof(label),
                                    out, sizeof(out), &out_len);
    expect(status, PSA_SUCCESS, "OAEP encrypt");
    if (status == PSA_SUCCESS) {
        expect(psa_asymmetric_decrypt(key, oaep, out, out_len, NULL, 0,
                                      plain, sizeof(plain), &plain_len),
               PSA_ERROR_INVALID_PADDING, "OAEP decrypt, wrong label");
    }
    psa_destroy_key(key);
}

int main(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    static uint8_t der[PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(KEY_BITS)];
    size_t der_len = 0;
    psa_status_t status;

    status = psa_crypto_init();
    expect(status, PSA_SUCCESS, "psa_crypto_init");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    status = psa_generate_key(&attrs, &key);
    if (status == PSA_SUCCESS) {
        status = psa_export_key(key, der, sizeof(der), &der_len);
    }
    psa_destroy_key(key);
    expect(status, PSA_SUCCESS, "generate and export key pair");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    check_v15_sign(der, der_len);
    check_v15_raw(der, der_len);
    check_pss(der, der_len);
    check_encrypt(der, der_len);

    if (failures == 0) {
        printf("RSA status tests: all passed\n");
        return 0;
    }
    printf("RSA status tests: %d failure(s)\n", failures);
    return 1;
}
