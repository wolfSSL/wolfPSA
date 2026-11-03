/* psa_reset_outputs_test.c
 *
 * A failed call clears its outputs: output lengths are 0, key ids are
 * PSA_KEY_ID_NULL and psa_get_key_attributes() leaves initialized
 * attributes.
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MISSING_KEY PSA_KEY_ID_USER_MAX
#define STALE_KEY   ((psa_key_id_t)0x5a5a)

static int failures;

static void check_length(psa_status_t status, const size_t *length,
                         const char *what)
{
    if (status == PSA_SUCCESS || *length != 0) {
        printf("FAIL: %s: status %d, length %zu\n", what, (int)status,
               *length);
        failures++;
    }
}

static void check_key(psa_status_t status, const psa_key_id_t *key,
                      const char *what)
{
    if (status == PSA_SUCCESS || *key != PSA_KEY_ID_NULL) {
        printf("FAIL: %s: status %d, key 0x%x\n", what, (int)status,
               (unsigned)*key);
        failures++;
    }
}

/* Preset the output to a stale value, then run a call that fails */
#define CHECK_LENGTH(length, call)              \
    do {                                        \
        (length) = SIZE_MAX;                    \
        check_length((call), &(length), #call); \
    } while (0)

#define CHECK_KEY(key, call)                    \
    do {                                        \
        (key) = STALE_KEY;                      \
        check_key((call), &(key), #call);       \
    } while (0)

static void check_keys(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t buf[32];
    psa_key_id_t key;
    size_t len;
    psa_status_t status;

    memset(buf, 0, sizeof(buf));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_NONE);
    psa_set_key_bits(&attrs, 128);
    CHECK_KEY(key, psa_generate_key(&attrs, &key));
    CHECK_KEY(key, psa_generate_key_custom(&attrs, NULL, NULL, 0, &key));
    CHECK_KEY(key, psa_key_derivation_output_key(&attrs, &kdf, &key));
    CHECK_KEY(key, psa_key_derivation_output_key_custom(&attrs, &kdf, NULL,
                                                        NULL, 0, &key));

    /* NULL arguments */
    CHECK_KEY(key, psa_import_key(&attrs, NULL, 0, &key));
    CHECK_KEY(key, psa_copy_key(MISSING_KEY, NULL, &key));
    CHECK_KEY(key, psa_key_agreement(MISSING_KEY, buf, sizeof(buf),
                                     PSA_ALG_ECDH, NULL, &key));
    CHECK_KEY(key, psa_encapsulate(MISSING_KEY, PSA_ALG_ML_KEM, NULL, &key,
                                   buf, sizeof(buf), &len));
    CHECK_LENGTH(len, psa_encapsulate(MISSING_KEY, PSA_ALG_ML_KEM, NULL, &key,
                                      buf, sizeof(buf), &len));
    CHECK_KEY(key, psa_decapsulate(MISSING_KEY, PSA_ALG_ML_KEM, NULL, 0,
                                   &attrs, &key));
    CHECK_KEY(key, psa_unwrap_key(&attrs, MISSING_KEY, PSA_ALG_KW, NULL, 0,
                                  &key));

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
    status = psa_get_key_attributes(MISSING_KEY, &attrs);
    if (status == PSA_SUCCESS || psa_get_key_type(&attrs) != 0 ||
            psa_get_key_bits(&attrs) != 0 ||
            psa_get_key_usage_flags(&attrs) != 0 ||
            psa_get_key_algorithm(&attrs) != 0 ||
            psa_get_key_id(&attrs) != PSA_KEY_ID_NULL) {
        printf("FAIL: psa_get_key_attributes: status %d, attributes kept\n",
               (int)status);
        failures++;
    }
}

static void check_lengths(void)
{
    const psa_algorithm_t ecdsa = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    const psa_algorithm_t rsa = PSA_ALG_RSA_PKCS1V15_CRYPT;
    const psa_algorithm_t hmac = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    uint8_t in[32];
    uint8_t out[64];
    size_t len;

    memset(in, 0, sizeof(in));
    CHECK_LENGTH(len, psa_export_key(MISSING_KEY, out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_export_public_key(MISSING_KEY, out, sizeof(out),
                                            &len));
    CHECK_LENGTH(len, psa_hash_compute(PSA_ALG_NONE, in, sizeof(in), out,
                                       sizeof(out), &len));
    CHECK_LENGTH(len, psa_sign_hash(MISSING_KEY, ecdsa, in, sizeof(in), out,
                                    sizeof(out), &len));
    CHECK_LENGTH(len, psa_sign_message(MISSING_KEY, ecdsa, in, sizeof(in),
                                       out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_asymmetric_encrypt(MISSING_KEY, rsa, in, sizeof(in),
                                             NULL, 0, out, sizeof(out),
                                             &len));
    CHECK_LENGTH(len, psa_asymmetric_decrypt(MISSING_KEY, rsa, in, sizeof(in),
                                             NULL, 0, out, sizeof(out),
                                             &len));
    CHECK_LENGTH(len, psa_raw_key_agreement(PSA_ALG_ECDH, MISSING_KEY, in,
                                            sizeof(in), out, sizeof(out),
                                            &len));
    CHECK_LENGTH(len, psa_wrap_key(MISSING_KEY, PSA_ALG_KW, MISSING_KEY, out,
                                   sizeof(out), &len));
    CHECK_LENGTH(len, psa_mac_compute(MISSING_KEY, hmac, in, sizeof(in), out,
                                      sizeof(out), &len));
    CHECK_LENGTH(len, psa_cipher_encrypt(MISSING_KEY, PSA_ALG_CTR, in,
                                         sizeof(in), out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_cipher_decrypt(MISSING_KEY, PSA_ALG_CTR, in,
                                         sizeof(in), out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_aead_encrypt(MISSING_KEY, PSA_ALG_GCM, in, 12, NULL,
                                       0, in, sizeof(in), out, sizeof(out),
                                       &len));
    CHECK_LENGTH(len, psa_aead_decrypt(MISSING_KEY, PSA_ALG_GCM, in, 12, NULL,
                                       0, in, sizeof(in), out, sizeof(out),
                                       &len));
}

/* Each operation is inactive, so every call fails */
static void check_multipart(void)
{
    psa_hash_operation_t hash = PSA_HASH_OPERATION_INIT;
    psa_mac_operation_t mac = PSA_MAC_OPERATION_INIT;
    psa_cipher_operation_t cipher = PSA_CIPHER_OPERATION_INIT;
    psa_aead_operation_t aead = PSA_AEAD_OPERATION_INIT;
    uint8_t in[16];
    uint8_t out[64];
    size_t len;
    size_t tag_len;

    memset(in, 0, sizeof(in));
    CHECK_LENGTH(len, psa_hash_finish(&hash, out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_mac_sign_finish(&mac, out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_cipher_generate_iv(&cipher, out, sizeof(out),
                                             &len));
    CHECK_LENGTH(len, psa_cipher_finish(&cipher, out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_aead_generate_nonce(&aead, out, sizeof(out), &len));
    CHECK_LENGTH(len, psa_aead_update(&aead, in, sizeof(in), out, sizeof(out),
                                      &len));
    CHECK_LENGTH(len, psa_aead_finish(&aead, out, sizeof(out), &len, in,
                                      sizeof(in), &tag_len));
    CHECK_LENGTH(tag_len, psa_aead_finish(&aead, out, sizeof(out), &len, in,
                                          sizeof(in), &tag_len));
    CHECK_LENGTH(len, psa_aead_verify(&aead, out, sizeof(out), &len, in,
                                      sizeof(in)));
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

    check_keys();
    check_lengths();
    check_multipart();

    if (failures == 0) {
        printf("reset outputs tests: all passed\n");
        return 0;
    }
    printf("reset outputs tests: %d failure(s)\n", failures);
    return 1;
}
