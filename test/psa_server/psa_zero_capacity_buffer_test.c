/* psa_zero_capacity_buffer_test.c
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

/* Regression test for the PSA zero-capacity buffer contract: an output
 * buffer may be represented by (NULL, 0), and an input buffer by (NULL, 0);
 * such calls must reach the size/length checks and return the contract
 * status (BUFFER_TOO_SMALL, INVALID_SIGNATURE, ...), not
 * INVALID_ARGUMENT. Covers F-13860..F-13872. */

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <wolfpsa/psa/crypto.h>

#define TEST_KEY_BITS 2048

static int check_status(psa_status_t st, psa_status_t expected,
                        const char *what)
{
    if (st != expected) {
        printf("FAIL: %s (status=%d, expected %d)\n",
               what, (int)st, (int)expected);
        return 1;
    }
    return 0;
}

/* F-13861: psa_generate_random(NULL, 0) is a valid empty request. */
static int test_random_zero(void)
{
    int rc = 0;

    rc |= check_status(psa_generate_random(NULL, 0), PSA_SUCCESS,
                       "generate_random(NULL, 0)");
    if (rc == 0) {
        printf("PASS: random zero-length\n");
    }
    return rc;
}

/* F-13862: exporting a nonempty key into (NULL, 0) is BUFFER_TOO_SMALL. */
static int test_export_zero_capacity(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t aes_key_id = PSA_KEY_ID_NULL;
    psa_key_id_t ecc_key_id = PSA_KEY_ID_NULL;
    psa_key_id_t ed_key_id = PSA_KEY_ID_NULL;
    uint8_t aes_key[32];
    size_t len = 0;
    psa_status_t st;
    int rc = 0;

    memset(aes_key, 0x5a, sizeof(aes_key));

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    if (check_status(psa_import_key(&attrs, aes_key, sizeof(aes_key),
                                    &aes_key_id),
                     PSA_SUCCESS, "import AES key") != 0) {
        return 1;
    }
    rc |= check_status(psa_export_key(aes_key_id, NULL, 0, &len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "export_key(NULL, 0)");

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    if (check_status(psa_generate_key(&attrs, &ecc_key_id),
                     PSA_SUCCESS, "generate ECC key pair") != 0) {
        return 1;
    }
    rc |= check_status(psa_export_public_key(ecc_key_id, NULL, 0, &len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "export_public_key(NULL, 0)");

    /* The Edwards exporters used to hand the NULL straight to wolfCrypt,
     * which reported it as INVALID_ARGUMENT instead. */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 255);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_PURE_EDDSA);
    st = psa_generate_key(&attrs, &ed_key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP: Ed25519 export zero-capacity (not supported)\n");
    }
    else if (check_status(st, PSA_SUCCESS, "generate Ed25519 key") != 0) {
        rc |= 1;
    }
    else {
        rc |= check_status(psa_export_public_key(ed_key_id, NULL, 0, &len),
                           PSA_ERROR_BUFFER_TOO_SMALL,
                           "export_public_key(Ed25519, NULL, 0)");
        (void)psa_destroy_key(ed_key_id);
    }

    if (rc == 0) {
        printf("PASS: export zero-capacity\n");
    }
    return rc;
}

/* F-13860: psa_copy_key clears *target_key before any fallible step. */
static int test_copy_key_failure_clears_target(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t target = 0x12345678;
    psa_status_t st;

    st = psa_copy_key(0xdeadbeef, &attrs, &target);
    if (st == PSA_SUCCESS) {
        printf("FAIL: copy_key of a missing key unexpectedly succeeded\n");
        return 1;
    }
    if (target != PSA_KEY_ID_NULL) {
        printf("FAIL: copy_key left stale target id %u on failure\n",
               (unsigned)target);
        return 1;
    }
    printf("PASS: copy_key failure clears target\n");
    return 0;
}

/* F-13863: finishing a hash into (NULL, 0) is BUFFER_TOO_SMALL. */
static int test_hash_finish_zero_capacity(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t data[16];
    size_t len = 0;
    int rc = 0;

    memset(data, 0x42, sizeof(data));
    rc |= check_status(psa_hash_setup(&op, PSA_ALG_SHA_256), PSA_SUCCESS,
                       "hash setup");
    rc |= check_status(psa_hash_update(&op, data, sizeof(data)),
                       PSA_SUCCESS, "hash update");
    rc |= check_status(psa_hash_finish(&op, NULL, 0, &len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "hash_finish(NULL, 0)");
    if (rc == 0) {
        printf("PASS: hash finish zero-capacity\n");
    }
    return rc;
}

/* F-13864: a zero-length reference digest is a mismatch, not an argument. */
static int test_hash_compare_empty_reference(void)
{
    uint8_t data[3] = {'a', 'b', 'c'};
    int rc;

    rc = check_status(psa_hash_compare(PSA_ALG_SHA_256, data, sizeof(data),
                                       NULL, 0),
                      PSA_ERROR_INVALID_SIGNATURE,
                      "hash_compare(NULL, 0)");

    /* psa_hash_verify() must agree: an empty reference is a mismatch, not an
     * argument error. */
    {
        psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

        rc |= check_status(psa_hash_setup(&op, PSA_ALG_SHA_256),
                           PSA_SUCCESS, "hash setup for verify");
        rc |= check_status(psa_hash_update(&op, data, sizeof(data)),
                           PSA_SUCCESS, "hash update for verify");
        rc |= check_status(psa_hash_verify(&op, NULL, 0),
                           PSA_ERROR_INVALID_SIGNATURE,
                           "hash_verify(NULL, 0)");
        (void)psa_hash_abort(&op);
    }

    if (rc == 0) {
        printf("PASS: hash compare empty reference\n");
    }
    return rc;
}

/* F-13865: finishing a MAC into (NULL, 0) is BUFFER_TOO_SMALL. */
static int test_mac_finish_zero_capacity(void)
{
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t mac_key[32];
    uint8_t data[16];
    size_t len = 0;
    int rc = 0;

    memset(mac_key, 0x21, sizeof(mac_key));
    memset(data, 0x42, sizeof(data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    rc |= check_status(psa_import_key(&attrs, mac_key, sizeof(mac_key),
                                      &key),
                       PSA_SUCCESS, "import HMAC key");
    rc |= check_status(psa_mac_sign_setup(&op, key,
                                          PSA_ALG_HMAC(PSA_ALG_SHA_256)),
                       PSA_SUCCESS, "mac sign setup");
    rc |= check_status(psa_mac_update(&op, data, sizeof(data)),
                       PSA_SUCCESS, "mac update");
    rc |= check_status(psa_mac_sign_finish(&op, NULL, 0, &len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "mac_sign_finish(NULL, 0)");
    if (rc == 0) {
        printf("PASS: mac finish zero-capacity\n");
    }
    return rc;
}

/* F-13870: AEAD nonce and tag outputs accept (NULL, 0) as a size query. */
static int test_aead_zero_capacity(void)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t aes_key[32];
    uint8_t nonce[12] = {0};
    uint8_t data[16];
    size_t nonce_len = 0;
    size_t out_len = 0;
    size_t tag_len = 0;
    int rc = 0;

    memset(aes_key, 0x5a, sizeof(aes_key));
    memset(data, 0x42, sizeof(data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_AEAD_WITH_SHORTENED_TAG(
                              PSA_ALG_GCM, 16));
    rc |= check_status(psa_import_key(&attrs, aes_key, sizeof(aes_key),
                                      &key),
                       PSA_SUCCESS, "import AES key");

    rc |= check_status(psa_aead_encrypt_setup(&op, key,
                                              PSA_ALG_AEAD_WITH_SHORTENED_TAG(
                                                  PSA_ALG_GCM, 16)),
                       PSA_SUCCESS, "aead encrypt setup");
    rc |= check_status(psa_aead_generate_nonce(&op, NULL, 0, &nonce_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "aead_generate_nonce(NULL, 0)");
    rc |= check_status(psa_aead_set_nonce(&op, nonce, 0),
                       PSA_ERROR_INVALID_ARGUMENT,
                       "aead set empty nonce");

    rc |= check_status(psa_aead_set_nonce(&op, nonce, sizeof(nonce)),
                       PSA_SUCCESS, "aead set nonce");
    rc |= check_status(psa_aead_update_ad(&op, data, sizeof(data)),
                       PSA_SUCCESS, "aead update ad");
    rc |= check_status(psa_aead_update(&op, data, sizeof(data),
                                       NULL, 0, &out_len),
                       PSA_SUCCESS, "aead update");
    rc |= check_status(psa_aead_finish(&op, NULL, 0, &out_len,
                                       NULL, 0, &tag_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "aead_finish tag (NULL, 0)");

    if (rc == 0) {
        printf("PASS: aead zero-capacity nonce and tag\n");
    }
    return rc;
}

/* F-13871: verifying with a zero-length tag is INVALID_SIGNATURE. */
static int test_aead_verify_empty_tag(void)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t aes_key[32];
    uint8_t nonce[12] = {0};
    uint8_t data[16];
    size_t out_len = 0;
    int rc = 0;

    memset(aes_key, 0x5a, sizeof(aes_key));
    memset(data, 0x42, sizeof(data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_AEAD_WITH_SHORTENED_TAG(
                              PSA_ALG_GCM, 16));
    rc |= check_status(psa_import_key(&attrs, aes_key, sizeof(aes_key),
                                      &key),
                       PSA_SUCCESS, "import AES key");
    rc |= check_status(psa_aead_decrypt_setup(&op, key,
                                              PSA_ALG_AEAD_WITH_SHORTENED_TAG(
                                                  PSA_ALG_GCM, 16)),
                       PSA_SUCCESS, "aead decrypt setup");
    rc |= check_status(psa_aead_set_nonce(&op, nonce, sizeof(nonce)),
                       PSA_SUCCESS, "aead set nonce");
    rc |= check_status(psa_aead_update_ad(&op, data, sizeof(data)),
                       PSA_SUCCESS, "aead update ad");
    rc |= check_status(psa_aead_update(&op, data, sizeof(data),
                                       NULL, 0, &out_len),
                       PSA_SUCCESS, "aead update");
    rc |= check_status(psa_aead_verify(&op, NULL, 0, &out_len, NULL, 0),
                       PSA_ERROR_INVALID_SIGNATURE,
                       "aead_verify tag (NULL, 0)");

    if (rc == 0) {
        printf("PASS: aead verify empty tag\n");
    }
    return rc;
}

/* F-13872: generating an IV into (NULL, 0) is BUFFER_TOO_SMALL. */
static int test_cipher_generate_iv_zero_capacity(void)
{
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t aes_key[32];
    size_t len = 0;
    int rc = 0;

    memset(aes_key, 0x5a, sizeof(aes_key));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);
    rc |= check_status(psa_import_key(&attrs, aes_key, sizeof(aes_key),
                                      &key),
                       PSA_SUCCESS, "import AES key");
    rc |= check_status(psa_cipher_encrypt_setup(&op, key,
                                                PSA_ALG_CBC_NO_PADDING),
                       PSA_SUCCESS, "cipher encrypt setup");
    rc |= check_status(psa_cipher_generate_iv(&op, NULL, 0, &len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "cipher_generate_iv(NULL, 0)");

    /* generate_iv does not abort on BUFFER_TOO_SMALL, so the operation is
     * still live here. */
    (void)psa_cipher_abort(&op);
    (void)psa_destroy_key(key);

    if (rc == 0) {
        printf("PASS: cipher generate IV zero-capacity\n");
    }
    return rc;
}

/* F-13867/F-13868/F-13869: RSA encrypt/decrypt/sign/verify contracts. */
static int test_rsa_zero_capacity(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t crypt_key = PSA_KEY_ID_NULL;
    psa_key_id_t sign_key = PSA_KEY_ID_NULL;
    uint8_t msg[16];
    uint8_t ct[TEST_KEY_BITS / 8];
    uint8_t sig[TEST_KEY_BITS / 8];
    uint8_t hash[32];
    size_t ct_len = 0;
    size_t sig_len = 0;
    size_t out_len = 0;
    psa_algorithm_t sign_alg;
    int rc = 0;

    memset(msg, 0x42, sizeof(msg));
    memset(hash, 0x33, sizeof(hash));
    sign_alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);

    /* This wolfPSA build requires the key policy to name the exact
     * algorithm, so the crypt and sign paths use separate keys. */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, TEST_KEY_BITS);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PKCS1V15_CRYPT);
    rc |= check_status(psa_generate_key(&attrs, &crypt_key), PSA_SUCCESS,
                       "generate RSA crypt key pair");

    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, sign_alg);
    rc |= check_status(psa_generate_key(&attrs, &sign_key), PSA_SUCCESS,
                       "generate RSA sign key pair");
    if (rc != 0) {
        return rc;
    }

    /* Encrypt: output is always modulus-sized. */
    rc |= check_status(psa_asymmetric_encrypt(crypt_key,
                                              PSA_ALG_RSA_PKCS1V15_CRYPT,
                                              msg, sizeof(msg),
                                              NULL, 0,
                                              NULL, 0, &out_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "rsa encrypt (NULL, 0)");

    /* Real round trip, then decrypt into (NULL, 0). */
    rc |= check_status(psa_asymmetric_encrypt(crypt_key,
                                              PSA_ALG_RSA_PKCS1V15_CRYPT,
                                              msg, sizeof(msg),
                                              NULL, 0,
                                              ct, sizeof(ct), &ct_len),
                       PSA_SUCCESS,
                       "rsa encrypt real buffer");
    if (rc != 0) {
        return rc;
    }
    rc |= check_status(psa_asymmetric_decrypt(crypt_key,
                                              PSA_ALG_RSA_PKCS1V15_CRYPT,
                                              ct, ct_len,
                                              NULL, 0,
                                              NULL, 0, &out_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "rsa decrypt (NULL, 0)");

    /* Sign a hash into (NULL, 0). */
    rc |= check_status(psa_sign_hash(sign_key, sign_alg,
                                     hash, sizeof(hash),
                                     NULL, 0, &sig_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "rsa sign_hash (NULL, 0)");

    /* Verify with an empty signature: a mismatch, not an argument. */
    rc |= check_status(psa_verify_hash(sign_key, sign_alg,
                                       hash, sizeof(hash),
                                       NULL, 0),
                       PSA_ERROR_INVALID_SIGNATURE,
                       "rsa verify_hash (NULL, 0)");

    /* A valid signature verifies; a corrupted one maps to
    * INVALID_SIGNATURE (F-13867), not a generic error. */
    rc |= check_status(psa_sign_hash(sign_key, sign_alg,
                                     hash, sizeof(hash),
                                     sig, sizeof(sig), &sig_len),
                       PSA_SUCCESS,
                       "rsa sign_hash real buffer");
    if (rc != 0) {
        return rc;
    }
    rc |= check_status(psa_verify_hash(sign_key, sign_alg,
                                       hash, sizeof(hash),
                                       sig, sig_len),
                       PSA_SUCCESS, "rsa verify_hash valid signature");
    sig[sizeof(sig) / 2] ^= 0x01;
    rc |= check_status(psa_verify_hash(sign_key, sign_alg,
                                       hash, sizeof(hash),
                                       sig, sig_len),
                       PSA_ERROR_INVALID_SIGNATURE,
                       "rsa verify_hash corrupted signature");

    if (rc == 0) {
        printf("PASS: rsa zero-capacity and pad error mapping\n");
    }
    return rc;
}

/* F-13868: raw key agreement accepts (NULL, 0) as a size query. */
static int test_raw_key_agreement_zero_capacity(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t priv = PSA_KEY_ID_NULL;
    uint8_t pub[65];
    size_t pub_len = 0;
    size_t out_len = 0;
    int rc = 0;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);
    rc |= check_status(psa_generate_key(&attrs, &priv), PSA_SUCCESS,
                       "generate ECC key pair");
    rc |= check_status(psa_export_public_key(priv, pub, sizeof(pub),
                                             &pub_len),
                       PSA_SUCCESS, "export ECC public key");
    rc |= check_status(psa_raw_key_agreement(PSA_ALG_ECDH,
                                             priv,
                                             pub, pub_len,
                                             NULL, 0, &out_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "raw_key_agreement (NULL, 0)");

    if (rc == 0) {
        printf("PASS: raw key agreement zero-capacity\n");
    }
    return rc;
}

/* F-13866: encapsulation accepts (NULL, 0) and clears its outputs. */
static int test_encapsulate_zero_capacity(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t ss_attrs = psa_key_attributes_init();
    psa_key_id_t kp = PSA_KEY_ID_NULL;
    psa_key_id_t ss = 0x12345678;
    size_t ct_len = 0xdeadbeef;
    int rc = 0;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
    psa_set_key_bits(&attrs, 512);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ML_KEM);
    rc |= check_status(psa_generate_key(&attrs, &kp), PSA_SUCCESS,
                       "generate ML-KEM key pair");
    if (rc != 0) {
        return rc;
    }

    psa_set_key_type(&ss_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&ss_attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&ss_attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_bits(&ss_attrs, 0);

    rc |= check_status(psa_encapsulate(kp, PSA_ALG_ML_KEM, &ss_attrs,
                                       &ss, NULL, 0, &ct_len),
                       PSA_ERROR_BUFFER_TOO_SMALL,
                       "encapsulate (NULL, 0)");
    if (ss != PSA_KEY_ID_NULL || ct_len != 0) {
        printf("FAIL: encapsulate left outputs uncleared on failure "
               "(ss=%u ct_len=%zu)\n",
               (unsigned)ss, ct_len);
        rc = 1;
    }

    if (rc == 0) {
        printf("PASS: encapsulate zero-capacity\n");
    }
    return rc;
}

int main(void)
{
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

    rc |= test_random_zero();
    rc |= test_export_zero_capacity();
    rc |= test_copy_key_failure_clears_target();
    rc |= test_hash_finish_zero_capacity();
    rc |= test_hash_compare_empty_reference();
    rc |= test_mac_finish_zero_capacity();
    rc |= test_aead_zero_capacity();
    rc |= test_aead_verify_empty_tag();
    rc |= test_cipher_generate_iv_zero_capacity();
    rc |= test_rsa_zero_capacity();
    rc |= test_raw_key_agreement_zero_capacity();
    rc |= test_encapsulate_zero_capacity();

    if (rc != 0) {
        printf("PSA zero-capacity buffer test: FAIL\n");
        return 1;
    }
    printf("PSA zero-capacity buffer test: OK\n");
    return 0;
}
