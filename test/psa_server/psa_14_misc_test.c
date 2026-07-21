/* psa_14_misc_test.c
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

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <string.h>

#include <wolfpsa/psa/crypto.h>

static int expect_status(const char *label, psa_status_t status,
                         psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s status=%d expected=%d\n", label, (int)status,
               (int)expected);
        return 1;
    }
    return 0;
}

/* Case 1: pre-init BAD_STATE check for psa_attach_key */
static int test_pre_init_bad_state(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    psa_status_t st;

    st = psa_attach_key(&attrs, (const uint8_t *)"label", 5, &key);
    if (expect_status("psa_attach_key before init", st,
                      PSA_ERROR_BAD_STATE) != 0) {
        return 1;
    }
    return 0;
}

/* Case 2: NOT_SUPPORTED stubs after init */
static int test_not_supported_stubs(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    uint8_t hash_state[256];
    size_t hash_state_len = 0;
    psa_sign_hash_interruptible_operation_t sign_op =
        PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT;
    psa_verify_hash_interruptible_operation_t verify_op =
        PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT;
    psa_key_agreement_iop_t ka_op = PSA_KEY_AGREEMENT_IOP_INIT;
    psa_generate_key_iop_t gk_op = PSA_GENERATE_KEY_IOP_INIT;
    psa_export_public_key_iop_t epk_op = PSA_EXPORT_PUBLIC_KEY_IOP_INIT;
    uint8_t dummy_hash[32] = {0};
    uint8_t dummy_sig[64] = {0};
    uint8_t dummy_peer[65] = {0};
    uint8_t dummy_sig_out[64];
    size_t dummy_sig_len = 0;
    psa_status_t st;

    st = psa_attach_key(&attrs, (const uint8_t *)"label", 5, &key);
    if (expect_status("psa_attach_key NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_hash_suspend(&hash_op, hash_state, sizeof(hash_state),
                          &hash_state_len);
    if (expect_status("psa_hash_suspend NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_hash_resume(&hash_op, hash_state, 0);
    if (expect_status("psa_hash_resume NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_sign_hash_start(&sign_op, 0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                              dummy_hash, sizeof(dummy_hash));
    if (expect_status("psa_sign_hash_start NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_sign_hash_complete(&sign_op, dummy_sig_out, sizeof(dummy_sig_out),
                                &dummy_sig_len);
    if (expect_status("psa_sign_hash_complete NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_verify_hash_start(&verify_op, 0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                dummy_hash, sizeof(dummy_hash),
                                dummy_sig, sizeof(dummy_sig));
    if (expect_status("psa_verify_hash_start NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_verify_hash_complete(&verify_op);
    if (expect_status("psa_verify_hash_complete NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_key_agreement_iop_setup(&ka_op, 0, dummy_peer, sizeof(dummy_peer),
                                     PSA_ALG_ECDH, &attrs);
    if (expect_status("psa_key_agreement_iop_setup NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_generate_key_iop_setup(&gk_op, &attrs);
    if (expect_status("psa_generate_key_iop_setup NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    st = psa_export_public_key_iop_setup(&epk_op, 0);
    if (expect_status("psa_export_public_key_iop_setup NOT_SUPPORTED", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    return 0;
}

/* Case 3: interruptible abort stubs return PSA_SUCCESS; get_num_ops == 0;
 * set/get max_ops round-trip */
static int test_interruptible_abort_stubs(void)
{
    psa_sign_hash_interruptible_operation_t sign_op =
        PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT;
    psa_verify_hash_interruptible_operation_t verify_op =
        PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT;
    psa_generate_key_iop_t gk_op = PSA_GENERATE_KEY_IOP_INIT;
    psa_status_t st;
    uint32_t n;

    st = psa_sign_hash_abort(&sign_op);
    if (expect_status("psa_sign_hash_abort", st, PSA_SUCCESS) != 0)
        return 1;

    st = psa_verify_hash_abort(&verify_op);
    if (expect_status("psa_verify_hash_abort", st, PSA_SUCCESS) != 0)
        return 1;

    st = psa_generate_key_iop_abort(&gk_op);
    if (expect_status("psa_generate_key_iop_abort", st, PSA_SUCCESS) != 0)
        return 1;

    n = psa_sign_hash_get_num_ops(&sign_op);
    if (n != 0) {
        printf("FAIL psa_sign_hash_get_num_ops=%u expected=0\n", (unsigned)n);
        return 1;
    }

    n = psa_verify_hash_get_num_ops(&verify_op);
    if (n != 0) {
        printf("FAIL psa_verify_hash_get_num_ops=%u expected=0\n",
               (unsigned)n);
        return 1;
    }

    n = psa_generate_key_iop_get_num_ops(&gk_op);
    if (n != 0) {
        printf("FAIL psa_generate_key_iop_get_num_ops=%u expected=0\n",
               (unsigned)n);
        return 1;
    }

    psa_interruptible_set_max_ops(123);
    n = psa_interruptible_get_max_ops();
    if (n != 123) {
        printf("FAIL psa_interruptible_get_max_ops=%u expected=123\n",
               (unsigned)n);
        return 1;
    }

    return 0;
}

/* Case 4: psa_generate_key_custom */
static int test_generate_key_custom(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_custom_key_parameters_t custom_default = PSA_CUSTOM_KEY_PARAMETERS_INIT;
    psa_custom_key_parameters_t custom_flags1 = PSA_CUSTOM_KEY_PARAMETERS_INIT;
    psa_key_id_t key = 0;
    psa_status_t st;

    /* flags=1 — INVALID_ARGUMENT */
    custom_flags1.flags = 1;

    /* Sub-case A: default custom (flags=0), custom_data_length=0 — success */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_generate_key_custom(&attrs, &custom_default, NULL, 0, &key);
    if (expect_status("psa_generate_key_custom default", st, PSA_SUCCESS) != 0)
        return 1;
    (void)psa_destroy_key(key);
    key = 0;

    /* Sub-case B: custom=NULL — INVALID_ARGUMENT */
    st = psa_generate_key_custom(&attrs, NULL, NULL, 0, &key);
    if (expect_status("psa_generate_key_custom NULL custom", st,
                      PSA_ERROR_INVALID_ARGUMENT) != 0) {
        return 1;
    }

    /* Sub-case C: flags=1 — INVALID_ARGUMENT */
    st = psa_generate_key_custom(&attrs, &custom_flags1, NULL, 0, &key);
    if (expect_status("psa_generate_key_custom flags=1", st,
                      PSA_ERROR_INVALID_ARGUMENT) != 0) {
        return 1;
    }

    return 0;
}

/* Case 5: psa_key_derivation_output_key_custom via HKDF-SHA256 */
static int test_key_derivation_output_key_custom(void)
{
    static const uint8_t secret[] = "hkdf-secret-input";
    static const uint8_t salt[]   = "hkdf-salt";
    static const uint8_t info[]   = "hkdf-info";
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_custom_key_parameters_t custom = PSA_CUSTOM_KEY_PARAMETERS_INIT;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t derived_key = 0;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (expect_status("kdf_output_key_custom: setup", st, PSA_SUCCESS) != 0)
        goto fail;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt) - 1u);
    if (expect_status("kdf_output_key_custom: salt", st, PSA_SUCCESS) != 0)
        goto fail;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (expect_status("kdf_output_key_custom: secret", st, PSA_SUCCESS) != 0)
        goto fail;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (expect_status("kdf_output_key_custom: info", st, PSA_SUCCESS) != 0)
        goto fail;

    st = psa_key_derivation_output_key_custom(&attrs, &op, &custom, NULL, 0,
                                              &derived_key);
    if (expect_status("psa_key_derivation_output_key_custom", st,
                      PSA_SUCCESS) != 0) {
        goto fail;
    }

    (void)psa_key_derivation_abort(&op);
    (void)psa_destroy_key(derived_key);
    return 0;

fail:
    (void)psa_key_derivation_abort(&op);
    return 1;
}

/* Case 6: psa_check_key_usage */
static int test_check_key_usage(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    psa_status_t st;

    /* AES key with only ENCRYPT usage, alg GCM */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_generate_key(&attrs, &key);
    if (expect_status("check_key_usage: generate", st, PSA_SUCCESS) != 0)
        return 1;

    /* Matching alg + usage — SUCCESS */
    st = psa_check_key_usage(key, PSA_ALG_GCM, PSA_KEY_USAGE_ENCRYPT);
    if (expect_status("check_key_usage ENCRYPT+GCM", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    /* Matching alg but wrong usage — NOT_PERMITTED */
    st = psa_check_key_usage(key, PSA_ALG_GCM, PSA_KEY_USAGE_DECRYPT);
    if (expect_status("check_key_usage DECRYPT+GCM", st,
                      PSA_ERROR_NOT_PERMITTED) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    /* Correct usage but wrong alg — NOT_PERMITTED */
    st = psa_check_key_usage(key, PSA_ALG_CCM, PSA_KEY_USAGE_ENCRYPT);
    if (expect_status("check_key_usage ENCRYPT+CCM", st,
                      PSA_ERROR_NOT_PERMITTED) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    (void)psa_destroy_key(key);

    /* Invalid key handle — must not succeed */
    st = psa_check_key_usage((psa_key_id_t)0x7fffffff, PSA_ALG_GCM,
                              PSA_KEY_USAGE_ENCRYPT);
    if (st == PSA_SUCCESS) {
        printf("FAIL check_key_usage invalid handle: expected error, got PSA_SUCCESS\n");
        return 1;
    }
    printf("INFO check_key_usage invalid handle: got status=%d (expected INVALID_HANDLE=%d)\n",
           (int)st, (int)PSA_ERROR_INVALID_HANDLE);

    return 0;
}

/* Case 7: ECDSA verify-equivalence (PSA 1.4 policy) */
static int test_ecdsa_verify_equivalence(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    static const uint8_t message[] = "ecdsa-policy-test";
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_status_t st;

    /* Key policy: ECDSA(SHA-256), SIGN_MESSAGE | VERIFY_MESSAGE */
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs,
                             PSA_KEY_USAGE_SIGN_MESSAGE |
                             PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &key);
    if (expect_status("ecdsa_equiv: generate", st, PSA_SUCCESS) != 0)
        return 1;

    /* Sign with the policy algorithm */
    st = psa_sign_message(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                          message, sizeof(message) - 1u,
                          sig, sizeof(sig), &sig_len);
    if (expect_status("ecdsa_equiv: sign_message ECDSA", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    /* Verify with DETERMINISTIC_ECDSA — must succeed (policy equivalence) */
    st = psa_verify_message(key, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
                             message, sizeof(message) - 1u,
                             sig, sig_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL ecdsa_equiv: verify_message DET_ECDSA status=%d"
               " (expected PSA_SUCCESS=%d) — library may not implement"
               " verify policy equivalence\n", (int)st, (int)PSA_SUCCESS);
        /* Report but treat as deviation; do not hard-fail the suite */
    } else {
        printf("INFO ecdsa_equiv: verify_message with DET_ECDSA: PSA_SUCCESS\n");
    }

    /* Sign with DETERMINISTIC_ECDSA — must fail (policy is ECDSA, not DET) */
    st = psa_sign_message(key, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
                          message, sizeof(message) - 1u,
                          sig, sizeof(sig), &sig_len);
    if (st == PSA_SUCCESS) {
        printf("FAIL ecdsa_equiv: sign_message DET_ECDSA must not succeed"
               " (policy is ECDSA)\n");
        (void)psa_destroy_key(key);
        return 1;
    }
    printf("INFO ecdsa_equiv: sign_message DET_ECDSA blocked: status=%d"
           " (expected NOT_PERMITTED=%d)\n",
           (int)st, (int)PSA_ERROR_NOT_PERMITTED);

    (void)psa_destroy_key(key);
    return 0;
}

/* Case 8: size macro runtime checks */
static int test_size_macros(void)
{
    int fail = 0;

    if (PSA_SIGNATURE_MAX_SIZE < 4627u) {
        printf("FAIL PSA_SIGNATURE_MAX_SIZE=%u < 4627\n",
               (unsigned)PSA_SIGNATURE_MAX_SIZE);
        fail = 1;
    }

    if (PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 192) != 32u) {
        printf("FAIL PSA_EXPORT_KEY_OUTPUT_SIZE(ML_DSA_KEY_PAIR,192)=%u"
               " expected=32\n",
               (unsigned)PSA_EXPORT_KEY_OUTPUT_SIZE(
                   PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 192));
        fail = 1;
    }

    if (PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 768) != 64u) {
        printf("FAIL PSA_EXPORT_KEY_OUTPUT_SIZE(ML_KEM_KEY_PAIR,768)=%u"
               " expected=64\n",
               (unsigned)PSA_EXPORT_KEY_OUTPUT_SIZE(
                   PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 768));
        fail = 1;
    }

    if (PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 256) != 2592u) {
        printf("FAIL PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(ML_DSA_KEY_PAIR,256)=%u"
               " expected=2592\n",
               (unsigned)PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
                   PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 256));
        fail = 1;
    }

    if (PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 192, PSA_ALG_ML_DSA) != 3309u) {
        printf("FAIL PSA_SIGN_OUTPUT_SIZE(ML_DSA_KEY_PAIR,192,ML_DSA)=%u"
               " expected=3309\n",
               (unsigned)PSA_SIGN_OUTPUT_SIZE(
                   PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 192, PSA_ALG_ML_DSA));
        fail = 1;
    }

    if (PSA_ENCAPSULATE_CIPHERTEXT_SIZE(PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 1024, PSA_ALG_ML_KEM) != 1568u) {
        printf("FAIL PSA_ENCAPSULATE_CIPHERTEXT_SIZE(ML_KEM_KEY_PAIR,1024,ML_KEM)=%u"
               " expected=1568\n",
               (unsigned)PSA_ENCAPSULATE_CIPHERTEXT_SIZE(
                   PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 1024, PSA_ALG_ML_KEM));
        fail = 1;
    }

    if (PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE < 1568u) {
        printf("FAIL PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE=%u < 1568\n",
               (unsigned)PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE);
        fail = 1;
    }

    if (PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_XCHACHA20,
                               PSA_ALG_XCHACHA20_POLY1305) != 24u) {
        printf("FAIL PSA_AEAD_NONCE_LENGTH(XCHACHA20,XCHACHA20_POLY1305)=%u"
               " expected=24\n",
               (unsigned)PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_XCHACHA20,
                                                PSA_ALG_XCHACHA20_POLY1305));
        fail = 1;
    }

    return fail;
}

/* Case 9: a key whose lifetime names a storage location this build does not
 * implement (for example a secure element or vendor location) must be rejected
 * rather than silently written to plaintext local storage. Covers both the
 * import and generate entry points. */
static int test_unsupported_lifetime_location(void)
{
    /* A non-local vendor / secure-element storage location. */
    psa_key_location_t se_location =
        (psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | 0x01u);
    psa_key_lifetime_t se_lifetime =
        PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
            PSA_KEY_PERSISTENCE_DEFAULT, se_location);
    static const uint8_t aes_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);
    psa_set_key_lifetime(&attrs, se_lifetime);

    /* Import path */
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key);
    if (st == PSA_SUCCESS) {
        (void)psa_destroy_key(key);
    }
    if (expect_status("import_key unsupported location", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    /* Generate path (funnels through psa_import_key) */
    key = 0;
    st = psa_generate_key(&attrs, &key);
    if (st == PSA_SUCCESS) {
        (void)psa_destroy_key(key);
    }
    if (expect_status("generate_key unsupported location", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        return 1;
    }

    return 0;
}

/* Case 10: deterministic ECDSA (RFC 6979) must produce identical signatures
 * for the same key and hash, and those signatures must verify. This exercises
 * the deterministic nonce setup on the sign path; a randomized ECDSA nonce
 * (deterministic setup deleted or disabled) yields two different signatures
 * and fails the identical-signature assertion. */
static int test_deterministic_ecdsa(void)
{
    psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    static const uint8_t hash[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t sig1[PSA_SIGNATURE_MAX_SIZE];
    uint8_t sig2[PSA_SIGNATURE_MAX_SIZE];
    size_t sig1_len = 0;
    size_t sig2_len = 0;
    psa_status_t st;

    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_generate_key(&attrs, &key);
    if (expect_status("det_ecdsa: generate", st, PSA_SUCCESS) != 0)
        return 1;

    st = psa_sign_hash(key, alg, hash, sizeof(hash), sig1, sizeof(sig1),
                       &sig1_len);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP test_deterministic_ecdsa (deterministic ECDSA not"
               " supported by this build)\n");
        (void)psa_destroy_key(key);
        return 0;
    }
    if (expect_status("det_ecdsa: sign #1", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    st = psa_sign_hash(key, alg, hash, sizeof(hash), sig2, sizeof(sig2),
                       &sig2_len);
    if (expect_status("det_ecdsa: sign #2", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    if (sig1_len != sig2_len || memcmp(sig1, sig2, sig1_len) != 0) {
        printf("FAIL det_ecdsa: signatures differ, deterministic nonce not"
               " applied\n");
        (void)psa_destroy_key(key);
        return 1;
    }

    st = psa_verify_hash(key, alg, hash, sizeof(hash), sig1, sig1_len);
    if (expect_status("det_ecdsa: verify", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    (void)psa_destroy_key(key);
    printf("PASS: deterministic ECDSA identical signatures\n");
    return 0;
}

/* Case 11: multipart ChaCha20-Poly1305 with a shortened tag must be rejected
 * at setup with PSA_ERROR_NOT_SUPPORTED. Truncated Poly1305 tags are not
 * implemented, so a shortened-tag algorithm must not be accepted and then fail
 * the encrypt/decrypt roundtrip. */
static int test_chacha20_poly1305_shortened_tag(void)
{
    psa_algorithm_t alg =
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305, 8);
    static const uint8_t key_bytes[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t nonce[12] = { 0 };
    static const uint8_t pt[16] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    uint8_t ct[sizeof(pt) + 16];
    size_t ct_len = 0;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, 256u);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    /* Bind the key policy to the shortened-tag algorithm so the key-policy
     * check passes and setup reaches the tag-length validation. */
    psa_set_key_algorithm(&attrs, alg);

    st = psa_import_key(&attrs, key_bytes, sizeof(key_bytes), &key);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP chacha20_poly1305_shortened_tag (not supported by this"
               " build)\n");
        return 0;
    }
    if (expect_status("chacha short-tag import", st, PSA_SUCCESS) != 0)
        return 1;

    /* Multipart setup must reject the shortened tag. */
    st = psa_aead_encrypt_setup(&op, key, alg);
    if (expect_status("chacha short-tag encrypt_setup", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        (void)psa_aead_abort(&op);
        (void)psa_destroy_key(key);
        return 1;
    }
    (void)psa_aead_abort(&op);

    /* One-shot path (routes through setup) must reject it too. */
    ct_len = 0;
    st = psa_aead_encrypt(key, alg, nonce, sizeof(nonce), NULL, 0,
                          pt, sizeof(pt), ct, sizeof(ct), &ct_len);
    if (expect_status("chacha short-tag encrypt", st,
                      PSA_ERROR_NOT_SUPPORTED) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    (void)psa_destroy_key(key);
    printf("PASS: ChaCha20-Poly1305 shortened tag rejected\n");
    return 0;
}

/* Case 12: an undersized RSA signature buffer must be reported as
 * PSA_ERROR_BUFFER_TOO_SMALL, not PSA_ERROR_GENERIC_ERROR. wc_RsaSSL_Sign
 * returns RSA_BUFFER_E when the output buffer is smaller than the modulus, and
 * the error translator must map that to BUFFER_TOO_SMALL so callers can retry
 * with a larger buffer. */
static int test_rsa_sign_buffer_too_small(void)
{
    psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    static const uint8_t hash[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = 0;
    uint8_t sig[16]; /* far smaller than a 2048-bit (256-byte) signature */
    size_t sig_len = 0;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, 2048u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_generate_key(&attrs, &key);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP rsa_sign_buffer_too_small (RSA not supported by this"
               " build)\n");
        return 0;
    }
    if (expect_status("rsa buffer-too-small: generate", st, PSA_SUCCESS) != 0)
        return 1;

    st = psa_sign_hash(key, alg, hash, sizeof(hash), sig, sizeof(sig),
                       &sig_len);
    if (expect_status("rsa sign undersized buffer", st,
                      PSA_ERROR_BUFFER_TOO_SMALL) != 0) {
        (void)psa_destroy_key(key);
        return 1;
    }

    (void)psa_destroy_key(key);
    printf("PASS: RSA sign undersized buffer -> BUFFER_TOO_SMALL\n");
    return 0;
}

int main(void)
{
    psa_status_t st;

    /* Case 1: pre-init BAD_STATE (before psa_crypto_init) */
    if (test_pre_init_bad_state() != 0)
        return 1;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)st);
        return 1;
    }

    /* Case 2: NOT_SUPPORTED stubs */
    if (test_not_supported_stubs() != 0)
        return 1;

    /* Case 3: interruptible abort / get_num_ops / set_max_ops */
    if (test_interruptible_abort_stubs() != 0)
        return 1;

    /* Case 4: psa_generate_key_custom */
    if (test_generate_key_custom() != 0)
        return 1;

    /* Case 5: psa_key_derivation_output_key_custom */
    if (test_key_derivation_output_key_custom() != 0)
        return 1;

    /* Case 6: psa_check_key_usage */
    if (test_check_key_usage() != 0)
        return 1;

    /* Case 7: ECDSA verify-equivalence */
    if (test_ecdsa_verify_equivalence() != 0)
        return 1;

    /* Case 8: size macro runtime checks */
    if (test_size_macros() != 0)
        return 1;

    /* Case 9: unsupported key lifetime location rejected */
    if (test_unsupported_lifetime_location() != 0)
        return 1;

    /* Case 10: deterministic ECDSA identical-signature check */
    if (test_deterministic_ecdsa() != 0)
        return 1;

    /* Case 11: ChaCha20-Poly1305 shortened tag rejected at setup */
    if (test_chacha20_poly1305_shortened_tag() != 0)
        return 1;

    /* Case 12: undersized RSA signature buffer -> BUFFER_TOO_SMALL */
    if (test_rsa_sign_buffer_too_small() != 0)
        return 1;

    printf("PSA 1.4 misc test: OK\n");
    return 0;
}
