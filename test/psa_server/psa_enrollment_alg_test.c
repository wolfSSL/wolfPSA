/* psa_enrollment_alg_test.c
 *
 * With WOLFPSA_ENROLLMENT_ALG, a volatile key's enrollment algorithm is a
 * second permitted algorithm: each operation accepts either one, and
 * psa_copy_key() intersects it. Links a library built with that option.
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

static int failures;

static void check(const char *what, const char *step, psa_status_t got,
                  psa_status_t want)
{
    if (got != want) {
        printf("FAIL: %s, %s: got %d want %d\n", what, step, (int)got,
               (int)want);
        failures++;
    }
}

/* Generate a volatile key with an enrollment algorithm */
static psa_key_id_t make_key(psa_key_type_t type, size_t bits,
                             psa_key_usage_t usage, psa_algorithm_t alg,
                             psa_algorithm_t alg2)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t status;

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, usage);
    psa_set_key_algorithm(&attrs, alg);
    psa_set_key_enrollment_algorithm(&attrs, alg2);
    status = psa_generate_key(&attrs, &key);
    check("make key", "generate", status, PSA_SUCCESS);
    if (status == PSA_SUCCESS) {
        check("make key", "get attributes", psa_get_key_attributes(key, &got),
              PSA_SUCCESS);
        if (psa_get_key_enrollment_algorithm(&got) != alg2) {
            printf("FAIL: enrollment algorithm 0x%08x want 0x%08x\n",
                   (unsigned)psa_get_key_enrollment_algorithm(&got),
                   (unsigned)alg2);
            failures++;
        }
    }
    return key;
}

static psa_status_t cipher(psa_key_id_t key, psa_algorithm_t alg)
{
    uint8_t in[16] = {0};
    uint8_t out[32];
    size_t out_len = 0;

    return psa_cipher_encrypt(key, alg, in, sizeof(in), out, sizeof(out),
                              &out_len);
}

static psa_status_t mac(psa_key_id_t key, psa_algorithm_t alg)
{
    uint8_t out[PSA_MAC_MAX_SIZE];
    size_t out_len = 0;

    return psa_mac_compute(key, alg, (const uint8_t *)"abc", 3, out,
                           sizeof(out), &out_len);
}

static psa_status_t aead(psa_key_id_t key, psa_algorithm_t alg)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    uint8_t nonce[PSA_AEAD_NONCE_MAX_SIZE] = {0};
    size_t nonce_len = 0;
    uint8_t ct[32];
    uint8_t pt[32];
    size_t ct_len = 0;
    size_t pt_len = 0;
    psa_status_t status;

    status = psa_get_key_attributes(key, &attrs);
    if (status == PSA_SUCCESS) {
        nonce_len = PSA_AEAD_NONCE_LENGTH(psa_get_key_type(&attrs), alg);
        status = psa_aead_encrypt(key, alg, nonce, nonce_len, NULL, 0,
                                  (const uint8_t *)"abc", 3, ct, sizeof(ct),
                                  &ct_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_decrypt(key, alg, nonce, nonce_len, NULL, 0, ct,
                                  ct_len, pt, sizeof(pt), &pt_len);
    }
    return status;
}

static psa_status_t sign(psa_key_id_t key, psa_algorithm_t alg)
{
    uint8_t hash[32] = {0};
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;

    return psa_sign_hash(key, alg, hash, sizeof(hash), sig, sizeof(sig),
                         &sig_len);
}

static psa_status_t agree(psa_key_id_t key, psa_algorithm_t alg)
{
    uint8_t pub[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
    uint8_t secret[PSA_BITS_TO_BYTES(256)];
    size_t pub_len = 0;
    size_t secret_len = 0;
    psa_status_t status;

    status = psa_export_public_key(key, pub, sizeof(pub), &pub_len);
    if (status == PSA_SUCCESS) {
        status = psa_raw_key_agreement(alg, key, pub, pub_len, secret,
                                       sizeof(secret), &secret_len);
    }
    return status;
}

static psa_status_t derive(psa_key_id_t key, psa_algorithm_t alg)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;

    status = psa_key_derivation_setup(&op, alg);
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_key(
            &op, PSA_KEY_DERIVATION_INPUT_SECRET, key);
    }
    psa_key_derivation_abort(&op);
    return status;
}

/* Wrap the key with itself, then unwrap it */
static psa_status_t wrap(psa_key_id_t key, psa_algorithm_t alg)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    uint8_t data[32];
    size_t data_len = 0;
    psa_key_id_t out = PSA_KEY_ID_NULL;
    psa_status_t status;

    status = psa_wrap_key(key, alg, key, data, sizeof(data), &data_len);
    if (status == PSA_SUCCESS) {
        psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
        status = psa_unwrap_key(&attrs, key, alg, data, data_len, &out);
        psa_destroy_key(out);
    }
    return status;
}

static psa_status_t kem(psa_key_id_t key, psa_algorithm_t alg)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    uint8_t ct[PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE];
    size_t ct_len = 0;
    psa_key_id_t out = PSA_KEY_ID_NULL;
    psa_status_t status;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    status = psa_encapsulate(key, alg, &attrs, &out, ct, sizeof(ct), &ct_len);
    psa_destroy_key(out);
    out = PSA_KEY_ID_NULL;
    if (status == PSA_SUCCESS) {
        status = psa_decapsulate(key, alg, ct, ct_len, &attrs, &out);
        psa_destroy_key(out);
    }
    return status;
}

/* One key per row: alg2 is permitted as well as alg, other (if set) is not */
static void check_operations(void)
{
    static const struct {
        const char *what;
        psa_key_type_t type;
        size_t bits;
        psa_key_usage_t usage;
        psa_algorithm_t alg;
        psa_algorithm_t alg2;
        psa_algorithm_t other;
        psa_status_t (*use)(psa_key_id_t key, psa_algorithm_t alg);
    } cases[] = {
        { "cipher", PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_ENCRYPT,
          PSA_ALG_CTR, PSA_ALG_CBC_NO_PADDING, PSA_ALG_ECB_NO_PADDING,
          cipher },
        { "MAC", PSA_KEY_TYPE_HMAC, 256, PSA_KEY_USAGE_SIGN_MESSAGE,
          PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_ALG_HMAC(PSA_ALG_SHA_384),
          PSA_ALG_HMAC(PSA_ALG_SHA_512), mac },
        { "AEAD", PSA_KEY_TYPE_AES, 128,
          PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
          PSA_ALG_GCM, PSA_ALG_CCM,
          PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 12), aead },
        { "XChaCha20-Poly1305", PSA_KEY_TYPE_XCHACHA20, 256,
          PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_NONE,
          PSA_ALG_XCHACHA20_POLY1305, PSA_ALG_NONE, aead },
        { "Ascon-AEAD128", PSA_KEY_TYPE_ASCON, 128,
          PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_NONE,
          PSA_ALG_ASCON_AEAD128, PSA_ALG_NONE, aead },
        { "key wrap", PSA_KEY_TYPE_AES, 128,
          PSA_KEY_USAGE_WRAP | PSA_KEY_USAGE_UNWRAP | PSA_KEY_USAGE_EXPORT,
          PSA_ALG_CTR, PSA_ALG_KW, PSA_ALG_NONE, wrap },
        { "ML-KEM", PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 768,
          PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_NONE,
          PSA_ALG_ML_KEM, PSA_ALG_NONE, kem },
        { "ECDSA", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
          PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
          PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
          PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), sign },
        { "ECDH", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
          PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE,
          PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), PSA_ALG_ECDH, PSA_ALG_NONE,
          agree },
        { "KDF", PSA_KEY_TYPE_DERIVE, 256, PSA_KEY_USAGE_DERIVE,
          PSA_ALG_HKDF(PSA_ALG_SHA_256), PSA_ALG_HKDF(PSA_ALG_SHA_384),
          PSA_ALG_HKDF(PSA_ALG_SHA_512), derive },
    };
    psa_key_id_t key;
    psa_algorithm_t use_alg;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        key = make_key(cases[i].type, cases[i].bits, cases[i].usage,
                       cases[i].alg, cases[i].alg2);
        if (key == PSA_KEY_ID_NULL) {
            continue;
        }
        use_alg = cases[i].alg2;
        if (use_alg == PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)) {
            use_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        }
        check(cases[i].what, "enrollment algorithm",
              cases[i].use(key, use_alg), PSA_SUCCESS);
        if (cases[i].other != PSA_ALG_NONE) {
            check(cases[i].what, "other algorithm",
                  cases[i].use(key, cases[i].other), PSA_ERROR_NOT_PERMITTED);
        }
        check(cases[i].what, "psa_check_key_usage",
              psa_check_key_usage(key, use_alg, 0), PSA_SUCCESS);
        psa_destroy_key(key);
    }
}

/* psa_copy_key() intersects alg2, or drops it if either side has none */
static void check_copy(void)
{
    static const struct {
        const char *what;
        psa_algorithm_t target_alg2;
        psa_status_t want;
        psa_algorithm_t want_alg2;
    } cases[] = {
        { "copy, same alg2", PSA_ALG_CBC_NO_PADDING, PSA_SUCCESS,
          PSA_ALG_CBC_NO_PADDING },
        { "copy, no alg2", PSA_ALG_NONE, PSA_SUCCESS, PSA_ALG_NONE },
        { "copy, other alg2", PSA_ALG_ECB_NO_PADDING,
          PSA_ERROR_INVALID_ARGUMENT, PSA_ALG_NONE },
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t source;
    psa_key_id_t copy;
    psa_status_t status;
    size_t i;

    source = make_key(PSA_KEY_TYPE_AES, 128,
                      PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_COPY,
                      PSA_ALG_CTR, PSA_ALG_CBC_NO_PADDING);
    if (source == PSA_KEY_ID_NULL) {
        return;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        copy = PSA_KEY_ID_NULL;
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
        psa_set_key_enrollment_algorithm(&attrs, cases[i].target_alg2);
        status = psa_copy_key(source, &attrs, &copy);
        check(cases[i].what, "psa_copy_key", status, cases[i].want);
        if (status == PSA_SUCCESS &&
            (psa_get_key_attributes(copy, &got) != PSA_SUCCESS ||
             psa_get_key_enrollment_algorithm(&got) != cases[i].want_alg2)) {
            printf("FAIL: %s: enrollment algorithm 0x%08x\n", cases[i].what,
                   (unsigned)psa_get_key_enrollment_algorithm(&got));
            failures++;
        }
        psa_destroy_key(copy);
    }
    psa_destroy_key(source);
}

/* Reading a persistent key clears a stale enrollment algorithm */
static void check_persistent(void)
{
    static const uint8_t data[16] = {0};
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
    psa_set_key_id(&attrs, PSA_KEY_ID_USER_MIN + 2408u);
    check("persistent", "import",
          psa_import_key(&attrs, data, sizeof(data), &key), PSA_SUCCESS);

    psa_set_key_enrollment_algorithm(&got, PSA_ALG_CBC_NO_PADDING);
    check("persistent", "get attributes", psa_get_key_attributes(key, &got),
          PSA_SUCCESS);
    if (psa_get_key_enrollment_algorithm(&got) != PSA_ALG_NONE) {
        printf("FAIL: persistent: enrollment algorithm 0x%08x\n",
               (unsigned)psa_get_key_enrollment_algorithm(&got));
        failures++;
    }
    check("persistent", "enrollment algorithm",
          cipher(key, PSA_ALG_CBC_NO_PADDING), PSA_ERROR_NOT_PERMITTED);
    psa_destroy_key(key);
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

    check_operations();
    check_copy();
    check_persistent();

    if (failures == 0) {
        printf("Enrollment algorithm tests: all passed\n");
        return 0;
    }
    printf("Enrollment algorithm tests: %d failure(s)\n", failures);
    return 1;
}
