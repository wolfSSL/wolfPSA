/* Regression: SP800-108 input_key accepts compatible MAC keys.
 *
 * psa_key_derivation_input_key() required PSA_KEY_TYPE_DERIVE for
 * every non-PBKDF2 secret, rejecting the algorithm-compatible keys
 * the PSA API allows: an HMAC key for PSA_ALG_SP800_108_COUNTER_HMAC
 * and an AES key for PSA_ALG_SP800_108_COUNTER_CMAC (the key
 * material is the raw MAC key in both cases). Keys are imported with
 * the KDF algorithm, matching the existing input_key algorithm
 * match.
 *
 * Each accepted case derives 16 bytes via input_key and compares
 * against the same derivation done with input_bytes on the same raw
 * key material. The cross-variant cases must stay rejected.
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

static int expect_status(const char *label, psa_status_t status,
                         psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s: status 0x%08x want 0x%08x\n", label,
               (unsigned)status, (unsigned)expected);
        return 1;
    }
    return 0;
}

/* Derive dklen bytes from SP800-108 with the given raw secret.
 * key == NULL uses input_key(key_id) as the secret source. */
static psa_status_t derive(psa_key_derivation_operation_t *op,
                           psa_algorithm_t alg,
                           const uint8_t *secret, size_t secret_len,
                           psa_key_id_t key_id,
                           const uint8_t *label, size_t label_len,
                           const uint8_t *context, size_t context_len,
                           uint8_t *dk, size_t dklen)
{
    psa_status_t status;

    status = psa_key_derivation_setup(op, alg);
    if (status != PSA_SUCCESS)
        return status;

    if (key_id != PSA_KEY_ID_NULL) {
        status = psa_key_derivation_input_key(op,
                                              PSA_KEY_DERIVATION_INPUT_SECRET,
                                              key_id);
    }
    else {
        status = psa_key_derivation_input_bytes(op,
                                                PSA_KEY_DERIVATION_INPUT_SECRET,
                                                secret, secret_len);
    }
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(
            op, PSA_KEY_DERIVATION_INPUT_LABEL, label, label_len);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(
            op, PSA_KEY_DERIVATION_INPUT_CONTEXT, context, context_len);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_output_bytes(op, dk, dklen);

    psa_key_derivation_abort(op);
    return status;
}

static psa_status_t import_usage_key(const uint8_t *key, size_t key_len,
                                     psa_algorithm_t kdf_alg,
                                     psa_key_type_t type,
                                     psa_key_usage_t usage,
                                     psa_key_id_t *kid)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();

    *kid = PSA_KEY_ID_NULL;
    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, (psa_key_bits_t)(key_len * 8u));
    psa_set_key_usage_flags(&attrs, usage);
    psa_set_key_algorithm(&attrs, kdf_alg);
    return psa_import_key(&attrs, key, key_len, kid);
}

static psa_status_t import_secret_key(const uint8_t *key, size_t key_len,
                                      psa_algorithm_t kdf_alg,
                                      psa_key_type_t type,
                                      psa_key_id_t *kid)
{
    return import_usage_key(key, key_len, kdf_alg, type,
                            PSA_KEY_USAGE_DERIVE, kid);
}

static const uint8_t kdf_input[16] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

/* Set up alg and, for PBKDF2, input the cost that must come first */
static psa_status_t kdf_start(psa_key_derivation_operation_t *op,
                              psa_algorithm_t alg)
{
    psa_status_t status = psa_key_derivation_setup(op, alg);

    if (status == PSA_SUCCESS && PSA_ALG_IS_PBKDF2(alg)) {
        status = psa_key_derivation_input_integer(
            op, PSA_KEY_DERIVATION_INPUT_COST, 1);
    }
    return status;
}

/* Key type accepted or rejected for each input step */
static void test_input_key_types(void)
{
    static const struct {
        const char *name;
        psa_algorithm_t alg;
        psa_key_derivation_step_t step;
        psa_key_type_t type;
        psa_status_t expected;
    } cases[] = {
        { "HKDF secret DERIVE", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SECRET, PSA_KEY_TYPE_DERIVE,
          PSA_SUCCESS },
        { "HKDF secret RAW_DATA", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SECRET, PSA_KEY_TYPE_RAW_DATA,
          PSA_ERROR_INVALID_ARGUMENT },
        { "HKDF salt RAW_DATA", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SALT, PSA_KEY_TYPE_RAW_DATA,
          PSA_SUCCESS },
        { "HKDF salt DERIVE", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SALT, PSA_KEY_TYPE_DERIVE,
          PSA_ERROR_INVALID_ARGUMENT },
        { "HKDF info RAW_DATA", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_INFO, PSA_KEY_TYPE_RAW_DATA,
          PSA_SUCCESS },
        { "TLS 1.2 PRF seed RAW_DATA", PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SEED, PSA_KEY_TYPE_RAW_DATA,
          PSA_SUCCESS },
        { "PBKDF2 password PASSWORD", PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_PASSWORD, PSA_KEY_TYPE_PASSWORD,
          PSA_SUCCESS },
        { "PBKDF2 password DERIVE", PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_PASSWORD, PSA_KEY_TYPE_DERIVE,
          PSA_SUCCESS },
        { "PBKDF2 password RAW_DATA", PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_PASSWORD, PSA_KEY_TYPE_RAW_DATA,
          PSA_ERROR_INVALID_ARGUMENT },
        { "PBKDF2 salt RAW_DATA", PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SALT, PSA_KEY_TYPE_RAW_DATA,
          PSA_SUCCESS },
        { "SP800-108 context RAW_DATA",
          PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_CONTEXT, PSA_KEY_TYPE_RAW_DATA,
          PSA_SUCCESS },
    };
    psa_key_derivation_operation_t op;
    psa_key_id_t kid;
    psa_status_t status;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        op = psa_key_derivation_operation_init();
        status = kdf_start(&op, cases[i].alg);
        if (status == PSA_ERROR_NOT_SUPPORTED) {
            continue;
        }
        if (expect_status(cases[i].name, status, PSA_SUCCESS) != 0 ||
            expect_status(cases[i].name,
                          import_secret_key(kdf_input, sizeof(kdf_input),
                                            cases[i].alg, cases[i].type,
                                            &kid), PSA_SUCCESS) != 0) {
            failures++;
            psa_key_derivation_abort(&op);
            continue;
        }
        status = psa_key_derivation_input_key(&op, cases[i].step, kid);
        if (expect_status(cases[i].name, status, cases[i].expected) != 0)
            failures++;
        psa_key_derivation_abort(&op);
        psa_destroy_key(kid);
    }
}

/* output_key needs the secret or password to come from a DERIVE key.
 * A usage of 0 inputs the secret or password as bytes. */
static void test_output_key_permission(void)
{
    static const struct {
        const char *name;
        psa_algorithm_t alg;
        psa_key_derivation_step_t step;
        psa_key_usage_t usage;
        psa_status_t expected;
    } cases[] = {
        { "HKDF secret from key", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SECRET, PSA_KEY_USAGE_DERIVE,
          PSA_SUCCESS },
        { "HKDF secret from verify-only key", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SECRET, PSA_KEY_USAGE_VERIFY_DERIVATION,
          PSA_ERROR_NOT_PERMITTED },
        { "HKDF secret from bytes", PSA_ALG_HKDF(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_SECRET, 0, PSA_ERROR_NOT_PERMITTED },
        { "PBKDF2 password from key", PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_PASSWORD, PSA_KEY_USAGE_DERIVE,
          PSA_SUCCESS },
        { "PBKDF2 password from verify-only key",
          PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_PASSWORD, PSA_KEY_USAGE_VERIFY_DERIVATION,
          PSA_ERROR_NOT_PERMITTED },
        { "PBKDF2 password from bytes",
          PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
          PSA_KEY_DERIVATION_INPUT_PASSWORD, 0, PSA_ERROR_NOT_PERMITTED },
    };
    psa_key_attributes_t out_attrs = psa_key_attributes_init();
    psa_key_derivation_operation_t op;
    psa_key_id_t kid = PSA_KEY_ID_NULL;
    psa_key_id_t out_id = PSA_KEY_ID_NULL;
    psa_status_t status;
    size_t i;

    psa_set_key_type(&out_attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&out_attrs, 128);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        op = psa_key_derivation_operation_init();
        status = kdf_start(&op, cases[i].alg);
        if (status == PSA_ERROR_NOT_SUPPORTED) {
            continue;
        }
        if (status == PSA_SUCCESS && PSA_ALG_IS_PBKDF2(cases[i].alg)) {
            status = psa_key_derivation_input_bytes(
                &op, PSA_KEY_DERIVATION_INPUT_SALT, kdf_input,
                sizeof(kdf_input));
        }
        if (status == PSA_SUCCESS && cases[i].usage != 0) {
            status = import_usage_key(kdf_input, sizeof(kdf_input),
                                      cases[i].alg, PSA_KEY_TYPE_DERIVE,
                                      cases[i].usage, &kid);
            if (status == PSA_SUCCESS)
                status = psa_key_derivation_input_key(&op, cases[i].step,
                                                      kid);
        }
        else if (status == PSA_SUCCESS) {
            status = psa_key_derivation_input_bytes(&op, cases[i].step,
                                                    kdf_input,
                                                    sizeof(kdf_input));
        }
        if (status == PSA_SUCCESS && PSA_ALG_IS_HKDF(cases[i].alg)) {
            status = psa_key_derivation_input_bytes(
                &op, PSA_KEY_DERIVATION_INPUT_INFO, kdf_input,
                sizeof(kdf_input));
        }
        if (expect_status(cases[i].name, status, PSA_SUCCESS) != 0) {
            failures++;
        }
        else {
            status = psa_key_derivation_output_key(&out_attrs, &op, &out_id);
            if (expect_status(cases[i].name, status, cases[i].expected) != 0)
                failures++;
        }
        psa_key_derivation_abort(&op);
        psa_destroy_key(out_id);
        psa_destroy_key(kid);
        out_id = PSA_KEY_ID_NULL;
        kid = PSA_KEY_ID_NULL;
    }
}

int main(void)
{
    static const uint8_t aes_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    static const uint8_t hmac_key[20] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13
    };
    static const uint8_t label[5] = { 'k', 'e', 'y', 'I', 'f' };
    static const uint8_t context[4] = { 0xde, 0xad, 0xbe, 0xef };
    uint8_t dk_key[16];
    uint8_t dk_bytes[16];
    int cmac_key_ok;
    int hmac_key_ok;
    psa_key_id_t aes_id = PSA_KEY_ID_NULL;
    psa_key_id_t hmac_id = PSA_KEY_ID_NULL;
    psa_key_id_t crossed_id = PSA_KEY_ID_NULL;
    psa_key_derivation_operation_t op;
    psa_status_t status;

    op = psa_key_derivation_operation_init();

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed\n");
        return 0;
    }

    /* AES key as the SP800-108-CMAC secret. */
    status = import_secret_key(aes_key, sizeof(aes_key),
                               PSA_ALG_SP800_108_COUNTER_CMAC,
                               PSA_KEY_TYPE_AES, &aes_id);
    if (expect_status("import AES key", status, PSA_SUCCESS) != 0)
        return 1;

    status = derive(&op, PSA_ALG_SP800_108_COUNTER_CMAC, NULL, 0, aes_id,
                    label, sizeof(label), context, sizeof(context),
                    dk_key, sizeof(dk_key));
    cmac_key_ok = (status == PSA_SUCCESS);
    if (expect_status("CMAC input_key derive", status, PSA_SUCCESS) != 0)
        failures++;

    status = derive(&op, PSA_ALG_SP800_108_COUNTER_CMAC, aes_key,
                    sizeof(aes_key), PSA_KEY_ID_NULL,
                    label, sizeof(label), context, sizeof(context),
                    dk_bytes, sizeof(dk_bytes));
    if (expect_status("CMAC input_bytes derive", status, PSA_SUCCESS) != 0)
        failures++;
    else if (cmac_key_ok &&
             memcmp(dk_key, dk_bytes, sizeof(dk_key)) != 0) {
        printf("FAIL: CMAC input_key output differs from input_bytes\n");
        failures++;
    }

    /* HMAC key as the SP800-108-HMAC secret. */
    status = import_secret_key(hmac_key, sizeof(hmac_key),
                               PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
                               PSA_KEY_TYPE_HMAC, &hmac_id);
    if (expect_status("import HMAC key", status, PSA_SUCCESS) != 0)
        return 1;

    status = derive(&op, PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
                    NULL, 0, hmac_id,
                    label, sizeof(label), context, sizeof(context),
                    dk_key, sizeof(dk_key));
    hmac_key_ok = (status == PSA_SUCCESS);
    if (expect_status("HMAC input_key derive", status, PSA_SUCCESS) != 0)
        failures++;

    status = derive(&op, PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
                    hmac_key, sizeof(hmac_key), PSA_KEY_ID_NULL,
                    label, sizeof(label), context, sizeof(context),
                    dk_bytes, sizeof(dk_bytes));
    if (expect_status("HMAC input_bytes derive", status, PSA_SUCCESS) != 0)
        failures++;
    else if (hmac_key_ok &&
             memcmp(dk_key, dk_bytes, sizeof(dk_key)) != 0) {
        printf("FAIL: HMAC input_key output differs from input_bytes\n");
        failures++;
    }

    /* Cross-variant keys stay rejected: an AES key on the HMAC variant,
     * an HMAC key on the CMAC variant. */
    status = import_secret_key(aes_key, sizeof(aes_key),
                               PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
                               PSA_KEY_TYPE_AES, &crossed_id);
    if (expect_status("import AES key (HMAC alg)", status, PSA_SUCCESS) != 0)
        return 1;
    status = derive(&op, PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
                    NULL, 0, crossed_id,
                    label, sizeof(label), context, sizeof(context),
                    dk_key, sizeof(dk_key));
    if (expect_status("AES key on HMAC variant rejected", status,
                      PSA_ERROR_INVALID_ARGUMENT) != 0)
        failures++;
    psa_destroy_key(crossed_id);

    status = import_secret_key(hmac_key, sizeof(hmac_key),
                               PSA_ALG_SP800_108_COUNTER_CMAC,
                               PSA_KEY_TYPE_HMAC, &crossed_id);
    if (expect_status("import HMAC key (CMAC alg)", status, PSA_SUCCESS) != 0)
        return 1;
    status = derive(&op, PSA_ALG_SP800_108_COUNTER_CMAC, NULL, 0, crossed_id,
                    label, sizeof(label), context, sizeof(context),
                    dk_key, sizeof(dk_key));
    if (expect_status("HMAC key on CMAC variant rejected", status,
                      PSA_ERROR_INVALID_ARGUMENT) != 0)
        failures++;
    psa_destroy_key(crossed_id);

    psa_destroy_key(aes_id);
    psa_destroy_key(hmac_id);

    test_input_key_types();
    test_output_key_permission();

    if (failures == 0) {
        printf("input-key tests: all passed\n");
        return 0;
    }
    printf("input-key tests: %d failure(s)\n", failures);
    return 1;
}
