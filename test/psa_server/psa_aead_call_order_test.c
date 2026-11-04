/* psa_aead_call_order_test.c
 *
 * Multipart AEAD accepts psa_aead_set_lengths() before or after the nonce,
 * and rejects it once additional data or payload has been passed.
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

#define AD_LEN  8
#define TAG_LEN 16

static int failures;

static const uint8_t nonce[12] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b
};
static const uint8_t ad[AD_LEN] = { 'a', 'd', 'd', 'a', 't', 'a', '0', '1' };
static const uint8_t msg[] = "multipart AEAD order";

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got %d want %d\n", what, (int)got, (int)want);
        failures++;
    }
}

static psa_key_id_t import_key(psa_algorithm_t alg)
{
    static const uint8_t key_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, alg);
    expect(psa_import_key(&attrs, key_data, sizeof(key_data), &key),
           PSA_SUCCESS, "import key");
    return key;
}

/* Multipart encrypt with the lengths set after the nonce, checked against
 * the one-shot result. */
static void check_lengths_after_nonce(psa_algorithm_t alg, const char *name)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key = import_key(alg);
    uint8_t want[sizeof(msg) + TAG_LEN];
    uint8_t out[sizeof(msg)];
    uint8_t tag[TAG_LEN];
    size_t want_len = 0;
    size_t out_len = 0;
    size_t fin_len = 0;
    size_t tag_len = 0;
    psa_status_t status;

    expect(psa_aead_encrypt(key, alg, nonce, sizeof(nonce), ad, sizeof(ad),
                            msg, sizeof(msg), want, sizeof(want), &want_len),
           PSA_SUCCESS, name);

    status = psa_aead_encrypt_setup(&op, key, alg);
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_lengths(&op, sizeof(ad), sizeof(msg));
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_update_ad(&op, ad, sizeof(ad));
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_update(&op, msg, sizeof(msg), out, sizeof(out),
                                 &out_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_finish(&op, out + out_len, sizeof(out) - out_len,
                                 &fin_len, tag, sizeof(tag), &tag_len);
    }
    expect(status, PSA_SUCCESS, name);
    if (status == PSA_SUCCESS &&
        (want_len != out_len + fin_len + tag_len ||
         memcmp(want, out, out_len + fin_len) != 0 ||
         memcmp(want + out_len + fin_len, tag, tag_len) != 0)) {
        printf("FAIL: %s: output differs from one-shot\n", name);
        failures++;
    }
    psa_aead_abort(&op);
    psa_destroy_key(key);
}

/* CCM takes a nonce before the lengths, but no data or finish without
 * them. */
static void check_ccm_without_lengths(void)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key = import_key(PSA_ALG_CCM);
    uint8_t buf[TAG_LEN];
    uint8_t gen[PSA_AEAD_NONCE_MAX_SIZE];
    size_t len = 0;
    size_t tag_len = 0;

    expect(psa_aead_encrypt_setup(&op, key, PSA_ALG_CCM), PSA_SUCCESS,
           "CCM setup");
    expect(psa_aead_generate_nonce(&op, gen, sizeof(gen), &len), PSA_SUCCESS,
           "CCM generate nonce before lengths");
    expect(psa_aead_update_ad(&op, ad, 0), PSA_SUCCESS,
           "CCM empty additional data before lengths");
    expect(psa_aead_update_ad(&op, ad, sizeof(ad)), PSA_ERROR_BAD_STATE,
           "CCM additional data before lengths");
    psa_aead_abort(&op);

    expect(psa_aead_encrypt_setup(&op, key, PSA_ALG_CCM), PSA_SUCCESS,
           "CCM setup");
    expect(psa_aead_set_nonce(&op, nonce, sizeof(nonce)), PSA_SUCCESS,
           "CCM nonce before lengths");
    expect(psa_aead_finish(&op, buf, sizeof(buf), &len, buf, sizeof(buf),
                           &tag_len),
           PSA_ERROR_BAD_STATE, "CCM finish without lengths");
    psa_aead_abort(&op);
    psa_destroy_key(key);
}

/* Once additional data or payload is passed, even empty, the lengths are
 * fixed. */
static void check_lengths_too_late(void)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key = import_key(PSA_ALG_GCM);
    uint8_t out[sizeof(msg)];
    size_t out_len = 0;

    expect(psa_aead_encrypt_setup(&op, key, PSA_ALG_GCM), PSA_SUCCESS,
           "GCM setup");
    expect(psa_aead_set_nonce(&op, nonce, sizeof(nonce)), PSA_SUCCESS,
           "GCM nonce");
    expect(psa_aead_update_ad(&op, ad, 0), PSA_SUCCESS,
           "GCM empty additional data");
    expect(psa_aead_set_lengths(&op, 0, 0), PSA_ERROR_BAD_STATE,
           "GCM lengths after additional data");
    psa_aead_abort(&op);

    expect(psa_aead_encrypt_setup(&op, key, PSA_ALG_GCM), PSA_SUCCESS,
           "GCM setup");
    expect(psa_aead_set_nonce(&op, nonce, sizeof(nonce)), PSA_SUCCESS,
           "GCM nonce");
    expect(psa_aead_update(&op, msg, 0, out, sizeof(out), &out_len),
           PSA_SUCCESS, "GCM empty update");
    expect(psa_aead_set_lengths(&op, 0, 0), PSA_ERROR_BAD_STATE,
           "GCM lengths after update");
    psa_aead_abort(&op);

#if SIZE_MAX > UINT32_MAX
    expect(psa_aead_encrypt_setup(&op, key, PSA_ALG_GCM), PSA_SUCCESS,
           "GCM setup");
    expect(psa_aead_set_lengths(&op, SIZE_MAX, 0), PSA_ERROR_INVALID_ARGUMENT,
           "GCM additional data length over the limit");
    expect(psa_aead_set_nonce(&op, nonce, sizeof(nonce)), PSA_ERROR_BAD_STATE,
           "GCM nonce after failed lengths");
    psa_aead_abort(&op);
#endif /* SIZE_MAX > UINT32_MAX */
    psa_destroy_key(key);
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

    check_lengths_after_nonce(PSA_ALG_GCM, "GCM lengths after nonce");
    check_lengths_after_nonce(PSA_ALG_CCM, "CCM lengths after nonce");
    check_ccm_without_lengths();
    check_lengths_too_late();

    if (failures == 0) {
        printf("AEAD call order tests: all passed\n");
        return 0;
    }
    printf("AEAD call order tests: %d failure(s)\n", failures);
    return 1;
}
