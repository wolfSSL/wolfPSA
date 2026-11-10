/* psa_track_memory_test.c
 *
 * With WOLFSSL_TRACK_MEMORY, wolfCrypt_Init() changes the allocator, so
 * calls that allocate memory for later calls need psa_crypto_init(). Links
 * a library built with that option and the real wolfCrypt_Init().
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

#include <wolfssl/wolfcrypt/settings.h>
#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <string.h>

#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

static int failures;

static const uint8_t msg[] = "abc";
static const uint8_t sha256_abc[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
static const uint8_t shake256_abc[] = {
    0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
    0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
    0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee,
    0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39
};

static void check(const char *what, psa_status_t got, psa_status_t want)
{
    if (got != want) {
        printf("FAIL: %s: got %d want %d\n", what, (int)got, (int)want);
        failures++;
    }
}

static void test_before_init(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_xof_operation_t xof = PSA_XOF_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    mbedtls_pk_context pk;
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length = 0;

    check("psa_hash_setup before init", psa_hash_setup(&op, PSA_ALG_SHA_256),
          PSA_ERROR_BAD_STATE);
    check("psa_hash_compute before init",
          psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1, hash,
                           sizeof(hash), &hash_length),
          PSA_ERROR_BAD_STATE);
    check("psa_xof_setup before init", psa_xof_setup(&xof, PSA_ALG_SHAKE256),
          PSA_ERROR_BAD_STATE);
    check("psa_key_derivation_setup before init",
          psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)),
          PSA_ERROR_BAD_STATE);
    mbedtls_pk_init(&pk);
    check("mbedtls_pk_parse_key before init",
          mbedtls_pk_parse_key(&pk, ecc_key_der_256,
                               (size_t)sizeof_ecc_key_der_256, NULL, 0),
          PSA_ERROR_BAD_STATE);

    (void)psa_hash_abort(&op);
    (void)psa_xof_abort(&xof);
    (void)psa_key_derivation_abort(&kdf);
    mbedtls_pk_free(&pk);
}

static void test_after_init(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_xof_operation_t xof = PSA_XOF_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    mbedtls_pk_context pk;
    uint8_t out[sizeof(shake256_abc)];
    psa_status_t st;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_verify(&op, sha256_abc, sizeof(sha256_abc));
    }
    check("psa_hash_setup, update, verify after init", st, PSA_SUCCESS);
    (void)psa_hash_abort(&op);

    st = psa_xof_setup(&xof, PSA_ALG_SHAKE256);
    if (st == PSA_SUCCESS) {
        st = psa_xof_update(&xof, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_xof_output(&xof, out, sizeof(out));
    }
    check("psa_xof_setup, update, output after init", st, PSA_SUCCESS);
    if (st == PSA_SUCCESS && memcmp(out, shake256_abc, sizeof(out)) != 0) {
        printf("FAIL: psa_xof_output after init: output mismatch\n");
        failures++;
    }
    (void)psa_xof_abort(&xof);

    st = psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&kdf,
                PSA_KEY_DERIVATION_INPUT_SALT, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&kdf,
                PSA_KEY_DERIVATION_INPUT_SECRET, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&kdf,
                PSA_KEY_DERIVATION_INPUT_INFO, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_bytes(&kdf, out, sizeof(out));
    }
    check("psa_key_derivation_setup, input, output after init", st,
          PSA_SUCCESS);
    (void)psa_key_derivation_abort(&kdf);

    mbedtls_pk_init(&pk);
    check("mbedtls_pk_parse_key after init",
          mbedtls_pk_parse_key(&pk, ecc_key_der_256,
                               (size_t)sizeof_ecc_key_der_256, NULL, 0),
          PSA_SUCCESS);
    mbedtls_pk_free(&pk);
}

int main(void)
{
    test_before_init();

    check("psa_crypto_init", psa_crypto_init(), PSA_SUCCESS);
    test_after_init();

    if (failures != 0) {
        printf("PSA track memory test: %d failure(s)\n", failures);
        return 1;
    }

    printf("PSA track memory test: OK\n");
    return 0;
}
