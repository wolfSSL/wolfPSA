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
#include <wolfssl/wolfcrypt/mem_track.h>
#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#ifdef MBEDTLS_PEM_PARSE_C
    #include <mbedtls/pem.h>
#endif /* MBEDTLS_PEM_PARSE_C */
#ifdef MBEDTLS_SSL_TLS_C
    #include <mbedtls/ssl.h>
#endif /* MBEDTLS_SSL_TLS_C */
#include <stdio.h>
#include <string.h>

#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

static int failures;

static const uint8_t msg[] = "abc";
#ifdef MBEDTLS_PEM_PARSE_C
static const unsigned char pem_abc[] = "^\nYWJj\n$";
#endif /* MBEDTLS_PEM_PARSE_C */
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
/* HKDF-SHA256 with "abc" as salt, secret and info */
static const uint8_t hkdf_abc[] = {
    0xfb, 0x71, 0xed, 0x96, 0x0a, 0x6e, 0xb9, 0x6e,
    0xfb, 0xef, 0xdc, 0x6f, 0xf8, 0x67, 0x54, 0x15,
    0x22, 0x69, 0x96, 0x52, 0x63, 0x87, 0x15, 0x85,
    0xde, 0x5c, 0x60, 0x13, 0xf3, 0xab, 0xa5, 0xc8
};

static void check(const char *what, psa_status_t got, psa_status_t want)
{
    if (got != want) {
        printf("FAIL: %s: got %d want %d\n", what, (int)got, (int)want);
        failures++;
    }
}

static void check_bytes(const char *what, const uint8_t *got, size_t got_len,
                        const uint8_t *want, size_t want_len)
{
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        printf("FAIL: %s: output mismatch\n", what);
        failures++;
    }
}

#ifdef MBEDTLS_PEM_PARSE_C
static void test_pem(int want, const char *what)
{
    mbedtls_pem_context pem;
    size_t used = 0;

    mbedtls_pem_init(&pem);
    check(what, mbedtls_pem_read_buffer(&pem, "^", "$", pem_abc, NULL, 0,
                                        &used), want);
    mbedtls_pem_free(&pem);
}
#endif /* MBEDTLS_PEM_PARSE_C */

#ifdef MBEDTLS_SSL_TLS_C
/* The calls that allocate what the config or context keeps */
static void test_ssl(int want, const char *when)
{
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    const int *ids = mbedtls_ssl_list_ciphersuites();
    char what[64];

    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    snprintf(what, sizeof(what), "mbedtls_ssl_config_defaults %s", when);
    check(what, mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT), want);
    snprintf(what, sizeof(what), "mbedtls_ssl_set_hostname %s", when);
    check(what, mbedtls_ssl_set_hostname(&ssl, "localhost"), want);
    /* Allocates nothing, so works before init too, as in Mbed TLS */
    snprintf(what, sizeof(what), "mbedtls_ssl_list_ciphersuites %s", when);
    check(what, ids[0] != 0 && mbedtls_ssl_get_ciphersuite_id(
              mbedtls_ssl_get_ciphersuite_name(ids[0])) == ids[0], 1);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
}
#endif /* MBEDTLS_SSL_TLS_C */

static void test_before_init(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_xof_operation_t xof = PSA_XOF_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    mbedtls_pk_context pk;
#ifdef MBEDTLS_X509_CRT_PARSE_C
    mbedtls_x509_crt crt;
#endif /* MBEDTLS_X509_CRT_PARSE_C */
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
#ifdef MBEDTLS_FS_IO
    /* A missing file, so only a check before the load gives BAD_STATE */
    check("mbedtls_pk_parse_keyfile before init",
          mbedtls_pk_parse_keyfile(&pk, "missing.key", NULL),
          PSA_ERROR_BAD_STATE);
#endif /* MBEDTLS_FS_IO */
#ifdef MBEDTLS_X509_CRT_PARSE_C
    mbedtls_x509_crt_init(&crt);
    check("mbedtls_x509_crt_parse_der before init",
          mbedtls_x509_crt_parse_der(&crt, serv_ecc_der_256,
                                     (size_t)sizeof_serv_ecc_der_256),
          PSA_ERROR_BAD_STATE);
    check("mbedtls_x509_crt_parse before init",
          mbedtls_x509_crt_parse(&crt, serv_ecc_der_256,
                                 (size_t)sizeof_serv_ecc_der_256),
          PSA_ERROR_BAD_STATE);
#ifdef MBEDTLS_FS_IO
    check("mbedtls_x509_crt_parse_file before init",
          mbedtls_x509_crt_parse_file(&crt, "missing.crt"),
          PSA_ERROR_BAD_STATE);
    check("mbedtls_x509_crt_parse_path before init",
          mbedtls_x509_crt_parse_path(&crt, "."), PSA_ERROR_BAD_STATE);
#endif /* MBEDTLS_FS_IO */
    mbedtls_x509_crt_free(&crt);
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#ifdef MBEDTLS_PEM_PARSE_C
    test_pem(PSA_ERROR_BAD_STATE, "mbedtls_pem_read_buffer before init");
#endif /* MBEDTLS_PEM_PARSE_C */
#ifdef MBEDTLS_SSL_TLS_C
    test_ssl(PSA_ERROR_BAD_STATE, "before init");
#endif /* MBEDTLS_SSL_TLS_C */

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
#ifdef MBEDTLS_X509_CRT_PARSE_C
    mbedtls_x509_crt crt;
#endif /* MBEDTLS_X509_CRT_PARSE_C */
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
    if (st == PSA_SUCCESS) {
        check_bytes("psa_xof_output after init", out, sizeof(out),
                    shake256_abc, sizeof(shake256_abc));
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
    if (st == PSA_SUCCESS) {
        check_bytes("psa_key_derivation_output_bytes after init", out,
                    sizeof(out), hkdf_abc, sizeof(hkdf_abc));
    }
    (void)psa_key_derivation_abort(&kdf);

    mbedtls_pk_init(&pk);
    check("mbedtls_pk_parse_key after init",
          mbedtls_pk_parse_key(&pk, ecc_key_der_256,
                               (size_t)sizeof_ecc_key_der_256, NULL, 0),
          PSA_SUCCESS);
    mbedtls_pk_free(&pk);
#ifdef MBEDTLS_X509_CRT_PARSE_C
    mbedtls_x509_crt_init(&crt);
    check("mbedtls_x509_crt_parse_der after init",
          mbedtls_x509_crt_parse_der(&crt, serv_ecc_der_256,
                                     (size_t)sizeof_serv_ecc_der_256),
          PSA_SUCCESS);
    mbedtls_x509_crt_free(&crt);
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#ifdef MBEDTLS_PEM_PARSE_C
    test_pem(0, "mbedtls_pem_read_buffer after init");
#endif /* MBEDTLS_PEM_PARSE_C */
#ifdef MBEDTLS_SSL_TLS_C
    test_ssl(0, "after init");
#endif /* MBEDTLS_SSL_TLS_C */
}

/* Leaks, and frees of memory the tracker did not allocate, unbalance it */
static void check_tracker(const memoryStats *stats)
{
    if (stats == NULL) {
        printf("FAIL: memory tracker not installed\n");
        failures++;
    }
    else if (stats->currentBytes != 0 ||
             stats->totalAllocs != stats->totalDeallocs) {
        printf("FAIL: memory tracker: %ld bytes, %ld allocs, %ld frees\n",
               stats->currentBytes, stats->totalAllocs, stats->totalDeallocs);
        failures++;
    }
}

int main(void)
{
    const memoryStats *stats;

    test_before_init();

    check("psa_crypto_init", psa_crypto_init(), PSA_SUCCESS);
    stats = wc_MemStats_Ptr;
    test_after_init();
    mbedtls_psa_crypto_free();
    check_tracker(stats);

    if (failures != 0) {
        printf("PSA track memory test: %d failure(s)\n", failures);
        return 1;
    }

    printf("PSA track memory test: OK\n");
    return 0;
}
