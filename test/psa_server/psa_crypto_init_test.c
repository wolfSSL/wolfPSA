/* psa_crypto_init_test.c
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
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <string.h>

#include <wolfpsa/psa/crypto.h>

static int g_wolfcrypt_init_calls;
static int g_wolfcrypt_init_result;

int __wrap_wolfCrypt_Init(void)
{
    g_wolfcrypt_init_calls++;
    return g_wolfcrypt_init_result;
}

static int expect_status(const char* label, psa_status_t status, psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s status=%d expected=%d\n", label, (int)status, (int)expected);
        return 1;
    }

    return 0;
}

static int expect_bytes(const char* label, const uint8_t* got, size_t got_len,
                        const uint8_t* want, size_t want_len)
{
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        printf("FAIL %s output mismatch\n", label);
        return 1;
    }

    return 0;
}

/* As in Mbed TLS, hashes and XOFs need no psa_crypto_init() */
static int test_hash_before_psa_crypto_init(void)
{
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
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_xof_operation_t xof = PSA_XOF_OPERATION_INIT;
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    uint8_t out[sizeof(shake256_abc)];
    size_t hash_length = 0;
    psa_status_t st;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_finish(&op, hash, sizeof(hash), &hash_length);
    }
    if (expect_status("psa_hash_setup, update, finish before init", st,
                      PSA_SUCCESS) != 0 ||
        expect_bytes("psa_hash_finish before init", hash, hash_length,
                     sha256_abc, sizeof(sha256_abc)) != 0) {
        (void)psa_hash_abort(&op);
        return 1;
    }

    hash_length = 0;
    st = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1, hash,
                          sizeof(hash), &hash_length);
    if (expect_status("psa_hash_compute before init", st,
                      PSA_SUCCESS) != 0 ||
        expect_bytes("psa_hash_compute before init", hash, hash_length,
                     sha256_abc, sizeof(sha256_abc)) != 0) {
        return 1;
    }

    st = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg) - 1, sha256_abc,
                          sizeof(sha256_abc));
    if (expect_status("psa_hash_compare before init", st,
                      PSA_SUCCESS) != 0) {
        return 1;
    }

    st = psa_xof_setup(&xof, PSA_ALG_SHAKE256);
    if (st == PSA_SUCCESS) {
        st = psa_xof_update(&xof, msg, sizeof(msg) - 1);
    }
    if (st == PSA_SUCCESS) {
        st = psa_xof_output(&xof, out, sizeof(out));
    }
    (void)psa_xof_abort(&xof);
    if (expect_status("psa_xof_setup, update, output before init", st,
                      PSA_SUCCESS) != 0 ||
        expect_bytes("psa_xof_output before init", out, sizeof(out),
                     shake256_abc, sizeof(shake256_abc)) != 0) {
        return 1;
    }

    return 0;
}

static int test_hash_compare_rejects_null_reference(void)
{
    static const uint8_t msg[] = "abc";
    psa_status_t st;

    /* A NULL reference hash with a length matching the algorithm output size
     * must be rejected, not dereferenced. */
    st = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg) - 1, NULL,
                          PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    if (expect_status("psa_hash_compare NULL reference", st,
                      PSA_ERROR_INVALID_ARGUMENT) != 0) {
        return 1;
    }

    return 0;
}

static int test_random_requires_psa_crypto_init(void)
{
    uint8_t buf[16];
    psa_status_t st;

    st = psa_generate_random(buf, sizeof(buf));
    if (expect_status("psa_generate_random before init", st,
                      PSA_ERROR_BAD_STATE) != 0) {
        return 1;
    }

    return 0;
}

int main(void)
{
    psa_status_t st;

    if (test_hash_before_psa_crypto_init() != 0) {
        return 1;
    }

    if (test_random_requires_psa_crypto_init() != 0) {
        return 1;
    }

    g_wolfcrypt_init_calls = 0;
    g_wolfcrypt_init_result = RNG_FAILURE_E;

    st = psa_crypto_init();
    if (expect_status("psa_crypto_init rng failure", st,
                      PSA_ERROR_INSUFFICIENT_ENTROPY) != 0) {
        return 1;
    }
    if (g_wolfcrypt_init_calls != 1) {
        printf("FAIL wolfCrypt_Init calls=%d expected=1\n", g_wolfcrypt_init_calls);
        return 1;
    }

    g_wolfcrypt_init_result = 0;
    st = psa_crypto_init();
    if (expect_status("psa_crypto_init success", st, PSA_SUCCESS) != 0) {
        return 1;
    }
    if (g_wolfcrypt_init_calls != 2) {
        printf("FAIL wolfCrypt_Init calls=%d expected=2\n", g_wolfcrypt_init_calls);
        return 1;
    }

    if (test_hash_compare_rejects_null_reference() != 0) {
        return 1;
    }

    printf("PSA crypto init test: OK\n");
    return 0;
}
