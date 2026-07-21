/* psa_api_test.c
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

#include <wolfssl/options.h>
#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <wolfpsa/psa/crypto.h>
#include "psa_aead_internal.h"

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#if defined(WOLFSSL_HAVE_MLDSA)
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif

#ifndef INVALID_DEVID
#define INVALID_DEVID -2
#endif

#define TEST_OK 0
#define TEST_FAIL 1
#define TEST_SKIPPED 2
#define ED25519_PUBLIC_KEY_BYTES 32u
#define ED448_PUBLIC_KEY_BYTES   57u
#define X25519_KEY_BYTES         32u
#define X448_KEY_BYTES           56u

typedef int (*test_fn_t)(void);

static int tests_passed = 0;
static int tests_skipped = 0;

extern psa_key_id_t wolfpsa_test_get_next_key_id(void);
extern void wolfpsa_test_set_next_key_id(psa_key_id_t key_id);

static int check_status(psa_status_t st, const char* what)
{
    if (st != PSA_SUCCESS) {
        printf("FAIL: %s (status=%d)\n", what, (int)st);
        return TEST_FAIL;
    }
    return TEST_OK;
}

static int check_true(int cond, const char* what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        return TEST_FAIL;
    }
    return TEST_OK;
}

static int check_buf_eq(const char* what, const uint8_t* a, const uint8_t* b, size_t sz)
{
    if (memcmp(a, b, sz) != 0) {
        printf("FAIL: %s (mismatch)\n", what);
        return TEST_FAIL;
    }
    return TEST_OK;
}

/* Known-answer test for a single hash algorithm: checks both the one-shot
 * psa_hash_compute path and the multipart setup/update/finish path against a
 * fixed digest of "abc". Catches mutated or swapped dispatch cases that a
 * SHA-256-only test would miss. Algorithms that the linked library was not
 * built with report PSA_ERROR_NOT_SUPPORTED and are skipped, so the same test
 * works across the build-config matrix. */
static int test_hash_kat(psa_algorithm_t alg, const uint8_t *expected,
                         size_t expected_len, const char *name)
{
    static const uint8_t msg[] = "abc";
    uint8_t out[PSA_HASH_MAX_SIZE];
    size_t out_len = 0;
    psa_hash_operation_t op = psa_hash_operation_init();
    psa_status_t st;
    char what[64];

    snprintf(what, sizeof(what), "psa_hash_compute(%s)", name);
    st = psa_hash_compute(alg, msg, sizeof(msg) - 1, out, sizeof(out),
                          &out_len);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP: %s (not supported by this build)\n", name);
        return TEST_OK;
    }
    if (check_status(st, what) != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == expected_len, what) != TEST_OK) return TEST_FAIL;
    if (check_buf_eq(what, out, expected, expected_len) != TEST_OK)
        return TEST_FAIL;

    out_len = 0;
    snprintf(what, sizeof(what), "psa_hash_finish(%s)", name);
    st = psa_hash_setup(&op, alg);
    if (check_status(st, what) != TEST_OK) return TEST_FAIL;
    st = psa_hash_update(&op, msg, sizeof(msg) - 1);
    if (check_status(st, what) != TEST_OK) {
        (void)psa_hash_abort(&op);
        return TEST_FAIL;
    }
    st = psa_hash_finish(&op, out, sizeof(out), &out_len);
    if (check_status(st, what) != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == expected_len, what) != TEST_OK) return TEST_FAIL;
    if (check_buf_eq(what, out, expected, expected_len) != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_hash(void)
{
    static const uint8_t msg[] = "abc";
    static const uint8_t expected[WC_SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t out1[WC_SHA256_DIGEST_SIZE];
    uint8_t out2[WC_SHA256_DIGEST_SIZE];
    size_t out1_len = 0;
    size_t out2_len = 0;
    psa_hash_operation_t op = psa_hash_operation_init();
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          out1, sizeof(out1), &out1_len);
    if (check_status(st, "psa_hash_compute") != TEST_OK) return TEST_FAIL;
    if (check_true(out1_len == sizeof(expected), "psa_hash_compute length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_hash_compute", out1, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (check_status(st, "psa_hash_setup") != TEST_OK) return TEST_FAIL;
    st = psa_hash_update(&op, msg, sizeof(msg) - 1);
    if (check_status(st, "psa_hash_update") != TEST_OK) return TEST_FAIL;
    st = psa_hash_finish(&op, out2, sizeof(out2), &out2_len);
    if (check_status(st, "psa_hash_finish") != TEST_OK) return TEST_FAIL;
    if (check_true(out2_len == sizeof(expected), "psa_hash_finish length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_hash_finish", out2, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    /* Known-answer coverage for every other hash dispatch case the library may
     * implement, so a mutated, swapped, or removed non-SHA-256 case does not
     * pass unnoticed. Cases the build omits report NOT_SUPPORTED and skip. */
    static const uint8_t exp_sha1[] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };
    if (test_hash_kat(PSA_ALG_SHA_1, exp_sha1, sizeof(exp_sha1), "SHA-1")
            != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha224[] = {
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
        0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
        0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
        0xe3, 0x6c, 0x9d, 0xa7,
    };
    if (test_hash_kat(PSA_ALG_SHA_224, exp_sha224, sizeof(exp_sha224),
            "SHA-224") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha384[] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
    };
    if (test_hash_kat(PSA_ALG_SHA_384, exp_sha384, sizeof(exp_sha384),
            "SHA-384") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha512[] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    if (test_hash_kat(PSA_ALG_SHA_512, exp_sha512, sizeof(exp_sha512),
            "SHA-512") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha512_224[] = {
        0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54,
        0xda, 0xae, 0x75, 0x30, 0x46, 0x08, 0x42, 0xe2,
        0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4,
        0x3e, 0x89, 0x24, 0xaa,
    };
    if (test_hash_kat(PSA_ALG_SHA_512_224, exp_sha512_224,
            sizeof(exp_sha512_224), "SHA-512/224") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha512_256[] = {
        0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9,
        0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab,
        0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46,
        0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23,
    };
    if (test_hash_kat(PSA_ALG_SHA_512_256, exp_sha512_256,
            sizeof(exp_sha512_256), "SHA-512/256") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha3_224[] = {
        0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a,
        0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f,
        0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad,
        0x73, 0xb4, 0x6f, 0xdf,
    };
    if (test_hash_kat(PSA_ALG_SHA3_224, exp_sha3_224, sizeof(exp_sha3_224),
            "SHA3-224") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha3_256[] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    };
    if (test_hash_kat(PSA_ALG_SHA3_256, exp_sha3_256, sizeof(exp_sha3_256),
            "SHA3-256") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha3_384[] = {
        0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9,
        0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
        0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25,
        0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
        0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
        0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25,
    };
    if (test_hash_kat(PSA_ALG_SHA3_384, exp_sha3_384, sizeof(exp_sha3_384),
            "SHA3-384") != TEST_OK) return TEST_FAIL;
    static const uint8_t exp_sha3_512[] = {
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
        0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
        0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
        0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
        0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
        0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
        0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
        0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
    };
    if (test_hash_kat(PSA_ALG_SHA3_512, exp_sha3_512, sizeof(exp_sha3_512),
            "SHA3-512") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_hash_compare(void)
{
    static const uint8_t msg[] = "abc";
    /* SHA-256("abc") */
    static const uint8_t sha256_abc[WC_SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t bad_hash[WC_SHA256_DIGEST_SIZE];
    psa_status_t st;

    /* Success path: correct digest must return PSA_SUCCESS. */
    st = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          sha256_abc, sizeof(sha256_abc));
    if (check_status(st, "psa_hash_compare correct") != TEST_OK) return TEST_FAIL;

    /* Mismatch path: one byte flipped must return PSA_ERROR_INVALID_SIGNATURE.
     * Catches mutation of the ConstantCompare check. */
    memcpy(bad_hash, sha256_abc, sizeof(bad_hash));
    bad_hash[0] ^= 0x01;
    st = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          bad_hash, sizeof(bad_hash));
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_hash_compare mismatch") != TEST_OK) return TEST_FAIL;

    /* Wrong reference length must return PSA_ERROR_INVALID_SIGNATURE. */
    st = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          sha256_abc, sizeof(sha256_abc) - 1);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_hash_compare wrong length") != TEST_OK) return TEST_FAIL;

    /* Non-hash algorithm must return PSA_ERROR_INVALID_ARGUMENT. */
    st = psa_hash_compare(PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, sizeof(msg) - 1,
                          sha256_abc, sizeof(sha256_abc));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_hash_compare non-hash alg") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int check_status_or_skip(psa_status_t st, const char* what)
{
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    return check_status(st, what);
}

static int test_random(void)
{
    uint8_t buf[32];
    size_t i;
    int all_zero = 1;
    psa_status_t st;

    st = psa_generate_random(buf, sizeof(buf));
    if (check_status(st, "psa_generate_random") != TEST_OK) return TEST_FAIL;

    for (i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    return check_true(!all_zero, "psa_generate_random non-zero");
}

static int test_hmac(void)
{
    static const uint8_t key[] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t msg[] = "hmac message";
    uint8_t expected[WC_SHA256_DIGEST_SIZE];
    uint8_t out[WC_SHA256_DIGEST_SIZE];
    uint8_t bad_mac[WC_SHA256_DIGEST_SIZE];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;
    Hmac hmac;
    int ret;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_HmacInit (%d)\n", ret);
        return TEST_FAIL;
    }
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, sizeof(key));
    if (ret != 0) {
        wc_HmacFree(&hmac);
        printf("FAIL: wc_HmacSetKey (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_HmacUpdate(&hmac, msg, (word32)sizeof(msg) - 1);
    wc_HmacFinal(&hmac, expected);
    wc_HmacFree(&hmac);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC)") != TEST_OK) return TEST_FAIL;

    st = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         msg, sizeof(msg) - 1, out, sizeof(out), &out_len);
    if (check_status(st, "psa_mac_compute") != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(expected), "psa_mac_compute length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_mac_compute", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_mac_verify(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        msg, sizeof(msg) - 1, out, out_len);
    if (check_status(st, "psa_mac_verify") != TEST_OK) return TEST_FAIL;

    memcpy(bad_mac, out, out_len);
    bad_mac[0] ^= 0x01u;
    st = psa_mac_verify(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        msg, sizeof(msg) - 1, bad_mac, out_len);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_mac_verify rejects bad MAC") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_mac_verify_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_mac_verify_setup") != TEST_OK) return TEST_FAIL;
    st = psa_mac_update(&op, msg, sizeof(msg) - 1);
    if (check_status(st, "psa_mac_update(verify)") != TEST_OK) return TEST_FAIL;
    st = psa_mac_verify_finish(&op, out, out_len - 1);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_mac_verify_finish rejects short MAC") != TEST_OK) {
        (void)psa_mac_abort(&op);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HMAC)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

/* Known-answer test for AES-CMAC, locking down the block-cipher-MAC dispatch
 * in psa_mac.c (setup/update/final/abort) that the HMAC-only tests never
 * exercise. Vector is NIST SP 800-38B AES-128 CMAC, Example 2 (Mlen = 128).
 * A build without WOLFSSL_CMAC reports PSA_ERROR_NOT_SUPPORTED and is
 * skipped, so the test works across the build-config matrix. */
static int test_cmac(void)
{
    static const uint8_t key[] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t msg[] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t expected[] = {
        0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,
        0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c
    };
    uint8_t out[sizeof(expected)];
    uint8_t bad_mac[sizeof(expected)];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_id_t hmac_key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_CMAC);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES CMAC)") != TEST_OK) return TEST_FAIL;

    st = psa_mac_compute(key_id, PSA_ALG_CMAC, msg, sizeof(msg),
                         out, sizeof(out), &out_len);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP: cmac (not supported by this build)\n");
        (void)psa_destroy_key(key_id);
        return TEST_OK;
    }
    if (check_status(st, "psa_mac_compute(CMAC)") != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(expected), "psa_mac_compute(CMAC) length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_mac_compute(CMAC)", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_mac_verify(key_id, PSA_ALG_CMAC, msg, sizeof(msg),
                        expected, sizeof(expected));
    if (check_status(st, "psa_mac_verify(CMAC)") != TEST_OK) return TEST_FAIL;

    memcpy(bad_mac, expected, sizeof(bad_mac));
    bad_mac[0] ^= 0x01u;
    st = psa_mac_verify(key_id, PSA_ALG_CMAC, msg, sizeof(msg),
                        bad_mac, sizeof(bad_mac));
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_mac_verify(CMAC) rejects bad MAC") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(CMAC)") != TEST_OK) return TEST_FAIL;

    /* CMAC setup must reject a key whose type is not AES, locking down the
     * PSA_KEY_TYPE_AES check in wolfpsa_mac_check_key. */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_CMAC);
    st = psa_import_key(&attrs, key, sizeof(key), &hmac_key_id);
    if (check_status(st, "psa_import_key(non-AES CMAC)") != TEST_OK) return TEST_FAIL;
    st = psa_mac_sign_setup(&op, hmac_key_id, PSA_ALG_CMAC);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_mac_sign_setup(CMAC) rejects non-AES key") != TEST_OK) {
        (void)psa_mac_abort(&op);
        (void)psa_destroy_key(hmac_key_id);
        return TEST_FAIL;
    }
    (void)psa_mac_abort(&op);
    st = psa_destroy_key(hmac_key_id);
    if (check_status(st, "psa_destroy_key(non-AES CMAC)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_mac_verify_finish_accepts_longer_at_least_length_mac(void)
{
    static const uint8_t key[] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t msg[] = "at least length mac";
    uint8_t expected[WC_SHA256_DIGEST_SIZE];
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;
    Hmac hmac;
    int ret;
    int result = TEST_FAIL;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_HmacInit(at least MAC) (%d)\n", ret);
        return TEST_FAIL;
    }
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, sizeof(key));
    if (ret != 0) {
        wc_HmacFree(&hmac);
        printf("FAIL: wc_HmacSetKey(at least MAC) (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_HmacUpdate(&hmac, msg, (word32)sizeof(msg) - 1u);
    wc_HmacFinal(&hmac, expected);
    wc_HmacFree(&hmac);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs,
        PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC at least length verify)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_mac_verify_setup(&op, key_id,
        PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16));
    if (check_status(st, "psa_mac_verify_setup(at least length verify)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_mac_update(&op, msg, sizeof(msg) - 1u);
    if (check_status(st, "psa_mac_update(at least length verify)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_mac_verify_finish(&op, expected, sizeof(expected));
    if (check_status(st, "psa_mac_verify_finish accepts longer at least-length MAC") != TEST_OK) {
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    (void)psa_mac_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return result;
}

static int test_hash_error_aborts_operation(void)
{
    static const uint8_t msg[] = "hash error state";
    uint8_t out[WC_SHA256_DIGEST_SIZE];
    size_t out_len = 0;
    psa_hash_operation_t op = psa_hash_operation_init();
    psa_status_t st;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (check_status(st, "psa_hash_setup(error state)") != TEST_OK) return TEST_FAIL;

    st = psa_hash_update(&op, msg, sizeof(msg) - 1);
    if (check_status(st, "psa_hash_update(error state seed)") != TEST_OK) {
        (void)psa_hash_abort(&op);
        return TEST_FAIL;
    }

    st = psa_hash_finish(&op, out, 1, &out_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_hash_finish(error state status)") != TEST_OK) {
        (void)psa_hash_abort(&op);
        return TEST_FAIL;
    }

    st = psa_hash_update(&op, msg, 1);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_hash_update(error state aborted)") != TEST_OK) {
        (void)psa_hash_abort(&op);
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_algorithm_none_rejects_key_usage(void)
{
    static const uint8_t aes_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t hmac_key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t hash[WC_SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t sig[80];
    size_t sig_len = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
    psa_aead_operation_t aead_op = psa_aead_operation_init();
    psa_mac_operation_t mac_op = psa_mac_operation_init();
    psa_key_derivation_operation_t kdf_op = psa_key_derivation_operation_init();
    psa_key_id_t key_id = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(AES alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_cipher_encrypt_setup(&cipher_op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_cipher_encrypt_setup rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES cipher alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(AES AEAD alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&aead_op, key_id, PSA_ALG_GCM);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_aead_encrypt_setup rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES AEAD alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(HMAC alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_mac_sign_setup(&mac_op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_mac_sign_setup rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HMAC alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
    st = psa_generate_key(&attrs, &key_id);
    if (check_status(st, "psa_generate_key(ECDSA alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_sign_hash rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ECDSA alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(DERIVE alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF alg none)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_input_key rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_cipher_abort(&cipher_op);
    (void)psa_aead_abort(&aead_op);
    (void)psa_mac_abort(&mac_op);
    (void)psa_key_derivation_abort(&kdf_op);
    return ret;
}

static int test_secondary_algorithm_is_not_supported(void)
{
    static const uint8_t aes_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);
    attrs.policy.alg2 = PSA_ALG_CTR;

    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_true(st == PSA_ERROR_NOT_SUPPORTED,
                   "psa_import_key rejects unsupported secondary algorithm policy") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "psa_import_key leaves key id null when alg2 is unsupported") != TEST_OK) {
        return TEST_FAIL;
    }

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);
    attrs.policy.alg2 = PSA_ALG_CTR;

    st = psa_generate_key(&attrs, &key_id);
    if (check_true(st == PSA_ERROR_NOT_SUPPORTED,
                   "psa_generate_key rejects unsupported secondary algorithm policy") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "psa_generate_key leaves key id null when alg2 is unsupported") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_mac_error_aborts_operation(void)
{
    static const uint8_t key[] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t msg[] = "mac error state";
    uint8_t mac[WC_SHA256_DIGEST_SIZE];
    size_t mac_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC error state)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_mac_sign_setup(error state)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_update(&op, msg, sizeof(msg) - 1);
    if (check_status(st, "psa_mac_update(error state seed)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_sign_finish(&op, mac, 1, &mac_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_mac_sign_finish(error state status)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_update(&op, msg, 1);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_mac_update(error state aborted)") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_mac_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_cipher_cbc(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[32] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
    };
    static const uint8_t expected[sizeof(plaintext)] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
        0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
        0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2
    };
    uint8_t out[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext) + 16];
    size_t out_len = 0;
    size_t finish_len = 0;
    size_t dec_len = 0;
    size_t dec_finish_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES)") != TEST_OK) return TEST_FAIL;

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_encrypt_setup") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext), out, sizeof(out), &out_len);
    if (check_status(st, "psa_cipher_update") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_finish(&op, out + out_len, sizeof(out) - out_len, &finish_len);
    if (check_status(st, "psa_cipher_finish") != TEST_OK) return TEST_FAIL;
    out_len += finish_len;

    if (check_true(out_len == sizeof(expected), "psa_cipher_encrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_cipher_encrypt", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_decrypt_setup") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(dec)") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_update(&op, out, out_len, dec, sizeof(dec), &dec_len);
    if (check_status(st, "psa_cipher_update(dec)") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_finish(&op, dec + dec_len, sizeof(dec) - dec_len, &dec_finish_len);
    if (check_status(st, "psa_cipher_finish(dec)") != TEST_OK) return TEST_FAIL;
    dec_len += dec_finish_len;

    if (check_true(dec_len == sizeof(plaintext), "psa_cipher_decrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_cipher_decrypt", dec, plaintext, sizeof(plaintext)) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

/* Exercises psa_cipher_generate_iv, which no other test reaches. Covers the
 * encrypt-direction success path (a freshly randomized IV is produced and
 * accepted by the operation, and a round trip still decrypts), the
 * decrypt-direction rejection, the re-generation rejection on an operation that
 * already has an IV, and the buffer-too-small rejection. The IV buffers are
 * zero-initialized so that dropping the psa_generate_random() call would leave
 * them equal and be caught by the "IVs differ" check. */
static int test_cipher_generate_iv(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    uint8_t iv1[16] = {0};
    uint8_t iv2[16] = {0};
    uint8_t small_iv[8] = {0};
    uint8_t enc[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext) + 16];
    size_t iv1_len = 0;
    size_t iv2_len = 0;
    size_t small_len = 0;
    size_t enc_len = 0;
    size_t enc_finish = 0;
    size_t dec_len = 0;
    size_t dec_finish = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(generate_iv)") != TEST_OK) goto cleanup;

    /* (a) encrypt-direction success: an IV is generated, has the algorithm's
     * length, and the operation can complete an encrypt round trip with it. */
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_encrypt_setup(gen_iv)") != TEST_OK) goto cleanup;
    st = psa_cipher_generate_iv(&op, iv1, sizeof(iv1), &iv1_len);
    if (check_status(st, "psa_cipher_generate_iv") != TEST_OK) goto cleanup;
    if (check_true(iv1_len == 16, "psa_cipher_generate_iv length") != TEST_OK) goto cleanup;

    /* (c) a second generate on the same operation must be rejected. */
    st = psa_cipher_generate_iv(&op, iv2, sizeof(iv2), &iv2_len);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_cipher_generate_iv rejects re-generation") != TEST_OK) goto cleanup;

    st = psa_cipher_update(&op, plaintext, sizeof(plaintext), enc, sizeof(enc), &enc_len);
    if (check_status(st, "psa_cipher_update(gen_iv)") != TEST_OK) goto cleanup;
    st = psa_cipher_finish(&op, enc + enc_len, sizeof(enc) - enc_len, &enc_finish);
    if (check_status(st, "psa_cipher_finish(gen_iv)") != TEST_OK) goto cleanup;
    enc_len += enc_finish;

    /* Decrypt using the generated IV to confirm it was the one actually used. */
    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_decrypt_setup(gen_iv)") != TEST_OK) goto cleanup;
    st = psa_cipher_set_iv(&op, iv1, iv1_len);
    if (check_status(st, "psa_cipher_set_iv(gen_iv dec)") != TEST_OK) goto cleanup;
    st = psa_cipher_update(&op, enc, enc_len, dec, sizeof(dec), &dec_len);
    if (check_status(st, "psa_cipher_update(gen_iv dec)") != TEST_OK) goto cleanup;
    st = psa_cipher_finish(&op, dec + dec_len, sizeof(dec) - dec_len, &dec_finish);
    if (check_status(st, "psa_cipher_finish(gen_iv dec)") != TEST_OK) goto cleanup;
    dec_len += dec_finish;
    if (check_true(dec_len == sizeof(plaintext), "psa_cipher_generate_iv round-trip length") != TEST_OK) goto cleanup;
    if (check_buf_eq("psa_cipher_generate_iv round-trip", dec, plaintext, sizeof(plaintext)) != TEST_OK) goto cleanup;

    /* (a cont.) a fresh operation must produce a different random IV. */
    op = psa_cipher_operation_init();
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_encrypt_setup(gen_iv 2)") != TEST_OK) goto cleanup;
    st = psa_cipher_generate_iv(&op, iv2, sizeof(iv2), &iv2_len);
    if (check_status(st, "psa_cipher_generate_iv(2)") != TEST_OK) goto cleanup;
    if (check_true(memcmp(iv1, iv2, sizeof(iv1)) != 0,
                   "psa_cipher_generate_iv produces fresh randomness") != TEST_OK) goto cleanup;
    (void)psa_cipher_abort(&op);

    /* (b) decrypt-direction operations must reject IV generation. */
    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_decrypt_setup(gen_iv reject)") != TEST_OK) goto cleanup;
    st = psa_cipher_generate_iv(&op, iv2, sizeof(iv2), &iv2_len);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_cipher_generate_iv rejects decrypt direction") != TEST_OK) goto cleanup;
    (void)psa_cipher_abort(&op);

    /* (d) too-small output buffer must be rejected. */
    op = psa_cipher_operation_init();
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_encrypt_setup(gen_iv small)") != TEST_OK) goto cleanup;
    st = psa_cipher_generate_iv(&op, small_iv, sizeof(small_iv), &small_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_cipher_generate_iv rejects too-small buffer") != TEST_OK) goto cleanup;

    ret = TEST_OK;

cleanup:
    (void)psa_cipher_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_cipher_rejects_algorithm_mismatch(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES CBC policy)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_cipher_encrypt_setup rejects mismatched algorithm policy") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_cipher_abort(&op);
    return ret;
}

static int test_cipher_requires_decrypt_usage(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES encrypt-only)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_cipher_decrypt_setup requires decrypt usage") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_cipher_abort(&op);
    return ret;
}

static int test_cipher_rejects_non_aes_key_type(void)
{
    static const uint8_t key[32] = {
        0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
        0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
        0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
        0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_STREAM_CIPHER);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(ChaCha20 for AES cipher mismatch)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_true(st == PSA_ERROR_NOT_SUPPORTED,
                   "psa_cipher_encrypt_setup rejects non-AES key for AES cipher") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_cipher_abort(&op);
    return ret;
}

static int test_mac_rejects_algorithm_mismatch(void)
{
    static const uint8_t hmac_key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(HMAC SHA-256 policy)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_512));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_mac_sign_setup rejects mismatched HMAC algorithm policy") != TEST_OK) {
        goto cleanup;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HMAC SHA-256 policy)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs,
        PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16));

    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(HMAC minimum-length policy)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_sign_setup(&op, key_id,
        PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 8));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_mac_sign_setup rejects MAC shorter than minimum policy") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_mac_abort(&op);
    return ret;
}

static int test_mac_requires_verify_usage(void)
{
    static const uint8_t hmac_key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t msg[] = "hmac message";
    uint8_t mac[WC_SHA256_DIGEST_SIZE];
    size_t mac_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(HMAC sign-only)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         msg, sizeof(msg) - 1, mac, sizeof(mac), &mac_len);
    if (check_status(st, "psa_mac_compute(sign-only)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_mac_verify(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        msg, sizeof(msg) - 1, mac, mac_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_mac_verify requires verify usage") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_export_key_requires_usage_flag(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t exported[sizeof(key)];
    size_t exported_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES no export)") != TEST_OK) return TEST_FAIL;

    st = psa_export_key(key_id, exported, sizeof(exported), &exported_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_export_key requires PSA_KEY_USAGE_EXPORT") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES no export)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static void setup_aes_key_attrs(psa_key_attributes_t* attrs, psa_key_usage_t usage,
                                psa_algorithm_t alg, psa_key_lifetime_t lifetime)
{
    *attrs = psa_key_attributes_init();
    psa_set_key_type(attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(attrs, 128);
    psa_set_key_usage_flags(attrs, usage);
    psa_set_key_algorithm(attrs, alg);
    psa_set_key_lifetime(attrs, lifetime);
}

static int get_persistent_key_store_path(psa_key_id_t key_id, char* path,
                                         size_t path_size)
{
    const char* root = getenv("WOLFPSA_TOKEN_PATH");

    if (root == NULL) {
        root = "./.store";
    }

    return snprintf(path, path_size, "%s/psa_key_%016lx_%016lx", root,
                    (unsigned long)key_id, 0ul);
}

static int overwrite_persistent_key_data_length(psa_key_id_t key_id,
                                                size_t key_data_length)
{
    char path[256];
    FILE* file;
    long offset;
    size_t written;
    int len;

    len = get_persistent_key_store_path(key_id, path, sizeof(path));
    if (len <= 0 || (size_t)len >= sizeof(path)) {
        return TEST_FAIL;
    }

    offset = (long)(sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) +
                    sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) +
                    sizeof(psa_key_lifetime_t));

    file = fopen(path, "r+b");
    if (file == NULL) {
        return TEST_FAIL;
    }

    if (fseek(file, offset, SEEK_SET) != 0) {
        fclose(file);
        return TEST_FAIL;
    }

    written = fwrite(&key_data_length, sizeof(key_data_length), 1, file);
    fclose(file);
    return written == 1 ? TEST_OK : TEST_FAIL;
}

static int test_copy_key_copies_material_and_attributes(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t exported[sizeof(key)];
    size_t exported_len = 0;
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = 0;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_attributes_t got_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT |
                        PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES copy source)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_status(st, "psa_copy_key(success)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(copy_key != src_key, "psa_copy_key returns a new key id") != TEST_OK) {
        goto cleanup;
    }

    st = psa_export_key(copy_key, exported, sizeof(exported), &exported_len);
    if (check_status(st, "psa_export_key(copied AES)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(exported_len == sizeof(key), "psa_export_key(copied AES) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_export_key(copied AES)", exported, key, sizeof(key)) != TEST_OK) {
        goto cleanup;
    }

    st = psa_get_key_attributes(copy_key, &got_attrs);
    if (check_status(st, "psa_get_key_attributes(copied AES)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_type(&got_attrs) == PSA_KEY_TYPE_AES,
                   "psa_copy_key preserves type") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_bits(&got_attrs) == 128,
                   "psa_copy_key preserves bits") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_algorithm(&got_attrs) == PSA_ALG_CBC_NO_PADDING,
                   "psa_copy_key preserves algorithm") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_lifetime(&got_attrs) == PSA_KEY_LIFETIME_VOLATILE,
                   "psa_copy_key preserves lifetime") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_usage_flags(&got_attrs) ==
                   (PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT),
                   "psa_copy_key intersects usage flags") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&got_attrs);
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != 0) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_export_key_rejects_oversized_persistent_length(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t exported[sizeof(key)];
    size_t exported_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 2406u;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    size_t oversized_length;
    int ret = TEST_FAIL;

    if (sizeof(size_t) <= sizeof(int)) {
        return TEST_SKIPPED;
    }

    (void)psa_destroy_key(persistent_id);

    setup_aes_key_attrs(&attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, persistent_id);
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES persistent oversized length)") != TEST_OK) {
        goto cleanup;
    }

    oversized_length = (size_t)UINT32_MAX + 17u;
    if (check_true(oversized_length > (size_t)INT_MAX,
                   "oversized persistent length exceeds INT_MAX") != TEST_OK) {
        goto cleanup;
    }
    if (overwrite_persistent_key_data_length(key_id, oversized_length) != TEST_OK) {
        printf("FAIL: overwrite_persistent_key_data_length\n");
        goto cleanup;
    }

    st = psa_export_key(key_id, exported, sizeof(exported), &exported_len);
    if (check_true(st == PSA_ERROR_DATA_INVALID,
                   "psa_export_key rejects oversized persistent length") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&attrs);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    else {
        (void)psa_destroy_key(persistent_id);
    }
    return ret;
}

static int test_export_key_zeroizes_buffer_on_short_read(void)
{
#if defined(_WIN32) || defined(_MSC_VER)
    return TEST_SKIPPED;
#else
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t exported[sizeof(key)];
    size_t exported_len = sizeof(key);
    psa_key_id_t key_id = 0;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 4097u;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    struct stat sb;
    char path[256];
    int len;
    int all_zero;
    size_t i;
    int ret = TEST_FAIL;

    (void)psa_destroy_key(persistent_id);

    setup_aes_key_attrs(&attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, persistent_id);
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES persistent short read)") != TEST_OK) {
        goto cleanup;
    }

    /* Truncate the store file by one byte so the key-data read in
     * psa_export_key returns fewer bytes than the recorded key_data_length.
     * The header (including the recorded length) stays intact, so the
     * failure happens at the key-data read, not the header read. */
    len = get_persistent_key_store_path(key_id, path, sizeof(path));
    if (len <= 0 || (size_t)len >= sizeof(path)) {
        printf("FAIL: get_persistent_key_store_path\n");
        goto cleanup;
    }
    if (stat(path, &sb) != 0 || sb.st_size <= 1) {
        printf("FAIL: stat persistent store\n");
        goto cleanup;
    }
    if (truncate(path, sb.st_size - 1) != 0) {
        printf("FAIL: truncate persistent store\n");
        goto cleanup;
    }

    /* Poison the caller buffer so leftover key material is detectable. */
    memset(exported, 0x5a, sizeof(exported));

    st = psa_export_key(key_id, exported, sizeof(exported), &exported_len);
    if (check_true(st == PSA_ERROR_STORAGE_FAILURE,
                   "psa_export_key reports short key-data read") != TEST_OK) {
        goto cleanup;
    }

    all_zero = 1;
    for (i = 0; i < sizeof(exported); i++) {
        if (exported[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (check_true(all_zero,
                   "psa_export_key zeroizes buffer on short read") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(exported_len == 0,
                   "psa_export_key clears length on short read") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&attrs);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    else {
        (void)psa_destroy_key(persistent_id);
    }
    return ret;
#endif
}

static int test_import_key_short_write_leaves_no_persistent_key(void)
{
#if defined(_WIN32) || defined(_MSC_VER) || !defined(RLIMIT_FSIZE)
    return TEST_SKIPPED;
#else
    enum { KEY_LEN = 1024 };
    uint8_t material[KEY_LEN];
    uint8_t exported[KEY_LEN];
    size_t exported_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 3175u;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    struct rlimit old_limit;
    struct rlimit short_limit;
    void (*old_sigxfsz)(int);
    int limit_set = 0;
    int ret = TEST_FAIL;
    size_t i;

    for (i = 0; i < sizeof(material); i++) {
        material[i] = (uint8_t)(0xa5u ^ i);
    }

    (void)psa_destroy_key(persistent_id);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&attrs, KEY_LEN * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, persistent_id);

    if (getrlimit(RLIMIT_FSIZE, &old_limit) != 0) {
        ret = TEST_SKIPPED;
        goto cleanup;
    }
    old_sigxfsz = signal(SIGXFSZ, SIG_IGN);
    if (old_sigxfsz == SIG_ERR) {
        ret = TEST_SKIPPED;
        goto cleanup;
    }
    short_limit.rlim_cur = 1;
    short_limit.rlim_max = old_limit.rlim_max;
    if (setrlimit(RLIMIT_FSIZE, &short_limit) != 0) {
        (void)signal(SIGXFSZ, old_sigxfsz);
        ret = TEST_SKIPPED;
        goto cleanup;
    }
    limit_set = 1;

    st = psa_import_key(&attrs, material, sizeof(material), &key_id);

    (void)setrlimit(RLIMIT_FSIZE, &old_limit);
    (void)signal(SIGXFSZ, old_sigxfsz);
    limit_set = 0;

    if (check_true(st == PSA_ERROR_STORAGE_FAILURE,
                   "psa_import_key reports short persistent write") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "short persistent write leaves key id null") != TEST_OK) {
        goto cleanup;
    }

    /* The aborted temp file must not have been committed: no key exists. */
    st = psa_export_key(persistent_id, exported, sizeof(exported), &exported_len);
    if (check_true(st == PSA_ERROR_INVALID_HANDLE,
                   "short persistent write commits no key") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (limit_set) {
        (void)setrlimit(RLIMIT_FSIZE, &old_limit);
        (void)signal(SIGXFSZ, old_sigxfsz);
    }
    psa_reset_key_attributes(&attrs);
    (void)psa_destroy_key(persistent_id);
    return ret;
#endif
}

static int test_import_key_rejects_duplicate_persistent_id(void)
{
    static const uint8_t first[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t second[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    uint8_t exported[sizeof(first)];
    size_t exported_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 3857u;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    (void)psa_destroy_key(persistent_id);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&attrs, sizeof(first) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, persistent_id);

    st = psa_import_key(&attrs, first, sizeof(first), &key_id);
    if (check_status(st, "psa_import_key(first persistent)") != TEST_OK) {
        goto cleanup;
    }

    /* A second import to the same persistent id must be rejected per the PSA
     * Crypto API rather than silently overwriting the stored key. */
    key_id = 0;
    st = psa_import_key(&attrs, second, sizeof(second), &key_id);
    if (check_true(st == PSA_ERROR_ALREADY_EXISTS,
                   "psa_import_key rejects duplicate persistent id") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "rejected duplicate import leaves key id null") != TEST_OK) {
        goto cleanup;
    }

    /* The original key material must remain intact. */
    st = psa_export_key(persistent_id, exported, sizeof(exported), &exported_len);
    if (check_status(st, "psa_export_key(after duplicate import)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(exported_len == sizeof(first),
                   "duplicate import preserves key length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("duplicate import preserves key data",
                     exported, first, sizeof(first)) != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&attrs);
    (void)psa_destroy_key(persistent_id);
    return ret;
}

static int test_copy_key_requires_copy_usage_flag(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES no copy)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_copy_key requires PSA_KEY_USAGE_COPY for volatile keys") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_copy_key_inherits_unspecified_type(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_attributes_t got_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT |
                        PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES copy inherit source)") != TEST_OK) {
        goto cleanup;
    }

    psa_set_key_usage_flags(&dst_attrs,
                            PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&dst_attrs, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_lifetime(&dst_attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_status(st, "psa_copy_key inherits unspecified type") != TEST_OK) {
        goto cleanup;
    }

    st = psa_get_key_attributes(copy_key, &got_attrs);
    if (check_status(st, "psa_get_key_attributes(inherited type copy)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_type(&got_attrs) == PSA_KEY_TYPE_AES,
                   "psa_copy_key inherited type") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_bits(&got_attrs) == 128,
                   "psa_copy_key inherited bits") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&got_attrs);
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_copy_key_persistent_inherits_unspecified_type(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 2812u;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_attributes_t got_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    (void)psa_destroy_key(persistent_id);

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT |
                        PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&src_attrs, persistent_id);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES persistent copy inherit source)") != TEST_OK) {
        goto cleanup;
    }

    psa_set_key_usage_flags(&dst_attrs,
                            PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&dst_attrs, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_lifetime(&dst_attrs, PSA_KEY_LIFETIME_PERSISTENT);

    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_status(st, "psa_copy_key persistent inherits unspecified type") != TEST_OK) {
        goto cleanup;
    }

    st = psa_get_key_attributes(copy_key, &got_attrs);
    if (check_status(st, "psa_get_key_attributes(persistent inherited type copy)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_type(&got_attrs) == PSA_KEY_TYPE_AES,
                   "psa_copy_key persistent inherited type") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_bits(&got_attrs) == 128,
                   "psa_copy_key persistent inherited bits") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&got_attrs);
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    else {
        (void)psa_destroy_key(persistent_id);
    }
    return ret;
}

static int test_copy_key_rejects_attribute_mismatch(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT |
                        PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES copy mismatch source)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_DES);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects type mismatch") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_bits(&dst_attrs, 192);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects bit-size mismatch") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_ECB_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects algorithm mismatch") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects lifetime mismatch") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_copy_key_requires_copy_usage_flag_persistent(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 2405u;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    (void)psa_destroy_key(persistent_id);

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&src_attrs, persistent_id);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES persistent no copy)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_copy_key requires PSA_KEY_USAGE_COPY for persistent keys") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_cipher_cbc_pkcs7_multipart_decrypt(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[17] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,
        0x67
    };
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];
    size_t ciphertext_len = 0;
    size_t part_len = 0;
    size_t finish_len = 0;
    size_t dec_len = 0;
    size_t dec_part_len = 0;
    size_t dec_finish_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES PKCS7)") != TEST_OK) goto cleanup;

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        result = TEST_SKIPPED;
        goto cleanup;
    }
    if (check_status(st, "psa_cipher_encrypt_setup(PKCS7)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext),
                           ciphertext, sizeof(ciphertext), &part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 enc)") != TEST_OK) {
        goto cleanup;
    }
    ciphertext_len += part_len;
    st = psa_cipher_finish(&op, ciphertext + ciphertext_len,
                           sizeof(ciphertext) - ciphertext_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(PKCS7 enc)") != TEST_OK) {
        goto cleanup;
    }
    ciphertext_len += finish_len;
    (void)psa_cipher_abort(&op);

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_decrypt_setup(PKCS7)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7 dec)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_update(&op, ciphertext, 1,
                           decrypted, sizeof(decrypted), &dec_part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 dec 1)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(dec_part_len == 0, "psa_cipher_update(PKCS7 dec 1) length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_update(&op, ciphertext + 1, 16,
                           decrypted, sizeof(decrypted), &dec_part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 dec 16)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(dec_part_len == 16, "psa_cipher_update(PKCS7 dec 16) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_cipher_update(PKCS7 dec 16)",
                     decrypted, plaintext, dec_part_len) != TEST_OK) {
        goto cleanup;
    }
    dec_len += dec_part_len;

    st = psa_cipher_update(&op, ciphertext + 17, ciphertext_len - 17,
                           decrypted + dec_len, sizeof(decrypted) - dec_len,
                           &dec_part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 dec tail)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(dec_part_len == 0, "psa_cipher_update(PKCS7 dec tail) length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_finish(&op, decrypted + dec_len, sizeof(decrypted) - dec_len,
                           &dec_finish_len);
    if (check_status(st, "psa_cipher_finish(PKCS7 dec)") != TEST_OK) {
        goto cleanup;
    }
    dec_len += dec_finish_len;
    (void)psa_cipher_abort(&op);

    if (check_true(dec_len == sizeof(plaintext), "psa_cipher_decrypt(PKCS7) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_cipher_decrypt(PKCS7)", decrypted, plaintext, sizeof(plaintext)) != TEST_OK) {
        goto cleanup;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES PKCS7)") != TEST_OK) return TEST_FAIL;

    key_id = 0;
    result = TEST_OK;

cleanup:
    (void)psa_cipher_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return result;
}

static int test_cipher_cbc_pkcs7_decrypt_update_small_output(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[17] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,
        0x67
    };
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t too_small[1];
    size_t ciphertext_len = 0;
    size_t part_len = 0;
    size_t finish_len = 0;
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES PKCS7 small out)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_encrypt_setup(PKCS7 small out)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7 small out enc)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext),
                           ciphertext, sizeof(ciphertext), &part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 small out enc)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    ciphertext_len += part_len;
    st = psa_cipher_finish(&op, ciphertext + ciphertext_len,
                           sizeof(ciphertext) - ciphertext_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(PKCS7 small out enc)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    ciphertext_len += finish_len;

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_decrypt_setup(PKCS7 small out)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7 small out dec)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_cipher_update(&op, ciphertext, 1, too_small, sizeof(too_small), &out_len);
    if (check_status(st, "psa_cipher_update(PKCS7 small out seed)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(out_len == 0,
                   "psa_cipher_update(PKCS7 small out seed) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_cipher_update(&op, ciphertext + 1, 16, too_small, sizeof(too_small), &out_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_cipher_update(PKCS7 small out status)") != TEST_OK) {
        (void)psa_cipher_abort(&op);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    (void)psa_cipher_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES PKCS7 small out)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_cipher_error_aborts_operation(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[17] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,
        0x67
    };
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t small[1];
    size_t ciphertext_len = 0;
    size_t part_len = 0;
    size_t finish_len = 0;
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES error state)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_encrypt_setup(error state enc)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(error state enc)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext),
                           ciphertext, sizeof(ciphertext), &part_len);
    if (check_status(st, "psa_cipher_update(error state enc)") != TEST_OK) {
        goto cleanup;
    }
    ciphertext_len += part_len;
    st = psa_cipher_finish(&op, ciphertext + ciphertext_len,
                           sizeof(ciphertext) - ciphertext_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(error state enc)") != TEST_OK) {
        goto cleanup;
    }
    ciphertext_len += finish_len;
    (void)psa_cipher_abort(&op);

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_decrypt_setup(error state)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(error state dec)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, ciphertext, 1, small, sizeof(small), &out_len);
    if (check_status(st, "psa_cipher_update(error state seed)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_update(&op, ciphertext + 1, 16, small, sizeof(small), &out_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_cipher_update(error state status)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_finish(&op, ciphertext, sizeof(ciphertext), &out_len);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_cipher_finish(error state aborted)") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_cipher_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_cipher_ccm_star_no_tag_multipart(void)
{
    static const uint8_t key[16] = {
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
        0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf
    };
    static const uint8_t nonce[13] = {
        0x00,0x00,0x00,0x03,0x02,0x01,0x00,0xa0,
        0xa1,0xa2,0xa3,0xa4,0xa5
    };
    static const uint8_t plaintext[32] = {
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27
    };
    uint8_t single[sizeof(plaintext)];
    uint8_t multi[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    size_t single_len = 0;
    size_t multi_len = 0;
    size_t part_len = 0;
    size_t finish_len = 0;
    size_t decrypted_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CCM_STAR_NO_TAG);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES CCM* no tag)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CCM_STAR_NO_TAG);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        result = TEST_SKIPPED;
        goto cleanup;
    }
    if (check_status(st, "psa_cipher_encrypt_setup(CCM* no tag single)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_cipher_set_iv(CCM* no tag single)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext),
                           single, sizeof(single), &single_len);
    if (check_status(st, "psa_cipher_update(CCM* no tag single)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_finish(&op, single + single_len, sizeof(single) - single_len,
                           &finish_len);
    if (check_status(st, "psa_cipher_finish(CCM* no tag single)") != TEST_OK) {
        goto cleanup;
    }
    single_len += finish_len;
    (void)psa_cipher_abort(&op);

    op = psa_cipher_operation_init();
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CCM_STAR_NO_TAG);
    if (check_status(st, "psa_cipher_encrypt_setup(CCM* no tag multi)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_cipher_set_iv(CCM* no tag multi)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, plaintext, 16, multi, sizeof(multi), &part_len);
    if (check_status(st, "psa_cipher_update(CCM* no tag first chunk)") != TEST_OK) {
        goto cleanup;
    }
    multi_len += part_len;
    st = psa_cipher_update(&op, plaintext + 16, sizeof(plaintext) - 16,
                           multi + multi_len, sizeof(multi) - multi_len, &part_len);
    if (check_status(st, "psa_cipher_update(CCM* no tag second chunk)") != TEST_OK) {
        goto cleanup;
    }
    multi_len += part_len;
    st = psa_cipher_finish(&op, multi + multi_len, sizeof(multi) - multi_len,
                           &finish_len);
    if (check_status(st, "psa_cipher_finish(CCM* no tag multi)") != TEST_OK) {
        goto cleanup;
    }
    multi_len += finish_len;
    (void)psa_cipher_abort(&op);

    if (check_true(single_len == sizeof(plaintext), "psa_cipher_update(CCM* no tag single) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(multi_len == single_len, "psa_cipher_update(CCM* no tag multi) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_cipher_update(CCM* no tag split matches single)",
                     multi, single, single_len) != TEST_OK) {
        goto cleanup;
    }

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CCM_STAR_NO_TAG);
    if (check_status(st, "psa_cipher_decrypt_setup(CCM* no tag multi)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_cipher_set_iv(CCM* no tag dec)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, multi, 16, decrypted, sizeof(decrypted), &part_len);
    if (check_status(st, "psa_cipher_update(CCM* no tag dec first chunk)") != TEST_OK) {
        goto cleanup;
    }
    decrypted_len += part_len;
    st = psa_cipher_update(&op, multi + 16, sizeof(multi) - 16,
                           decrypted + decrypted_len, sizeof(decrypted) - decrypted_len,
                           &part_len);
    if (check_status(st, "psa_cipher_update(CCM* no tag dec second chunk)") != TEST_OK) {
        goto cleanup;
    }
    decrypted_len += part_len;
    st = psa_cipher_finish(&op, decrypted + decrypted_len,
                           sizeof(decrypted) - decrypted_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(CCM* no tag dec)") != TEST_OK) {
        goto cleanup;
    }
    decrypted_len += finish_len;

    if (check_true(decrypted_len == sizeof(plaintext), "psa_cipher_decrypt(CCM* no tag multi) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_cipher_decrypt(CCM* no tag multi)",
                     decrypted, plaintext, sizeof(plaintext)) != TEST_OK) {
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    (void)psa_cipher_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return result;
}

static int test_aead_gcm(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t aad[1] = { 0 };
    static const size_t aad_len = 0;
    static const uint8_t plaintext[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t expected[sizeof(plaintext) + 16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78,
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    uint8_t out[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext)];
    size_t out_len = 0;
    size_t dec_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM)") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, aad_len,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_status(st, "psa_aead_encrypt") != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(expected), "psa_aead_encrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_aead_encrypt", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, aad_len,
                          out, out_len,
                          dec, sizeof(dec), &dec_len);
    if (check_status(st, "psa_aead_decrypt") != TEST_OK) return TEST_FAIL;
    if (check_true(dec_len == sizeof(plaintext), "psa_aead_decrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_aead_decrypt", dec, plaintext, sizeof(plaintext)) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

/* F-5551: a corrupted authentication tag must be rejected with
 * PSA_ERROR_INVALID_SIGNATURE and must not yield any accepted plaintext.
 * Exercises the one-shot psa_aead_decrypt path. */
static int aead_corrupt_tag_oneshot(psa_key_id_t key_id, psa_algorithm_t alg,
                                    const uint8_t *nonce, size_t nonce_len,
                                    const char *label)
{
    static const uint8_t plaintext[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    uint8_t aead_out[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext)];
    size_t out_len = 0;
    size_t dec_len = 0;
    psa_status_t st;

    st = psa_aead_encrypt(key_id, alg, nonce, nonce_len, NULL, 0,
                          plaintext, sizeof(plaintext),
                          aead_out, sizeof(aead_out), &out_len);
    if (check_status(st, label) != TEST_OK) return TEST_FAIL;
    if (check_true(out_len > 0, label) != TEST_OK) return TEST_FAIL;

    /* Flip one tag byte (the last byte of the ciphertext||tag output). */
    aead_out[out_len - 1] ^= 0xff;

    st = psa_aead_decrypt(key_id, alg, nonce, nonce_len, NULL, 0,
                          aead_out, out_len, dec, sizeof(dec), &dec_len);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE, label) != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(dec_len == 0, label) != TEST_OK) return TEST_FAIL;
    return TEST_OK;
}

/* F-5551: same property exercised through the multipart psa_aead_verify path. */
static int aead_corrupt_tag_multipart(psa_key_id_t key_id, psa_algorithm_t alg,
                                      const uint8_t *nonce, size_t nonce_len,
                                      const char *label)
{
    static const uint8_t plaintext[16] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    const size_t tag_len = 16;
    uint8_t aead_out[sizeof(plaintext) + 16];
    uint8_t update_out[sizeof(plaintext)];
    uint8_t dec[sizeof(plaintext)];
    size_t out_len = 0;
    size_t update_len = 0;
    size_t dec_len = 0;
    size_t ct_len;
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_OK;

    st = psa_aead_encrypt(key_id, alg, nonce, nonce_len, NULL, 0,
                          plaintext, sizeof(plaintext),
                          aead_out, sizeof(aead_out), &out_len);
    if (check_status(st, label) != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(plaintext) + tag_len, label) != TEST_OK) {
        return TEST_FAIL;
    }
    ct_len = out_len - tag_len;

    /* Flip one tag byte. */
    aead_out[out_len - 1] ^= 0xff;

    st = psa_aead_decrypt_setup(&op, key_id, alg);
    if (check_status(st, label) != TEST_OK) { ret = TEST_FAIL; goto cleanup; }
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    if (check_status(st, label) != TEST_OK) { ret = TEST_FAIL; goto cleanup; }
    st = psa_aead_update_ad(&op, NULL, 0);
    if (check_status(st, label) != TEST_OK) { ret = TEST_FAIL; goto cleanup; }
    st = psa_aead_update(&op, aead_out, ct_len,
                         update_out, sizeof(update_out), &update_len);
    if (check_status(st, label) != TEST_OK) { ret = TEST_FAIL; goto cleanup; }
    st = psa_aead_verify(&op, dec, sizeof(dec), &dec_len,
                         aead_out + ct_len, tag_len);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE, label) != TEST_OK) {
        ret = TEST_FAIL;
    }

cleanup:
    psa_aead_abort(&op);
    return ret;
}

/* F-3653: psa_aead_encrypt must return BUFFER_TOO_SMALL without modifying the
 * output buffer when ciphertext_size < plaintext_length + tag_length. */
static int test_aead_encrypt_buffer_too_small(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t plaintext[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    /* Exactly plaintext_length — no room for the 16-byte GCM tag. */
    uint8_t out[sizeof(plaintext)];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key") != TEST_OK) goto cleanup;

    XMEMSET(out, 0, sizeof(out));

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          NULL, 0,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_aead_encrypt with short buffer returns BUFFER_TOO_SMALL")
        != TEST_OK) goto cleanup;

    /* Output buffer must not have been modified on BUFFER_TOO_SMALL. */
    {
        uint8_t zeros[sizeof(out)];
        XMEMSET(zeros, 0, sizeof(zeros));
        if (check_buf_eq("psa_aead_encrypt short-buf output unmodified",
                         out, zeros, sizeof(zeros)) != TEST_OK) goto cleanup;
    }

    result = TEST_OK;
cleanup:
    if (key_id != 0)
        (void)psa_destroy_key(key_id);
    return result;
}

static int test_aead_rejects_corrupted_tag(void)
{
    static const uint8_t aes_key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs;
    psa_status_t st;
    int ret = TEST_OK;

#ifdef HAVE_AESGCM
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(GCM corrupt tag)") != TEST_OK) {
        return TEST_FAIL;
    }
    if (aead_corrupt_tag_oneshot(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                 "psa_aead_decrypt(GCM corrupt tag)") != TEST_OK) {
        ret = TEST_FAIL;
    }
    if (aead_corrupt_tag_multipart(key_id, PSA_ALG_GCM, nonce, sizeof(nonce),
                                   "psa_aead_verify(GCM corrupt tag)") != TEST_OK) {
        ret = TEST_FAIL;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM corrupt tag)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CCM);
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(CCM corrupt tag)") != TEST_OK) {
        return TEST_FAIL;
    }
    if (aead_corrupt_tag_oneshot(key_id, PSA_ALG_CCM, nonce, sizeof(nonce),
                                 "psa_aead_decrypt(CCM corrupt tag)") != TEST_OK) {
        ret = TEST_FAIL;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(CCM corrupt tag)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;
#endif /* HAVE_AESCCM */

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    {
        static const uint8_t chacha_key[32] = {
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
            0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
            0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
        };
        attrs = psa_key_attributes_init();
        psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
        psa_set_key_bits(&attrs, 256);
        psa_set_key_usage_flags(&attrs,
                                PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);
        st = psa_import_key(&attrs, chacha_key, sizeof(chacha_key), &key_id);
        if (check_status(st, "psa_import_key(ChaCha20 corrupt tag)") != TEST_OK) {
            return TEST_FAIL;
        }
        if (aead_corrupt_tag_oneshot(key_id, PSA_ALG_CHACHA20_POLY1305,
                                     nonce, sizeof(nonce),
                                     "psa_aead_decrypt(ChaCha20 corrupt tag)")
                != TEST_OK) {
            ret = TEST_FAIL;
        }
        st = psa_destroy_key(key_id);
        if (check_status(st, "psa_destroy_key(ChaCha20 corrupt tag)") != TEST_OK) {
            return TEST_FAIL;
        }
        key_id = 0;
    }
#endif /* HAVE_CHACHA && HAVE_POLY1305 */

    return ret;
}

static int test_aead_generate_nonce(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t aad[4] = { 0x10,0x11,0x12,0x13 };
    static const uint8_t plaintext[16] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    uint8_t nonce[16];
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];
    uint8_t combined[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext)];
    size_t nonce_len = 0;
    size_t ct_len = 0;
    size_t tag_len = 0;
    size_t update_len = 0;
    size_t dec_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_OK;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(generate_nonce)") != TEST_OK) return TEST_FAIL;

    /* (1) success on an encrypt context: the generated nonce drives a round-trip */
    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "encrypt_setup(generate_nonce)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_generate_nonce(&op, nonce, sizeof(nonce), &nonce_len);
    if (check_status(st, "psa_aead_generate_nonce") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    if (check_true(nonce_len == PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_GCM),
                   "generate_nonce length matches PSA_AEAD_NONCE_LENGTH") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_update_ad(&op, aad, sizeof(aad));
    if (check_status(st, "update_ad(generate_nonce)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_update(&op, plaintext, sizeof(plaintext),
                         ciphertext, sizeof(ciphertext), &update_len);
    if (check_status(st, "update(generate_nonce)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_finish(&op, ciphertext + update_len, sizeof(ciphertext) - update_len,
                         &ct_len, tag, sizeof(tag), &tag_len);
    if (check_status(st, "finish(generate_nonce)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    if (check_true(update_len + ct_len == sizeof(ciphertext) &&
                   tag_len == sizeof(tag),
                   "generate_nonce ciphertext+tag length") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    memcpy(combined, ciphertext, sizeof(ciphertext));
    memcpy(combined + sizeof(ciphertext), tag, sizeof(tag));
    /* The generated nonce must be accepted by a single-shot decrypt. */
    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          nonce, nonce_len,
                          aad, sizeof(aad),
                          combined, sizeof(combined),
                          dec, sizeof(dec), &dec_len);
    if (check_status(st, "decrypt(generate_nonce round-trip)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    if (check_buf_eq("generate_nonce round-trip plaintext",
                     dec, plaintext, sizeof(plaintext)) != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }

    /* (2) generating a nonce on a decrypt context is rejected. */
    (void)psa_aead_abort(&op);
    op = psa_aead_operation_init();
    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "decrypt_setup(generate_nonce neg)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_generate_nonce(&op, nonce, sizeof(nonce), &nonce_len);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "generate_nonce on decrypt context rejected") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    (void)psa_aead_abort(&op);

    /* (3) generating a nonce twice on the same operation is rejected. */
    op = psa_aead_operation_init();
    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "encrypt_setup(generate_nonce twice)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_generate_nonce(&op, nonce, sizeof(nonce), &nonce_len);
    if (check_status(st, "generate_nonce(first)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_generate_nonce(&op, nonce, sizeof(nonce), &nonce_len);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "generate_nonce twice rejected") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    (void)psa_aead_abort(&op);

    /* (5) nonce buffer smaller than PSA_AEAD_NONCE_LENGTH is rejected. */
    op = psa_aead_operation_init();
    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "encrypt_setup(generate_nonce small buf)") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    st = psa_aead_generate_nonce(&op, nonce,
                                 PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_GCM) - 1,
                                 &nonce_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "generate_nonce buffer too small rejected") != TEST_OK) {
        ret = TEST_FAIL; goto cleanup;
    }
    (void)psa_aead_abort(&op);

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(generate_nonce)") != TEST_OK) return TEST_FAIL;
    key_id = 0;

#ifdef HAVE_AESCCM
    /* (4) CCM requires psa_aead_set_lengths before a nonce can be generated. */
    {
        psa_key_attributes_t ccm_attrs = psa_key_attributes_init();
        psa_key_id_t ccm_key_id = 0;

        psa_set_key_type(&ccm_attrs, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&ccm_attrs, 128);
        psa_set_key_usage_flags(&ccm_attrs, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&ccm_attrs, PSA_ALG_CCM);
        st = psa_import_key(&ccm_attrs, key, sizeof(key), &ccm_key_id);
        if (check_status(st, "psa_import_key(generate_nonce CCM)") != TEST_OK) {
            return TEST_FAIL;
        }
        op = psa_aead_operation_init();
        st = psa_aead_encrypt_setup(&op, ccm_key_id, PSA_ALG_CCM);
        if (check_status(st, "encrypt_setup(generate_nonce CCM)") != TEST_OK) {
            (void)psa_destroy_key(ccm_key_id);
            return TEST_FAIL;
        }
        st = psa_aead_generate_nonce(&op, nonce, sizeof(nonce), &nonce_len);
        if (check_true(st == PSA_ERROR_BAD_STATE,
                       "generate_nonce CCM without set_lengths rejected") != TEST_OK) {
            (void)psa_aead_abort(&op);
            (void)psa_destroy_key(ccm_key_id);
            return TEST_FAIL;
        }
        (void)psa_aead_abort(&op);
        st = psa_destroy_key(ccm_key_id);
        if (check_status(st, "psa_destroy_key(generate_nonce CCM)") != TEST_OK) {
            return TEST_FAIL;
        }
    }
#endif

    return TEST_OK;

cleanup:
    (void)psa_aead_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_aead_gcm_multipart_zero_length_inputs(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t aad[12] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b
    };
    static const uint8_t plaintext[16] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    uint8_t combined[sizeof(plaintext) + 16];
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];
    uint8_t decrypt_out[sizeof(plaintext)];
    uint8_t update_out[sizeof(plaintext)];
    uint8_t dummy[1] = { 0 };
    size_t combined_len = 0;
    size_t ciphertext_len = 0;
    size_t plaintext_len = 0;
    size_t tag_len = 0;
    size_t update_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_OK;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM zero-length multipart)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, sizeof(aad),
                          dummy, 0,
                          combined, sizeof(combined), &combined_len);
    if (check_status(st, "psa_aead_encrypt(GCM zero plaintext reference)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(combined_len == sizeof(tag),
                   "psa_aead_encrypt(GCM zero plaintext reference length)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update_ad(&op, aad, sizeof(aad));
    if (check_status(st, "psa_aead_update_ad(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update(&op, dummy, 0, update_out, sizeof(update_out), &update_len);
    if (check_status(st, "psa_aead_update(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(update_len == 0, "psa_aead_update(GCM zero plaintext) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_finish(&op, dummy, sizeof(dummy), &ciphertext_len,
                         tag, sizeof(tag), &tag_len);
    if (check_status(st, "psa_aead_finish(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(ciphertext_len == 0, "psa_aead_finish(GCM zero plaintext) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(tag_len == sizeof(tag), "psa_aead_finish(GCM zero plaintext) tag length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_buf_eq("psa_aead_finish(GCM zero plaintext) tag matches reference)",
                     tag, combined, sizeof(tag)) != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(GCM zero plaintext verify)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update_ad(&op, aad, sizeof(aad));
    if (check_status(st, "psa_aead_update_ad(GCM zero plaintext verify)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update(&op, dummy, 0, update_out, sizeof(update_out), &update_len);
    if (check_status(st, "psa_aead_update(GCM zero plaintext verify)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_verify(&op, dummy, sizeof(dummy), &plaintext_len, tag, tag_len);
    if (check_status(st, "psa_aead_verify(GCM zero plaintext)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(plaintext_len == 0, "psa_aead_verify(GCM zero plaintext) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, 0,
                          plaintext, sizeof(plaintext),
                          combined, sizeof(combined), &combined_len);
    if (check_status(st, "psa_aead_encrypt(GCM zero aad reference)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(combined_len == sizeof(plaintext) + sizeof(tag),
                   "psa_aead_encrypt(GCM zero aad reference length)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update_ad(&op, aad, 0);
    if (check_status(st, "psa_aead_update_ad(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update(&op, plaintext, sizeof(plaintext),
                         update_out, sizeof(update_out), &update_len);
    if (check_status(st, "psa_aead_update(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(update_len == 0, "psa_aead_update(GCM zero aad) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_finish(&op, ciphertext, sizeof(ciphertext), &ciphertext_len,
                         tag, sizeof(tag), &tag_len);
    if (check_status(st, "psa_aead_finish(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(ciphertext_len == sizeof(ciphertext), "psa_aead_finish(GCM zero aad) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(tag_len == sizeof(tag), "psa_aead_finish(GCM zero aad) tag length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_buf_eq("psa_aead_finish(GCM zero aad) ciphertext matches reference)",
                     ciphertext, combined, sizeof(ciphertext)) != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_buf_eq("psa_aead_finish(GCM zero aad) tag matches reference)",
                     tag, combined + sizeof(ciphertext), sizeof(tag)) != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(GCM zero aad verify)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update_ad(&op, aad, 0);
    if (check_status(st, "psa_aead_update_ad(GCM zero aad verify)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update(&op, ciphertext, ciphertext_len,
                         update_out, sizeof(update_out), &update_len);
    if (check_status(st, "psa_aead_update(GCM zero aad verify)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_verify(&op, decrypt_out, sizeof(decrypt_out), &plaintext_len, tag, tag_len);
    if (check_status(st, "psa_aead_verify(GCM zero aad)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(plaintext_len == sizeof(plaintext), "psa_aead_verify(GCM zero aad) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_buf_eq("psa_aead_verify(GCM zero aad)", decrypt_out, plaintext, sizeof(plaintext)) != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    if (key_id != 0) {
        st = psa_destroy_key(key_id);
        if (check_status(st, "psa_destroy_key(GCM zero-length multipart)") != TEST_OK) {
            return TEST_FAIL;
        }
    }
    return ret;
}

static int test_aead_multipart_length_overflow_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t chunk[2] = { 0xaa, 0x55 };
    uint8_t out[sizeof(chunk)];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    wolfpsa_aead_ctx_t *ctx;
    int ret = TEST_OK;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM overflow)") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup") != TEST_OK) goto cleanup;
    st = psa_aead_set_lengths(&op, SIZE_MAX, SIZE_MAX);
    if (check_status(st, "psa_aead_set_lengths") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce") != TEST_OK) goto cleanup;

    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->aad_length = SIZE_MAX - 1;
    st = psa_aead_update_ad(&op, chunk, sizeof(chunk));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_update_ad rejects wrapped accumulated length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(plaintext)") != TEST_OK) goto cleanup;
    st = psa_aead_set_lengths(&op, 0, SIZE_MAX);
    if (check_status(st, "psa_aead_set_lengths(plaintext)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(plaintext)") != TEST_OK) goto cleanup;

    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->input_length = SIZE_MAX - 1;
    st = psa_aead_update(&op, chunk, sizeof(chunk), out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_update rejects wrapped accumulated length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM overflow)") != TEST_OK) return TEST_FAIL;
    return ret;
}

/* F-3861: psa_aead_set_lengths is a one-shot setup call -- a second call
 * before any nonce/AAD/input is provided must fail with PSA_ERROR_BAD_STATE
 * rather than silently overwriting the committed lengths. */
static int test_aead_set_lengths_twice_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    int ret = TEST_OK;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(set_lengths twice)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(set_lengths twice)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_aead_set_lengths(&op, 4, 16);
    if (check_status(st, "psa_aead_set_lengths(first)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_aead_set_lengths(&op, 8, 32);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_aead_set_lengths rejects second call") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(set_lengths twice)") != TEST_OK) {
        return TEST_FAIL;
    }
    return ret;
}

static int test_aead_finish_verify_word32_overflow_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t empty_gcm_tag[16] = {
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
    };
    uint8_t out[1];
    uint8_t tag[sizeof(empty_gcm_tag)];
    size_t out_len = 0;
    size_t tag_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    wolfpsa_aead_ctx_t *ctx;
    int ret = TEST_OK;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM word32 overflow)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(word32 input)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 input)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->input = NULL;
    ctx->input_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_finish(&op, out, SIZE_MAX, &out_len, tag, sizeof(tag), &tag_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_finish rejects input_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(word32 aad)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 aad)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->aad = NULL;
    ctx->aad_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_finish(&op, out, sizeof(out), &out_len, tag, sizeof(tag), &tag_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_finish rejects aad_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(word32 input)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 verify input)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->input = NULL;
    ctx->input_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_verify(&op, out, SIZE_MAX, &out_len, empty_gcm_tag, sizeof(empty_gcm_tag));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_verify rejects input_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(word32 aad)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 verify aad)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->aad = NULL;
    ctx->aad_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_verify(&op, out, sizeof(out), &out_len, empty_gcm_tag, sizeof(empty_gcm_tag));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_verify rejects aad_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM word32 overflow)") != TEST_OK) {
        return TEST_FAIL;
    }
    return ret;
}

static int test_aead_policy_mismatch_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_OK;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);

    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM policy)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_CCM);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_aead_encrypt_setup rejects AEAD base mismatch") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id,
                                PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_aead_encrypt_setup rejects exact tag mismatch") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM policy)") != TEST_OK) {
        return TEST_FAIL;
    }

    psa_set_key_algorithm(&attrs,
                          PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 8));
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM at least tag)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id,
                                PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 12));
    if (check_status(st, "psa_aead_encrypt_setup(allows longer AEAD tag)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup_at_least;
    }
    psa_aead_abort(&op);

    st = psa_aead_encrypt_setup(&op, key_id,
                                PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 4));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_aead_encrypt_setup rejects shorter AEAD tag than policy") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup_at_least;
    }

cleanup_at_least:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM at least tag)") != TEST_OK) {
        return TEST_FAIL;
    }

    return ret;
}

static int test_aead_requires_decrypt_usage(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM encrypt-only)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_aead_decrypt_setup requires decrypt usage") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_aead_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

/* F-3860: psa_aead_finish on a decrypt context and psa_aead_verify on an
 * encrypt context must both return PSA_ERROR_BAD_STATE. */
static int test_aead_direction_mismatch_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t tag[16] = { 0 };
    uint8_t buf[16];
    size_t len;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(direction mismatch)") != TEST_OK) {
        goto cleanup;
    }

    /* decrypt_setup + psa_aead_finish must be rejected */
    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(direction mismatch)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_aead_finish(&op, buf, sizeof(buf), &len, buf, sizeof(buf), &len);
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_aead_finish on decrypt context rejected") != TEST_OK) {
        goto cleanup;
    }
    (void)psa_aead_abort(&op);

    /* encrypt_setup + psa_aead_verify must be rejected */
    op = psa_aead_operation_init();
    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(direction mismatch)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_aead_verify(&op, buf, sizeof(buf), &len, tag, sizeof(tag));
    if (check_true(st == PSA_ERROR_BAD_STATE,
                   "psa_aead_verify on encrypt context rejected") != TEST_OK) {
        goto cleanup;
    }
    (void)psa_aead_abort(&op);

    ret = TEST_OK;

cleanup:
    (void)psa_aead_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_aead_gcm_rejects_short_tags(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_OK;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs,
                          PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                              PSA_ALG_GCM, 1));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM short tag policy)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id,
                                PSA_ALG_AEAD_WITH_SHORTENED_TAG(
                                    PSA_ALG_GCM, 1));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_encrypt_setup rejects 1-byte GCM tag") != TEST_OK) {
        ret = TEST_FAIL;
    }

    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM short tag policy)") != TEST_OK) {
        return TEST_FAIL;
    }

    return ret;
}

/* F-4096: PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG is a wildcard policy
 * algorithm and must be rejected by operation setup with
 * PSA_ERROR_INVALID_ARGUMENT, not accepted as a concrete tag length. */
static int test_aead_rejects_wildcard_alg(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_algorithm_t wildcard = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
        PSA_ALG_GCM, 8);
    psa_status_t st;
    int ret = TEST_OK;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, wildcard);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM wildcard policy)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id, wildcard);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_encrypt_setup rejects wildcard alg") != TEST_OK) {
        ret = TEST_FAIL;
    }
    psa_aead_abort(&op);

    st = psa_aead_decrypt_setup(&op, key_id, wildcard);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_decrypt_setup rejects wildcard alg") != TEST_OK) {
        ret = TEST_FAIL;
    }
    psa_aead_abort(&op);

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM wildcard policy)") != TEST_OK) {
        return TEST_FAIL;
    }

    return ret;
}

static int test_aead_gcm_rejects_short_nonce(void)
{
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t short_nonce[11] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM short nonce)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(GCM short nonce)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_aead_set_nonce(&op, short_nonce, sizeof(short_nonce));
    if (check_true(st == PSA_ERROR_NOT_SUPPORTED,
                   "psa_aead_set_nonce reports 11-byte GCM nonce unsupported")
            != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_aead_abort(&op);
    psa_reset_key_attributes(&attrs);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_chacha20_poly1305_rejects_aes_key(void)
{
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t plaintext[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint8_t out[sizeof(plaintext) + 16];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    /*
     * Import a valid AES AEAD key first, then prove that the ChaCha20-Poly1305
     * path rejects it when the operation algorithm does not match the key type.
     */
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES for GCM)") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                          nonce, sizeof(nonce),
                          NULL, 0,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_encrypt(AES key with ChaCha20) rejected") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES for GCM)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_gcm_ccm_reject_non_aes_key_type(void)
{
    static const uint8_t key[32] = {
        0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
        0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
        0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
        0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
    };
    static const uint8_t nonce[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b
    };
    static const uint8_t plaintext[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint8_t out[sizeof(plaintext) + 16];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(ChaCha20 for GCM/CCM mismatch)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          NULL, 0,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_encrypt(ChaCha20 key with GCM) rejected") != TEST_OK) {
        goto cleanup;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_CCM,
                          nonce, sizeof(nonce),
                          NULL, 0,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_encrypt(ChaCha20 key with CCM) rejected") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return ret;
}

static int test_chacha20_import_rejects_invalid_key_size(void)
{
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_STREAM_CIPHER);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    psa_reset_key_attributes(&attrs);

    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_import_key rejects invalid ChaCha20 key size") != TEST_OK) {
        if (key_id != 0) {
            (void)psa_destroy_key(key_id);
        }
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_chacha20_poly1305_multipart_finish_split_buffers(void)
{
    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47
    };
    static const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };
    static const uint8_t plaintext[16] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c
    };
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];
    uint8_t combined[sizeof(plaintext) + sizeof(tag)];
    uint8_t update_out[sizeof(plaintext)];
    size_t ciphertext_len = 0;
    size_t tag_len = 0;
    size_t combined_len = 0;
    size_t update_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    int ret = TEST_OK;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(ChaCha20 multipart)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_CHACHA20_POLY1305);
    if (check_status(st, "psa_aead_encrypt_setup(ChaCha20 multipart)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(ChaCha20 multipart)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update_ad(&op, aad, sizeof(aad));
    if (check_status(st, "psa_aead_update_ad(ChaCha20 multipart)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    st = psa_aead_update(&op, plaintext, sizeof(plaintext),
                         update_out, sizeof(update_out), &update_len);
    if (check_status(st, "psa_aead_update(ChaCha20 multipart)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(update_len == 0,
                   "psa_aead_update(ChaCha20 multipart) length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_finish(&op, ciphertext, sizeof(ciphertext), &ciphertext_len,
                         tag, sizeof(tag), &tag_len);
    if (check_status(st, "psa_aead_finish(ChaCha20 split buffers)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(ciphertext_len == sizeof(ciphertext),
                   "psa_aead_finish(ChaCha20 ciphertext length)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(tag_len == sizeof(tag),
                   "psa_aead_finish(ChaCha20 tag length)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                          nonce, sizeof(nonce),
                          aad, sizeof(aad),
                          plaintext, sizeof(plaintext),
                          combined, sizeof(combined), &combined_len);
    if (check_status(st, "psa_aead_encrypt(ChaCha20 reference)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_true(combined_len == sizeof(combined),
                   "psa_aead_encrypt(ChaCha20 reference length)") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_buf_eq("psa_aead_finish(ChaCha20 ciphertext matches reference)",
                     ciphertext, combined, sizeof(ciphertext)) != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }
    if (check_buf_eq("psa_aead_finish(ChaCha20 tag matches reference)",
                     tag, combined + sizeof(ciphertext), sizeof(tag)) != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ChaCha20 multipart)") != TEST_OK) {
        return TEST_FAIL;
    }
    return ret;
}

static int test_asym_ecc(void)
{
    static const uint8_t msg[] = "psa ecc sign";
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    uint8_t sig[128];
    size_t sig_len = 0;
    uint8_t pub[128];
    size_t pub_len = 0;
    psa_key_id_t sign_key = 0;
    psa_key_id_t dh_key1 = 0;
    psa_key_id_t dh_key2 = 0;
    uint8_t dh_pub1[128];
    uint8_t dh_pub2[128];
    size_t dh_pub1_len = 0;
    size_t dh_pub2_len = 0;
    uint8_t dh_out1[128];
    uint8_t dh_out2[128];
    size_t dh_out1_len = 0;
    size_t dh_out2_len = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("FAIL: wc_InitSha256 (ecc) (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_Sha256Update(&sha, msg, (word32)sizeof(msg) - 1);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &sign_key);
    if (check_status(st, "psa_generate_key(ECDSA)") != TEST_OK) return TEST_FAIL;

    st = psa_sign_hash(sign_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash") != TEST_OK) return TEST_FAIL;

    st = psa_verify_hash(sign_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                         hash, sizeof(hash), sig, sig_len);
    if (check_status(st, "psa_verify_hash") != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(sign_key, pub, sizeof(pub), &pub_len);
    if (check_status(st, "psa_export_public_key") != TEST_OK) return TEST_FAIL;
    if (check_true(pub_len > 0, "psa_export_public_key length") != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(sign_key);
    if (check_status(st, "psa_destroy_key(ECDSA)") != TEST_OK) return TEST_FAIL;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &dh_key1);
    if (check_status(st, "psa_generate_key(ECDH1)") != TEST_OK) return TEST_FAIL;
    st = psa_generate_key(&attrs, &dh_key2);
    if (check_status(st, "psa_generate_key(ECDH2)") != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(dh_key1, dh_pub1, sizeof(dh_pub1), &dh_pub1_len);
    if (check_status(st, "psa_export_public_key(ECDH1)") != TEST_OK) return TEST_FAIL;
    st = psa_export_public_key(dh_key2, dh_pub2, sizeof(dh_pub2), &dh_pub2_len);
    if (check_status(st, "psa_export_public_key(ECDH2)") != TEST_OK) return TEST_FAIL;

    st = psa_raw_key_agreement(PSA_ALG_ECDH, dh_key1, dh_pub2, dh_pub2_len,
                               dh_out1, sizeof(dh_out1), &dh_out1_len);
    if (check_status(st, "psa_raw_key_agreement(1)") != TEST_OK) return TEST_FAIL;
    st = psa_raw_key_agreement(PSA_ALG_ECDH, dh_key2, dh_pub1, dh_pub1_len,
                               dh_out2, sizeof(dh_out2), &dh_out2_len);
    if (check_status(st, "psa_raw_key_agreement(2)") != TEST_OK) return TEST_FAIL;

    if (check_true(dh_out1_len == dh_out2_len, "psa_raw_key_agreement length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_raw_key_agreement", dh_out1, dh_out2, dh_out1_len) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(dh_key1);
    if (check_status(st, "psa_destroy_key(ECDH1)") != TEST_OK) return TEST_FAIL;
    st = psa_destroy_key(dh_key2);
    if (check_status(st, "psa_destroy_key(ECDH2)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

/* F-3176: exercise high-level psa_key_agreement validation and dispatch. */
static int test_psa_key_agreement(void)
{
    uint8_t peer_pub[128];
    uint8_t exported[32];
    size_t peer_pub_len = 0;
    size_t exported_len = 0;
    psa_key_id_t private_key = PSA_KEY_ID_NULL;
    psa_key_id_t peer_key = PSA_KEY_ID_NULL;
    psa_key_id_t agreed_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t out_attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &private_key);
    if (check_status(st, "psa_generate_key(psa_key_agreement private)") != TEST_OK)
        return TEST_FAIL;
    st = psa_generate_key(&attrs, &peer_key);
    if (check_status(st, "psa_generate_key(psa_key_agreement peer)") != TEST_OK)
        goto cleanup;

    st = psa_export_public_key(peer_key, peer_pub, sizeof(peer_pub), &peer_pub_len);
    if (check_status(st, "psa_export_public_key(psa_key_agreement peer)") != TEST_OK)
        goto cleanup;

    psa_set_key_type(&out_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&out_attrs, 256);
    psa_set_key_usage_flags(&out_attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&out_attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    st = psa_key_agreement(private_key, peer_pub, peer_pub_len, PSA_ALG_ECDH,
                           &out_attrs, &agreed_key);
    if (check_status(st, "psa_key_agreement raw ECDH to DERIVE key") != TEST_OK)
        goto cleanup;
    st = psa_destroy_key(agreed_key);
    if (check_status(st, "psa_destroy_key(raw agreement output)") != TEST_OK)
        goto cleanup;
    agreed_key = PSA_KEY_ID_NULL;

    psa_reset_key_attributes(&out_attrs);
    psa_set_key_type(&out_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&out_attrs, 256);
    psa_set_key_usage_flags(&out_attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&out_attrs, PSA_ALG_CTR);

    st = psa_key_agreement(private_key, peer_pub, peer_pub_len, PSA_ALG_ECDH,
                           &out_attrs, &agreed_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_agreement rejects raw ECDH to AES key") != TEST_OK)
        goto cleanup;
    if (check_true(agreed_key == PSA_KEY_ID_NULL,
                   "psa_key_agreement leaves key null for AES output") != TEST_OK)
        goto cleanup;

    st = psa_key_agreement(private_key, peer_pub, peer_pub_len, PSA_ALG_SHA_256,
                           &out_attrs, &agreed_key);
    if (check_true(st == PSA_ERROR_NOT_SUPPORTED,
                   "psa_key_agreement rejects non-key-agreement algorithm") != TEST_OK)
        goto cleanup;
    if (check_true(agreed_key == PSA_KEY_ID_NULL,
                   "psa_key_agreement leaves key null for non-KA algorithm") != TEST_OK)
        goto cleanup;

    psa_reset_key_attributes(&out_attrs);
    psa_set_key_type(&out_attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&out_attrs, 128);
    psa_set_key_usage_flags(&out_attrs, PSA_KEY_USAGE_EXPORT);

    st = psa_key_agreement(private_key, peer_pub, peer_pub_len,
                           PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH,
                                                 PSA_ALG_HKDF(PSA_ALG_SHA_256)),
                           &out_attrs, &agreed_key);
    if (check_status(st, "psa_key_agreement ECDH+HKDF to RAW_DATA key") != TEST_OK)
        goto cleanup;

    st = psa_export_key(agreed_key, exported, sizeof(exported), &exported_len);
    if (check_status(st, "psa_export_key(ECDH+HKDF output)") != TEST_OK)
        goto cleanup;
    if (check_true(exported_len == 16,
                   "psa_key_agreement ECDH+HKDF output length") != TEST_OK)
        goto cleanup;

    st = psa_destroy_key(agreed_key);
    if (check_status(st, "psa_destroy_key(KDF agreement output)") != TEST_OK)
        goto cleanup;
    agreed_key = PSA_KEY_ID_NULL;

    st = psa_destroy_key(peer_key);
    if (check_status(st, "psa_destroy_key(psa_key_agreement peer)") != TEST_OK)
        goto cleanup;
    peer_key = PSA_KEY_ID_NULL;
    st = psa_destroy_key(private_key);
    if (check_status(st, "psa_destroy_key(psa_key_agreement private)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;

cleanup:
    if (agreed_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(agreed_key);
    }
    if (peer_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(peer_key);
    }
    if (private_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(private_key);
    }
    return TEST_FAIL;
}

static int test_asym_algorithm_mismatch_policy(void)
{
    static const uint8_t msg[] = "wolfpsa asym mismatch";
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    uint8_t peer_pub[100];
    uint8_t secret[100];
    uint8_t sig[80];
    size_t peer_pub_len = 0;
    size_t secret_len = 0;
    size_t sig_len = 0;
    psa_key_id_t ecdsa_key = PSA_KEY_ID_NULL;
    psa_key_id_t ecdh_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("FAIL: wc_InitSha256 (asym mismatch) (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_Sha256Update(&sha, msg, (word32)sizeof(msg) - 1u);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &ecdsa_key);
    if (check_status(st, "psa_generate_key(ECDSA mismatch)") != TEST_OK) {
        goto cleanup;
    }

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &ecdh_key);
    if (check_status(st, "psa_generate_key(ECDH mismatch)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_export_public_key(ecdh_key, peer_pub, sizeof(peer_pub), &peer_pub_len);
    if (check_status(st, "psa_export_public_key(ECDH mismatch peer)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_raw_key_agreement(PSA_ALG_ECDH, ecdsa_key, peer_pub, peer_pub_len,
                               secret, sizeof(secret), &secret_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_raw_key_agreement rejects ECDSA key policy") != TEST_OK) {
        goto cleanup;
    }

    st = psa_sign_hash(ecdh_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_sign_hash rejects ECDH key policy") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (ecdh_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ecdh_key);
    }
    if (ecdsa_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ecdsa_key);
    }

    return ret;
}

/* F-5554: a key whose policy is the wildcard PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)
 * must authorize concrete hash-and-sign operations such as
 * PSA_ALG_ECDSA(PSA_ALG_SHA_256). */
static int test_asym_any_hash_policy(void)
{
    static const uint8_t msg[] = "wolfpsa any-hash policy";
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    uint8_t sig[80];
    size_t sig_len = 0;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("FAIL: wc_InitSha256 (any-hash policy) (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_Sha256Update(&sha, msg, (word32)sizeof(msg) - 1u);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));

    ret = TEST_FAIL;

    st = psa_generate_key(&attrs, &key_id);
    if (check_status(st, "psa_generate_key(ECDSA any-hash)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash(any-hash policy)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_verify_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                         hash, sizeof(hash), sig, sig_len);
    if (check_status(st, "psa_verify_hash(any-hash policy)") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(key_id);
    }

    return ret;
}

static int test_rsa_pkcs1v15_raw_sign_hash_roundtrip_large_input(void)
{
    uint8_t input[65];
    uint8_t sig[512];
    size_t sig_len = 0;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int result = TEST_FAIL;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i + 1u);
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, 2048);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_generate_key(RSA RAW roundtrip)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_sign_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
                       input, sizeof(input), sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash(RSA RAW 65-byte input)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_verify_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
                         input, sizeof(input), sig, sig_len);
    if (check_status(st, "psa_verify_hash(RSA RAW 65-byte input)") != TEST_OK) {
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    if (key_id != PSA_KEY_ID_NULL) {
        psa_status_t destroy_st = psa_destroy_key(key_id);
        if (result == TEST_OK &&
            check_status(destroy_st, "psa_destroy_key(RSA RAW roundtrip)") != TEST_OK) {
            result = TEST_FAIL;
        }
    }
    return result;
}

static int test_generate_key_rejects_public_key_type(void)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);

    st = psa_generate_key(&attrs, &key_id);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_generate_key rejects ECC public key type") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "psa_generate_key leaves key id null on public key type") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_import_key_rejects_wrapped_volatile_key_id(void)
{
    static const uint8_t aes_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const psa_key_id_t original_next_key_id = wolfpsa_test_get_next_key_id();
    const psa_key_id_t max_key_id = PSA_KEY_ID_VENDOR_MAX;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t first_key_id = PSA_KEY_ID_NULL;
    psa_key_id_t second_key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    wolfpsa_test_set_next_key_id(max_key_id);

    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &first_key_id);
    if (check_status(st, "psa_import_key(max volatile key id)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(first_key_id == max_key_id,
                   "psa_import_key uses max volatile key id before wrap") != TEST_OK) {
        goto cleanup;
    }

    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &second_key_id);
    if (check_true(st == PSA_ERROR_INSUFFICIENT_STORAGE,
                   "psa_import_key rejects wrapped volatile key id") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(second_key_id == PSA_KEY_ID_NULL,
                   "psa_import_key leaves key id null on volatile key id wrap") != TEST_OK) {
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    if (first_key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(first_key_id);
    }
    wolfpsa_test_set_next_key_id(original_next_key_id);
    return result;
}

static int test_import_key_auto_id_uses_vendor_range(void)
{
    static const uint8_t aes_key[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(auto-assigned volatile id)") != TEST_OK) {
        goto cleanup;
    }

    /* The PSA API reserves the user id range
     * [PSA_KEY_ID_USER_MIN, PSA_KEY_ID_USER_MAX] for caller-specified
     * persistent keys. Implementation-assigned (volatile) ids must come from
     * the vendor range so an auto-assigned id can never collide with - and
     * thus shadow on read or leave undestroyed on disk - a persistent key
     * that a caller created with the same numeric id. */
    if (check_true(key_id >= PSA_KEY_ID_VENDOR_MIN &&
                   key_id <= PSA_KEY_ID_VENDOR_MAX,
                   "auto-assigned volatile id avoids the user range") != TEST_OK) {
        printf("  got key id 0x%08lx\n", (unsigned long)key_id);
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    if (key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(key_id);
    }
    return result;
}

static int test_import_key_reports_volatile_store_invalid_argument(void)
{
    static const uint8_t key_data[1] = { 0 };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&attrs, 8);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_import_key(&attrs, key_data, 0, &key_id);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_import_key reports volatile-store invalid argument") != TEST_OK) {
        printf("  expected PSA_ERROR_INVALID_ARGUMENT, got %d\n", (int)st);
        return TEST_FAIL;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "psa_import_key leaves key id null on volatile-store failure") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_import_key_rejects_overflow_data_length(void)
{
    static const uint8_t key_data[1] = { 0x42 };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    /* A data_length close to SIZE_MAX wraps the internal buffer_size
     * computation to a tiny allocation; the subsequent copy of data_length
     * bytes would then overflow that allocation. The import must reject the
     * length before allocating or copying anything. */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&attrs, 8);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_import_key(&attrs, key_data, ~(size_t)0 - 4, &key_id);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_import_key rejects overflowing data_length") != TEST_OK) {
        printf("  expected PSA_ERROR_INVALID_ARGUMENT, got %d\n", (int)st);
        return TEST_FAIL;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "psa_import_key leaves key id null on overflow length") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_import_key_rejects_unknown_usage_bits(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);
    attrs.policy.usage = ~(psa_key_usage_t)0;

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_import_key rejects unknown usage bits") != TEST_OK) {
        printf("  expected PSA_ERROR_INVALID_ARGUMENT, got %d\n", (int)st);
        return TEST_FAIL;
    }
    if (check_true(key_id == PSA_KEY_ID_NULL,
                   "psa_import_key leaves key id null on usage failure") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_asym_rsa_oaep_usage_policy(void)
{
    static const uint8_t plaintext[] = "psa rsa oaep";
    uint8_t exported_pub[256];
    uint8_t ciphertext[256];
    uint8_t decrypted[sizeof(plaintext)];
    size_t exported_pub_len = 0;
    size_t ciphertext_len = 0;
    size_t decrypted_len = 0;
    psa_key_id_t decrypt_key = 0;
    psa_key_id_t encrypt_pub_key = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, 1024);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &decrypt_key);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_generate_key(RSA OAEP decrypt)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_export_public_key(decrypt_key, exported_pub, sizeof(exported_pub),
                               &exported_pub_len);
    if (check_status(st, "psa_export_public_key(RSA OAEP)") != TEST_OK) {
        goto cleanup;
    }

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, 1024);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, exported_pub, exported_pub_len, &encrypt_pub_key);
    if (check_status(st, "psa_import_key(RSA OAEP public)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_asymmetric_encrypt(encrypt_pub_key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
                                plaintext, sizeof(plaintext) - 1,
                                NULL, 0, ciphertext, sizeof(ciphertext), NULL);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_asymmetric_encrypt rejects NULL output_length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_asymmetric_encrypt(decrypt_key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
                                plaintext, sizeof(plaintext) - 1,
                                NULL, 0, ciphertext, sizeof(ciphertext),
                                &ciphertext_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_asymmetric_encrypt enforces ENCRYPT usage") != TEST_OK) {
        goto cleanup;
    }

    st = psa_asymmetric_encrypt(encrypt_pub_key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
                                plaintext, sizeof(plaintext) - 1,
                                NULL, 0, ciphertext, sizeof(ciphertext),
                                &ciphertext_len);
    if (check_status(st, "psa_asymmetric_encrypt(RSA OAEP)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_asymmetric_decrypt(decrypt_key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
                                ciphertext, ciphertext_len,
                                NULL, 0, decrypted, sizeof(decrypted), NULL);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_asymmetric_decrypt rejects NULL output_length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_asymmetric_decrypt(decrypt_key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
                                ciphertext, ciphertext_len,
                                NULL, 0, decrypted, sizeof(decrypted),
                                &decrypted_len);
    if (check_status(st, "psa_asymmetric_decrypt(RSA OAEP)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(decrypted_len == sizeof(plaintext) - 1,
                   "psa_asymmetric_decrypt(RSA OAEP) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_asymmetric_encrypt/decrypt(RSA OAEP)",
                     decrypted, plaintext, sizeof(plaintext) - 1) != TEST_OK) {
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    if (encrypt_pub_key != 0) {
        psa_status_t destroy_st = psa_destroy_key(encrypt_pub_key);
        if (result == TEST_OK &&
            check_status(destroy_st, "psa_destroy_key(RSA OAEP public)") != TEST_OK) {
            result = TEST_FAIL;
        }
    }
    if (decrypt_key != 0) {
        psa_status_t destroy_st = psa_destroy_key(decrypt_key);
        if (result == TEST_OK &&
            check_status(destroy_st, "psa_destroy_key(RSA OAEP decrypt)") != TEST_OK) {
            result = TEST_FAIL;
        }
    }

    return result;
}

static int test_ed25519_signature_length(void)
{
    static const uint8_t hash[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    static const uint8_t msg[] = "ed25519 message dispatch";
    uint8_t sig[128];
    /*
     * The original bug cast `size_t*` to `word32*`. On 64-bit builds that can
     * update only the low 32 bits, leaving the upper 32 bits stale. Seed
     * `sig_len` with the low half clear and the upper half all ones so a
     * truncated store becomes a large non-64 value instead of accidentally
     * looking correct.
     */
    size_t sig_len = ~((size_t)UINT32_MAX);
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 255);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
        PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ED25519PH);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_generate_key(ED25519)") != TEST_OK) return TEST_FAIL;

    st = psa_sign_hash(key_id, PSA_ALG_ED25519PH,
                       hash, sizeof(hash),
                       sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(sig_len == 64u, "psa_sign_hash(ED25519PH) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_verify_hash(key_id, PSA_ALG_ED25519PH,
                         hash, sizeof(hash), sig, sig_len);
    if (check_status(st, "psa_verify_hash(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    sig_len = sizeof(sig);
    st = psa_sign_message(key_id, PSA_ALG_ED25519PH,
                          msg, sizeof(msg) - 1,
                          sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_message(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(sig_len == 64u, "psa_sign_message(ED25519PH) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_verify_message(key_id, PSA_ALG_ED25519PH,
                            msg, sizeof(msg) - 1, sig, sig_len);
    if (check_status(st, "psa_verify_message(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ED25519)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

/*
 * HashEdDSA (Ed25519ph / Ed448ph) signs and verifies a fixed 64-byte prehash
 * (SHA-512 for Ed25519ph, the 64-byte SHAKE256 digest for Ed448ph). The PSA
 * API must reject any other hash length with PSA_ERROR_INVALID_ARGUMENT
 * instead of silently producing a non-RFC-8032 signature (F-4095).
 */
static int test_hash_eddsa_rejects_bad_hash_length(size_t bits,
                                                   psa_algorithm_t alg,
                                                   const char* gen_label)
{
    static const uint8_t short_hash[32] = { 0 };
    uint8_t sig[128];
    size_t sig_len = sizeof(sig);
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, gen_label) != TEST_OK) return TEST_FAIL;

    st = psa_sign_hash(key_id, alg, short_hash, sizeof(short_hash),
                       sig, sizeof(sig), &sig_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_sign_hash rejects non-64-byte prehash") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_verify_hash(key_id, alg, short_hash, sizeof(short_hash),
                         sig, sizeof(sig));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_verify_hash rejects non-64-byte prehash") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HashEdDSA bad hash len)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_ed25519_rejects_bad_hash_length(void)
{
    return test_hash_eddsa_rejects_bad_hash_length(
        255, PSA_ALG_ED25519PH, "psa_generate_key(ED25519 bad hash len)");
}

static int test_ed448_rejects_bad_hash_length(void)
{
    return test_hash_eddsa_rejects_bad_hash_length(
        448, PSA_ALG_ED448PH, "psa_generate_key(ED448 bad hash len)");
}

static int test_ed448_sign_message(void)
{
    static const uint8_t msg[] = "ed448 sign_message roundtrip";
    uint8_t sig[128];
    size_t sig_len = sizeof(sig);
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ED448PH);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_generate_key(ED448)") != TEST_OK) return TEST_FAIL;

    st = psa_sign_message(key_id, PSA_ALG_ED448PH,
                          msg, sizeof(msg) - 1,
                          sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_message(ED448PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(sig_len == 114u, "psa_sign_message(ED448PH) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_verify_message(key_id, PSA_ALG_ED448PH,
                            msg, sizeof(msg) - 1, sig, sig_len);
    if (check_status(st, "psa_verify_message(ED448PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ED448)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_twisted_edwards_export_public_key(size_t bits,
                                                  psa_algorithm_t alg,
                                                  size_t expected_pub_len,
                                                  const char* label)
{
    uint8_t pub[ED448_PUBLIC_KEY_BYTES];
    size_t pub_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, label) != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    if (check_status(st, "psa_export_public_key(Twisted Edwards)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(pub_len == expected_pub_len,
                   "psa_export_public_key(Twisted Edwards) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(Twisted Edwards)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_ed25519_export_public_key(void)
{
    return test_twisted_edwards_export_public_key(255, PSA_ALG_ED25519PH,
                                                  ED25519_PUBLIC_KEY_BYTES,
                                                  "psa_generate_key(ED25519 export)");
}

static int test_ed448_export_public_key(void)
{
    return test_twisted_edwards_export_public_key(448, PSA_ALG_ED448PH,
                                                  ED448_PUBLIC_KEY_BYTES,
                                                  "psa_generate_key(ED448 export)");
}

static int test_ecc_export_public_key(void)
{
    /* P-256 uncompressed: 0x04 || 32-byte X || 32-byte Y */
    uint8_t pub[65];
    size_t pub_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &key_id);
    if (check_status(st, "psa_generate_key(ECC export)") != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    if (check_status(st, "psa_export_public_key(ECC)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(pub_len == 65u, "psa_export_public_key(ECC) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ECC)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_x25519_key_usability(void)
{
    static const uint8_t alice_priv[X25519_KEY_BYTES] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    static const uint8_t bob_priv[X25519_KEY_BYTES] = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
    };
    uint8_t alice_pub[X25519_KEY_BYTES];
    uint8_t bob_pub[X25519_KEY_BYTES];
    uint8_t alice_secret[X25519_KEY_BYTES];
    uint8_t bob_secret[X25519_KEY_BYTES];
    uint8_t generated_pub[X25519_KEY_BYTES];
    size_t alice_pub_len = 0;
    size_t bob_pub_len = 0;
    size_t alice_secret_len = 0;
    size_t bob_secret_len = 0;
    size_t generated_pub_len = 0;
    psa_key_id_t alice_key = 0;
    psa_key_id_t bob_key = 0;
    psa_key_id_t generated_key = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attrs, 255);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_import_key(&attrs, alice_priv, sizeof(alice_priv), &alice_key);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_import_key(X25519 alice)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_import_key(&attrs, bob_priv, sizeof(bob_priv), &bob_key);
    if (check_status(st, "psa_import_key(X25519 bob)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        return TEST_FAIL;
    }

    st = psa_export_public_key(alice_key, alice_pub, sizeof(alice_pub),
                               &alice_pub_len);
    if (check_status(st, "psa_export_public_key(X25519 alice)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }
    st = psa_export_public_key(bob_key, bob_pub, sizeof(bob_pub), &bob_pub_len);
    if (check_status(st, "psa_export_public_key(X25519 bob)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }
    if (check_true(alice_pub_len == X25519_KEY_BYTES &&
                   bob_pub_len == X25519_KEY_BYTES,
                   "psa_export_public_key(X25519) length") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }

    st = psa_raw_key_agreement(PSA_ALG_ECDH, alice_key, bob_pub, bob_pub_len,
                               alice_secret, sizeof(alice_secret),
                               &alice_secret_len);
    if (check_status(st, "psa_raw_key_agreement(X25519 alice)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }
    st = psa_raw_key_agreement(PSA_ALG_ECDH, bob_key, alice_pub, alice_pub_len,
                               bob_secret, sizeof(bob_secret),
                               &bob_secret_len);
    if (check_status(st, "psa_raw_key_agreement(X25519 bob)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }
    if (check_true(alice_secret_len == X25519_KEY_BYTES &&
                   bob_secret_len == X25519_KEY_BYTES,
                   "psa_raw_key_agreement(X25519) length") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }
    if (check_buf_eq("psa_raw_key_agreement(X25519)", alice_secret,
                     bob_secret, X25519_KEY_BYTES) != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }

    st = psa_generate_key(&attrs, &generated_key);
    if (check_status(st, "psa_generate_key(X25519)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        return TEST_FAIL;
    }
    st = psa_export_public_key(generated_key, generated_pub,
                               sizeof(generated_pub), &generated_pub_len);
    if (check_status(st, "psa_export_public_key(generated X25519)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        (void)psa_destroy_key(generated_key);
        return TEST_FAIL;
    }
    if (check_true(generated_pub_len == X25519_KEY_BYTES,
                   "psa_export_public_key(generated X25519) length") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        (void)psa_destroy_key(bob_key);
        (void)psa_destroy_key(generated_key);
        return TEST_FAIL;
    }

    st = psa_destroy_key(alice_key);
    if (check_status(st, "psa_destroy_key(X25519 alice)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_destroy_key(bob_key);
    if (check_status(st, "psa_destroy_key(X25519 bob)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_destroy_key(generated_key);
    if (check_status(st, "psa_destroy_key(X25519 generated)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_x448_key_usability(void)
{
    static const uint8_t alice_priv[X448_KEY_BYTES] = {
        0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
        0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
        0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
        0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
        0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
        0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
        0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b
    };
    static const uint8_t bob_priv[X448_KEY_BYTES] = {
        0x1c, 0x30, 0x6a, 0x7a, 0xc2, 0xa0, 0xe2, 0xe0,
        0x99, 0x0b, 0x29, 0x44, 0x70, 0xcb, 0xa3, 0x39,
        0xe6, 0x45, 0x37, 0x72, 0xb0, 0x75, 0x81, 0x1d,
        0x8f, 0xad, 0x0d, 0x1d, 0x69, 0x27, 0xc1, 0x20,
        0xbb, 0x5e, 0xe8, 0x97, 0x2b, 0x0d, 0x3e, 0x21,
        0x37, 0x4c, 0x9c, 0x92, 0x1b, 0x09, 0xd1, 0xb0,
        0x36, 0x6f, 0x10, 0xb6, 0x51, 0x73, 0x99, 0x2d
    };
    static const uint8_t alice_pub_expected[X448_KEY_BYTES] = {
        0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
        0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
        0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
        0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
        0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
        0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
        0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0
    };
    static const uint8_t bob_pub_expected[X448_KEY_BYTES] = {
        0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5,
        0xbc, 0xfc, 0x0b, 0x59, 0x9b, 0x6f, 0xec, 0xcf,
        0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4,
        0xf3, 0x45, 0xb4, 0x30, 0x27, 0xd8, 0xb9, 0x72,
        0xfc, 0x3e, 0x34, 0xfb, 0x42, 0x32, 0xa1, 0x3c,
        0xa7, 0x06, 0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae,
        0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09
    };
    static const uint8_t shared_secret_expected[X448_KEY_BYTES] = {
        0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95,
        0xec, 0x1c, 0x16, 0xa9, 0x4a, 0x0f, 0x74, 0xd1,
        0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52,
        0x28, 0x1d, 0x28, 0x2b, 0xb6, 0x0c, 0x0b, 0x56,
        0xfd, 0x24, 0x64, 0xc3, 0x35, 0x54, 0x39, 0x36,
        0x52, 0x1c, 0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a,
        0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d
    };
    uint8_t alice_pub[X448_KEY_BYTES];
    uint8_t bob_pub[X448_KEY_BYTES];
    uint8_t alice_secret[X448_KEY_BYTES];
    uint8_t bob_secret[X448_KEY_BYTES];
    uint8_t generated_pub[X448_KEY_BYTES];
    size_t alice_pub_len = 0;
    size_t bob_pub_len = 0;
    size_t alice_secret_len = 0;
    size_t bob_secret_len = 0;
    size_t generated_pub_len = 0;
    psa_key_id_t alice_key = 0;
    psa_key_id_t bob_key = 0;
    psa_key_id_t generated_key = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_import_key(&attrs, alice_priv, sizeof(alice_priv), &alice_key);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_import_key(X448 alice)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_import_key(&attrs, bob_priv, sizeof(bob_priv), &bob_key);
    if (check_status(st, "psa_import_key(X448 bob)") != TEST_OK) {
        (void)psa_destroy_key(alice_key);
        return TEST_FAIL;
    }

    st = psa_export_public_key(alice_key, alice_pub, sizeof(alice_pub),
                               &alice_pub_len);
    result = check_status_or_skip(st, "psa_export_public_key(X448 alice)");
    if (result != TEST_OK) {
        goto cleanup;
    }
    st = psa_export_public_key(bob_key, bob_pub, sizeof(bob_pub), &bob_pub_len);
    result = check_status_or_skip(st, "psa_export_public_key(X448 bob)");
    if (result != TEST_OK) {
        goto cleanup;
    }
    if (check_true(alice_pub_len == X448_KEY_BYTES &&
                   bob_pub_len == X448_KEY_BYTES,
                   "psa_export_public_key(X448) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_export_public_key(X448 alice)", alice_pub,
                     alice_pub_expected, X448_KEY_BYTES) != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_export_public_key(X448 bob)", bob_pub,
                     bob_pub_expected, X448_KEY_BYTES) != TEST_OK) {
        goto cleanup;
    }

    st = psa_raw_key_agreement(PSA_ALG_ECDH, alice_key, bob_pub, bob_pub_len,
                               alice_secret, sizeof(alice_secret),
                               &alice_secret_len);
    result = check_status_or_skip(st, "psa_raw_key_agreement(X448 alice)");
    if (result != TEST_OK) {
        goto cleanup;
    }
    st = psa_raw_key_agreement(PSA_ALG_ECDH, bob_key, alice_pub, alice_pub_len,
                               bob_secret, sizeof(bob_secret),
                               &bob_secret_len);
    result = check_status_or_skip(st, "psa_raw_key_agreement(X448 bob)");
    if (result != TEST_OK) {
        goto cleanup;
    }
    if (check_true(alice_secret_len == X448_KEY_BYTES &&
                   bob_secret_len == X448_KEY_BYTES,
                   "psa_raw_key_agreement(X448) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_raw_key_agreement(X448)", alice_secret,
                     bob_secret, X448_KEY_BYTES) != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_raw_key_agreement(X448 expected)", alice_secret,
                     shared_secret_expected, X448_KEY_BYTES) != TEST_OK) {
        goto cleanup;
    }

    st = psa_generate_key(&attrs, &generated_key);
    result = check_status_or_skip(st, "psa_generate_key(X448)");
    if (result != TEST_OK) {
        goto cleanup;
    }
    st = psa_export_public_key(generated_key, generated_pub,
                               sizeof(generated_pub), &generated_pub_len);
    result = check_status_or_skip(st, "psa_export_public_key(generated X448)");
    if (result != TEST_OK) {
        goto cleanup;
    }
    if (check_true(generated_pub_len == X448_KEY_BYTES,
                   "psa_export_public_key(generated X448) length") != TEST_OK) {
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    st = psa_destroy_key(alice_key);
    if (alice_key != 0 && check_status(st, "psa_destroy_key(X448 alice)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_destroy_key(bob_key);
    if (bob_key != 0 && check_status(st, "psa_destroy_key(X448 bob)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_destroy_key(generated_key);
    if (generated_key != 0 &&
        check_status(st, "psa_destroy_key(X448 generated)") != TEST_OK) {
        return TEST_FAIL;
    }

    return result;
}

static int test_hash_verify_rejects_bad_signature(psa_key_type_t type,
                                                  size_t bits,
                                                  psa_algorithm_t alg,
                                                  const uint8_t* hash,
                                                  size_t hash_len,
                                                  size_t expected_sig_len,
                                                  const char* label)
{
    uint8_t sig[128];
    size_t sig_len = 0;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, label) != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_sign_hash(key_id, alg, hash, hash_len, sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash(bad signature setup)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(sig_len == expected_sig_len,
                   "psa_sign_hash(bad signature setup) length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_verify_hash(key_id, alg, hash, hash_len, sig, sig_len);
    if (check_status(st, "psa_verify_hash(valid signature setup)") != TEST_OK) {
        goto cleanup;
    }

    sig[0] ^= 0x01u;
    st = psa_verify_hash(key_id, alg, hash, hash_len, sig, sig_len);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_verify_hash rejects corrupted signature") != TEST_OK) {
        printf("  %s expected PSA_ERROR_INVALID_SIGNATURE, got %d\n",
               label, (int)st);
        goto cleanup;
    }

    result = TEST_OK;

cleanup:
    if (key_id != PSA_KEY_ID_NULL) {
        psa_status_t destroy_st = psa_destroy_key(key_id);
        if (result == TEST_OK &&
            check_status(destroy_st, "psa_destroy_key(bad signature test)") != TEST_OK) {
            result = TEST_FAIL;
        }
    }
    return result;
}

static int test_asym_verify_rejects_bad_signatures(void)
{
    static const uint8_t hash_sha256[WC_SHA256_DIGEST_SIZE] = {
        0x9f,0x86,0xd0,0x81,0x88,0x4c,0x7d,0x65,
        0x9a,0x2f,0xea,0xa0,0xc5,0x5a,0xd0,0x15,
        0xa3,0xbf,0x4f,0x1b,0x2b,0x0b,0x82,0x2c,
        0xd1,0x5d,0x6c,0x15,0xb0,0xf0,0x0a,0x08
    };
    static const uint8_t hash_ed25519[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    /* Ed448ph wc API requires the pre-hash input to be exactly
     * ED448_PREHASH_SIZE (64) bytes of SHAKE256 output. */
    static const uint8_t hash_ed448[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    int ed25519_result;
    int ed448_result;

    if (test_hash_verify_rejects_bad_signature(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            256, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
            hash_sha256, sizeof(hash_sha256), 64u,
            "psa_generate_key(ECDSA bad signature)") != TEST_OK) {
        return TEST_FAIL;
    }

    ed25519_result = test_hash_verify_rejects_bad_signature(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS),
        255, PSA_ALG_ED25519PH, hash_ed25519, sizeof(hash_ed25519), 64u,
        "psa_generate_key(ED25519 bad signature)");
    if (ed25519_result == TEST_FAIL) {
        return TEST_FAIL;
    }

    ed448_result = test_hash_verify_rejects_bad_signature(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS),
        448, PSA_ALG_ED448PH, hash_ed448, sizeof(hash_ed448), 114u,
        "psa_generate_key(ED448 bad signature)");
    if (ed448_result == TEST_FAIL) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_asym_requires_verify_usage(void)
{
    static const uint8_t hash[WC_SHA256_DIGEST_SIZE] = {
        0x9f,0x86,0xd0,0x81,0x88,0x4c,0x7d,0x65,
        0x9a,0x2f,0xea,0xa0,0xc5,0x5a,0xd0,0x15,
        0xa3,0xbf,0x4f,0x1b,0x2b,0x0b,0x82,0x2c,
        0x15,0xd6,0xa4,0x4f,0x00,0x5e,0x4b,0x49
    };
    uint8_t sig[128];
    size_t sig_len = 0;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_generate_key(ECDSA sign-only)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash(sign-only)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_verify_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                         hash, sizeof(hash), sig, sig_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_verify_hash requires verify usage") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != PSA_KEY_ID_NULL) {
        psa_status_t destroy_st = psa_destroy_key(key_id);
        if (ret == TEST_OK &&
            check_status(destroy_st, "psa_destroy_key(ECDSA sign-only)") != TEST_OK) {
            ret = TEST_FAIL;
        }
    }
    return ret;
}

/* Quarantined: the legacy psa_ml_dsa_* API and PSA_ML_DSA_PARAMETER_*
 * convention were removed by the PSA 1.4 upgrade. Spec-API ML-DSA coverage
 * lives in test/psa_mldsa_test.c. */
#if 0
static int test_ml_dsa_verify_rejects_bad_signature_for_parameter(
    psa_ml_dsa_parameter_t parameter, size_t expected_private_key_length,
    size_t expected_public_key_length, size_t expected_signature_length,
    const char* label)
{
#if defined(WOLFSSL_HAVE_MLDSA)
    static const uint8_t message[] = {
        0x46, 0x2f, 0x32, 0x38, 0x32, 0x33, 0x20, 0x4d,
        0x4c, 0x2d, 0x44, 0x53, 0x41, 0x20, 0x76, 0x65,
        0x72, 0x69, 0x66, 0x79
    };
    uint8_t private_key[MLDSA_MAX_KEY_SIZE];
    uint8_t public_key[MLDSA_MAX_PUB_KEY_SIZE];
    uint8_t signature[MLDSA_MAX_SIG_SIZE];
    size_t private_key_length = 0;
    size_t public_key_length = 0;
    size_t signature_length = 0;
    psa_status_t st;

    st = psa_ml_dsa_generate_key(parameter,
                                 private_key, sizeof(private_key),
                                 &private_key_length,
                                 public_key, sizeof(public_key),
                                 &public_key_length);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, label) != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(private_key_length == expected_private_key_length,
                   "psa_ml_dsa_generate_key private key length") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(public_key_length == expected_public_key_length,
                   "psa_ml_dsa_generate_key public key length") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_ml_dsa_sign(parameter,
                         private_key, private_key_length,
                         message, sizeof(message),
                         signature, sizeof(signature),
                         &signature_length);
    if (check_status(st, "psa_ml_dsa_sign") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(signature_length == expected_signature_length,
                   "psa_ml_dsa_sign signature length") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_ml_dsa_verify(parameter,
                           public_key, public_key_length,
                           message, sizeof(message),
                           signature, signature_length);
    if (check_status(st, "psa_ml_dsa_verify(valid)") != TEST_OK) {
        return TEST_FAIL;
    }

    signature[0] ^= 0x01u;
    st = psa_ml_dsa_verify(parameter,
                           public_key, public_key_length,
                           message, sizeof(message),
                           signature, signature_length);
    if (check_true(st == PSA_ERROR_INVALID_SIGNATURE,
                   "psa_ml_dsa_verify rejects corrupted signature") != TEST_OK) {
        printf("  %s expected PSA_ERROR_INVALID_SIGNATURE, got %d\n",
               label, (int)st);
        return TEST_FAIL;
    }

    return TEST_OK;
#else
    return TEST_SKIPPED;
#endif
}
#endif /* 0 */

static int test_ml_dsa_verify_rejects_bad_signature(void)
{
#if 0 /* legacy psa_ml_dsa_* API removed; see test/psa_mldsa_test.c */
    int ran = 0;
    int skipped = 0;
    int ret;

    ret = test_ml_dsa_verify_rejects_bad_signature_for_parameter(
        PSA_ML_DSA_PARAMETER_2, WC_MLDSA_44_KEY_SIZE,
        WC_MLDSA_44_PUB_KEY_SIZE, WC_MLDSA_44_SIG_SIZE,
        "psa_ml_dsa_generate_key(level2)");
    if (ret == TEST_FAIL) {
        return TEST_FAIL;
    }
    ran += (ret == TEST_OK);
    skipped += (ret == TEST_SKIPPED);
#ifndef WOLFSSL_NO_ML_DSA_65
    ret = test_ml_dsa_verify_rejects_bad_signature_for_parameter(
        PSA_ML_DSA_PARAMETER_3, WC_MLDSA_65_KEY_SIZE,
        WC_MLDSA_65_PUB_KEY_SIZE, WC_MLDSA_65_SIG_SIZE,
        "psa_ml_dsa_generate_key(level3)");
    if (ret == TEST_FAIL) {
        return TEST_FAIL;
    }
    ran += (ret == TEST_OK);
    skipped += (ret == TEST_SKIPPED);
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    ret = test_ml_dsa_verify_rejects_bad_signature_for_parameter(
        PSA_ML_DSA_PARAMETER_5, WC_MLDSA_87_KEY_SIZE,
        WC_MLDSA_87_PUB_KEY_SIZE, WC_MLDSA_87_SIG_SIZE,
        "psa_ml_dsa_generate_key(level5)");
    if (ret == TEST_FAIL) {
        return TEST_FAIL;
    }
    ran += (ret == TEST_OK);
    skipped += (ret == TEST_SKIPPED);
#endif

    if (ran == 0 && skipped > 0) {
        return TEST_SKIPPED;
    }
    return TEST_OK;
#else
    return TEST_SKIPPED;
#endif
}

static int test_mac_alg_mismatch(void)
{
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;

    /* Import HMAC key bound to SHA-256 */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC-SHA256 key)") != TEST_OK)
        return TEST_FAIL;

    /* Attempt HMAC-SHA-512 with a SHA-256 key -- must be rejected */
    st = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_512));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "mac_sign_setup rejects HMAC alg mismatch") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(mac mismatch)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_aead_alg_mismatch(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t nonce[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b
    };
    static const uint8_t pt[] = "hello";
    uint8_t ct[64];
    size_t ct_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    /* Import AES key bound to GCM */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM key)") != TEST_OK) return TEST_FAIL;

    /* Attempt CCM with a GCM key -- must be rejected */
    st = psa_aead_encrypt(key_id, PSA_ALG_CCM,
                          nonce, sizeof(nonce), NULL, 0,
                          pt, sizeof(pt) - 1,
                          ct, sizeof(ct), &ct_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "aead_encrypt rejects GCM key for CCM") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(aead mismatch)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_kdf_key_agreement_derive_check(void)
{
    psa_key_id_t key_with = 0, key_without = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t pub[128];
    size_t pub_len = 0;
    psa_status_t st;

    /* Generate ECC key WITH DERIVE */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
    st = psa_generate_key(&attrs, &key_with);
    if (check_status(st, "psa_generate_key(ECDH+DERIVE)") != TEST_OK)
        return TEST_FAIL;

    st = psa_export_public_key(key_with, pub, sizeof(pub), &pub_len);
    if (check_status(st, "export_pub(ECDH)") != TEST_OK) {
        (void)psa_destroy_key(key_with);
        return TEST_FAIL;
    }

    /* Test 1: key_agreement with DERIVE flag should succeed */
    st = psa_key_derivation_setup(&op,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
    if (check_status(st, "kdf_setup(ka)") != TEST_OK) goto fail;
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          key_with, pub, pub_len);
    if (check_status(st, "kdf_key_agreement with DERIVE") != TEST_OK) goto fail;
    psa_key_derivation_abort(&op);
    (void)psa_destroy_key(key_with);

    /* Generate ECC key WITHOUT DERIVE */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
    st = psa_generate_key(&attrs, &key_without);
    if (check_status(st, "psa_generate_key(ECDH no-DERIVE)") != TEST_OK)
        return TEST_FAIL;

    /* Test 2: key_agreement without DERIVE must fail */
    memset(&op, 0, sizeof(op));
    st = psa_key_derivation_setup(&op,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
    if (check_status(st, "kdf_setup(ka no-derive)") != TEST_OK) goto fail2;
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          key_without, pub, pub_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "kdf_key_agreement rejects key without DERIVE") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        goto fail2;
    }
    psa_key_derivation_abort(&op);
    (void)psa_destroy_key(key_without);
    return TEST_OK;

fail:
    psa_key_derivation_abort(&op);
    (void)psa_destroy_key(key_with);
    return TEST_FAIL;
fail2:
    psa_key_derivation_abort(&op);
    (void)psa_destroy_key(key_without);
    return TEST_FAIL;
}

static int test_kdf_input_key_checks(void)
{
    static const uint8_t ikm[16] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    psa_key_id_t derive_key = 0;
    psa_key_id_t no_derive_key = 0;
    psa_key_id_t aes_key = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st;

    /* Test 1: DERIVE key with correct usage -- should succeed */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, ikm, sizeof(ikm), &derive_key);
    if (check_status(st, "psa_import_key(DERIVE)") != TEST_OK) return TEST_FAIL;

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "kdf_setup(input_key test)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        ikm, sizeof(ikm));
    if (check_status(st, "kdf_input_salt") != TEST_OK) goto fail;
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                      derive_key);
    if (check_status(st, "kdf_input_key(DERIVE key)") != TEST_OK) goto fail;
    psa_key_derivation_abort(&op);

    /* Test 2: key lacking DERIVE usage -- must fail NOT_PERMITTED */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, ikm, sizeof(ikm), &no_derive_key);
    if (check_status(st, "psa_import_key(no DERIVE)") != TEST_OK) goto fail;

    memset(&op, 0, sizeof(op));
    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "kdf_setup(no-derive)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        ikm, sizeof(ikm));
    if (check_status(st, "kdf_input_salt(no-derive)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                      no_derive_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "kdf_input_key rejects key without DERIVE") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        goto fail;
    }
    psa_key_derivation_abort(&op);

    /* Test 3: AES key for SECRET step -- must fail INVALID_ARGUMENT */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, ikm, sizeof(ikm), &aes_key);
    if (check_status(st, "psa_import_key(AES for KDF)") != TEST_OK) goto fail;

    memset(&op, 0, sizeof(op));
    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "kdf_setup(aes)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        ikm, sizeof(ikm));
    if (check_status(st, "kdf_input_salt(aes)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                      aes_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "kdf_input_key rejects AES key for SECRET") != TEST_OK) {
        printf("  expected PSA_ERROR_INVALID_ARGUMENT, got %d\n", (int)st);
        goto fail;
    }
    psa_key_derivation_abort(&op);

    (void)psa_destroy_key(derive_key);
    (void)psa_destroy_key(no_derive_key);
    (void)psa_destroy_key(aes_key);
    return TEST_OK;

fail:
    psa_key_derivation_abort(&op);
    if (derive_key) (void)psa_destroy_key(derive_key);
    if (no_derive_key) (void)psa_destroy_key(no_derive_key);
    if (aes_key) (void)psa_destroy_key(aes_key);
    return TEST_FAIL;
}

static int test_asymmetric_alg_mismatch(void)
{
    uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
    uint8_t sig[128];
    size_t sig_len = 0;
    uint8_t pub[128];
    size_t pub_len = 0;
    uint8_t dh_out[128];
    size_t dh_out_len = 0;
    psa_key_id_t ecdsa_key = 0;
    psa_key_id_t ecdh_key = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    /* Generate ECDSA key */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &ecdsa_key);
    if (check_status(st, "psa_generate_key(ECDSA)") != TEST_OK) return TEST_FAIL;

    /* Get public key for use in raw_key_agreement */
    st = psa_export_public_key(ecdsa_key, pub, sizeof(pub), &pub_len);
    if (check_status(st, "psa_export_public_key(ECDSA)") != TEST_OK) {
        (void)psa_destroy_key(ecdsa_key);
        return TEST_FAIL;
    }

    /* Attempt ECDH with ECDSA key -- must be rejected */
    st = psa_raw_key_agreement(PSA_ALG_ECDH, ecdsa_key,
                               pub, pub_len,
                               dh_out, sizeof(dh_out), &dh_out_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "raw_key_agreement rejects ECDSA key") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(ecdsa_key);
        return TEST_FAIL;
    }

    (void)psa_destroy_key(ecdsa_key);

    /* Generate ECDH key */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &ecdh_key);
    if (check_status(st, "psa_generate_key(ECDH)") != TEST_OK) return TEST_FAIL;

    /* Attempt sign_hash with ECDH key -- must be rejected */
    st = psa_sign_hash(ecdh_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "sign_hash rejects ECDH key") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(ecdh_key);
        return TEST_FAIL;
    }

    st = psa_destroy_key(ecdh_key);
    if (check_status(st, "psa_destroy_key(ECDH)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_cipher_alg_mismatch(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;

    /* Import AES key bound to CBC_NO_PADDING */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(CBC key)") != TEST_OK) return TEST_FAIL;

    /* Attempt CTR with a CBC key -- must be rejected */
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "cipher_encrypt_setup rejects alg mismatch") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(cipher mismatch)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_alg_none_not_permitted(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
    psa_mac_operation_t mac_op = psa_mac_operation_init();
    psa_status_t st;

    /* Import AES key with PSA_ALG_NONE (no algorithm set) */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
        PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    /* Deliberately do NOT call psa_set_key_algorithm => PSA_ALG_NONE */

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES alg_none)") != TEST_OK)
        return TEST_FAIL;

    /* Cipher with ALG_NONE key must be rejected */
    st = psa_cipher_encrypt_setup(&cipher_op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "cipher_encrypt_setup rejects ALG_NONE key") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    /* AEAD with ALG_NONE key must be rejected */
    {
        uint8_t ct[32];
        size_t ct_len = 0;
        st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                              (const uint8_t *)"nonce123nonce", 12,
                              NULL, 0,
                              key, sizeof(key),
                              ct, sizeof(ct), &ct_len);
        if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                       "aead_encrypt rejects ALG_NONE key") != TEST_OK) {
            printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
            (void)psa_destroy_key(key_id);
            return TEST_FAIL;
        }
    }

    (void)psa_destroy_key(key_id);

    /* Import HMAC key with PSA_ALG_NONE */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    /* No algorithm set => PSA_ALG_NONE */

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC alg_none)") != TEST_OK)
        return TEST_FAIL;

    /* MAC with ALG_NONE key must be rejected */
    st = psa_mac_sign_setup(&mac_op, key_id,
                            PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "mac_sign_setup rejects ALG_NONE key") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED, got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(alg_none)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_kdf_output_bytes_consecutive(void)
{
    /* Property: concat(output_bytes(16), output_bytes(16)) == output_bytes(32) */
    static const uint8_t ikm[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t salt[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c
    };
    static const uint8_t info[] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    uint8_t split_a[16], split_b[16];
    uint8_t whole[32];
    psa_key_derivation_operation_t op1 = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_derivation_operation_t op2 = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    /* Import IKM as a DERIVE key */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, 8 * sizeof(ikm));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, ikm, sizeof(ikm), &key_id);
    if (check_status(st, "psa_import_key(HKDF ikm)") != TEST_OK) return TEST_FAIL;

    /* Operation 1: two split calls of 16 bytes each */
    st = psa_key_derivation_setup(&op1, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "kdf_setup(split)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op1, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt));
    if (check_status(st, "kdf_input_salt(split)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_key(&op1, PSA_KEY_DERIVATION_INPUT_SECRET,
                                      key_id);
    if (check_status(st, "kdf_input_key(split)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op1, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info));
    if (check_status(st, "kdf_input_info(split)") != TEST_OK) goto fail;
    st = psa_key_derivation_set_capacity(&op1, 32);
    if (check_status(st, "kdf_set_capacity(split)") != TEST_OK) goto fail;

    st = psa_key_derivation_output_bytes(&op1, split_a, 16);
    if (check_status(st, "kdf_output_bytes(split 1st 16)") != TEST_OK) goto fail;
    st = psa_key_derivation_output_bytes(&op1, split_b, 16);
    if (check_status(st, "kdf_output_bytes(split 2nd 16)") != TEST_OK) goto fail;
    psa_key_derivation_abort(&op1);

    /* Operation 2: single call of 32 bytes */
    st = psa_key_derivation_setup(&op2, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "kdf_setup(whole)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op2, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt));
    if (check_status(st, "kdf_input_salt(whole)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_key(&op2, PSA_KEY_DERIVATION_INPUT_SECRET,
                                      key_id);
    if (check_status(st, "kdf_input_key(whole)") != TEST_OK) goto fail;
    st = psa_key_derivation_input_bytes(&op2, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info));
    if (check_status(st, "kdf_input_info(whole)") != TEST_OK) goto fail;
    st = psa_key_derivation_set_capacity(&op2, 32);
    if (check_status(st, "kdf_set_capacity(whole)") != TEST_OK) goto fail;

    st = psa_key_derivation_output_bytes(&op2, whole, 32);
    if (check_status(st, "kdf_output_bytes(whole 32)") != TEST_OK) goto fail;
    psa_key_derivation_abort(&op2);

    /* Verify: split_a || split_b == whole */
    if (check_buf_eq("kdf consecutive first half", split_a, whole, 16) != TEST_OK) {
        printf("  split first 16 bytes differ from whole\n");
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_buf_eq("kdf consecutive second half", split_b, whole + 16, 16) != TEST_OK) {
        printf("  split second 16 bytes differ from whole\n");
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    (void)psa_destroy_key(key_id);
    return TEST_OK;

fail:
    psa_key_derivation_abort(&op1);
    psa_key_derivation_abort(&op2);
    (void)psa_destroy_key(key_id);
    return TEST_FAIL;
}

static int test_copy_key(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_id = 0, dst_id = 0;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_attributes_t got_attrs = psa_key_attributes_init();
    psa_status_t st;

    /* --- Test 1: copy with COPY flag succeeds --- */
    psa_set_key_type(&src_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&src_attrs, 128);
    psa_set_key_usage_flags(&src_attrs,
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&src_attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&src_attrs, key, sizeof(key), &src_id);
    if (check_status(st, "psa_import_key(copy src)") != TEST_OK) return TEST_FAIL;

    /* Destination attributes must match source type, algorithm, lifetime */
    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&dst_attrs, 128);
    psa_set_key_usage_flags(&dst_attrs,
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&dst_attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_copy_key(src_id, &dst_attrs, &dst_id);
    if (check_status(st, "psa_copy_key with COPY flag") != TEST_OK) {
        (void)psa_destroy_key(src_id);
        return TEST_FAIL;
    }

    /* --- Test 2: verify copied key attributes match source --- */
    st = psa_get_key_attributes(dst_id, &got_attrs);
    if (check_status(st, "psa_get_key_attributes(copied)") != TEST_OK) {
        (void)psa_destroy_key(src_id);
        (void)psa_destroy_key(dst_id);
        return TEST_FAIL;
    }
    if (check_true(psa_get_key_type(&got_attrs) == PSA_KEY_TYPE_AES,
                   "copied key type matches") != TEST_OK) {
        (void)psa_destroy_key(src_id);
        (void)psa_destroy_key(dst_id);
        return TEST_FAIL;
    }
    if (check_true(psa_get_key_bits(&got_attrs) == 128,
                   "copied key bits match") != TEST_OK) {
        (void)psa_destroy_key(src_id);
        (void)psa_destroy_key(dst_id);
        return TEST_FAIL;
    }

    /* Verify copied key data matches original */
    {
        uint8_t export_buf[16];
        size_t export_len = 0;
        st = psa_export_key(dst_id, export_buf, sizeof(export_buf), &export_len);
        if (check_status(st, "psa_export_key(copied)") != TEST_OK) {
            (void)psa_destroy_key(src_id);
            (void)psa_destroy_key(dst_id);
            return TEST_FAIL;
        }
        if (check_true(export_len == sizeof(key),
                       "exported copied key length") != TEST_OK) {
            (void)psa_destroy_key(src_id);
            (void)psa_destroy_key(dst_id);
            return TEST_FAIL;
        }
        if (check_buf_eq("exported copied key data",
                         export_buf, key, sizeof(key)) != TEST_OK) {
            (void)psa_destroy_key(src_id);
            (void)psa_destroy_key(dst_id);
            return TEST_FAIL;
        }
    }

    (void)psa_destroy_key(dst_id);
    (void)psa_destroy_key(src_id);

    /* --- Test 3: copy WITHOUT COPY flag must fail --- */
    src_attrs = psa_key_attributes_init();
    psa_set_key_type(&src_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&src_attrs, 128);
    psa_set_key_usage_flags(&src_attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&src_attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&src_attrs, key, sizeof(key), &src_id);
    if (check_status(st, "psa_import_key(copy no-copy src)") != TEST_OK)
        return TEST_FAIL;

    dst_attrs = psa_key_attributes_init();
    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&dst_attrs, 128);
    psa_set_key_usage_flags(&dst_attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&dst_attrs, PSA_ALG_CBC_NO_PADDING);

    dst_id = 0;
    st = psa_copy_key(src_id, &dst_attrs, &dst_id);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_copy_key rejects key without COPY flag") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED (-133), got %d\n", (int)st);
        (void)psa_destroy_key(src_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(src_id);
    if (check_status(st, "psa_destroy_key(no-copy src)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_mac_setup_truncated_too_short(void)
{
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_mac_operation_t op = psa_mac_operation_init();
    psa_status_t st;

    /* Import an HMAC key */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs,
                          PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 2));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC trunc-short)") != TEST_OK)
        return TEST_FAIL;

    /* Truncation length 2 < 4: must be rejected after wc_HmacSetKey ran */
    st = psa_mac_sign_setup(&op, key_id,
                            PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 2));
    if (check_true(st == PSA_ERROR_NOT_SUPPORTED,
                   "psa_mac_sign_setup rejects trunc < 4") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_SUPPORTED (-134), got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HMAC trunc-short)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_export_key_no_export_flag(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t export_buf[16];
    size_t export_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    /* Import a volatile AES key with ENCRYPT only -- no EXPORT flag */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES no-export)") != TEST_OK)
        return TEST_FAIL;

    /* psa_export_key must refuse because EXPORT usage is not set */
    st = psa_export_key(key_id, export_buf, sizeof(export_buf), &export_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_export_key rejects key without EXPORT flag") != TEST_OK) {
        printf("  expected PSA_ERROR_NOT_PERMITTED (-133), got %d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(no-export)") != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

static int test_kdf_null_capacity(void)
{
    size_t capacity = 0;
    psa_status_t st;

    st = psa_key_derivation_get_capacity(NULL, &capacity);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_get_capacity(NULL)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_default_capacity(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    size_t capacity = 0;
    psa_status_t st;

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF default capacity)") != TEST_OK) {
        goto fail;
    }
    st = psa_key_derivation_get_capacity(&op, &capacity);
    if (check_status(st, "psa_key_derivation_get_capacity(HKDF)") != TEST_OK) {
        goto fail;
    }
    if (check_true(capacity == 255u * WC_SHA256_DIGEST_SIZE,
                   "HKDF default capacity is 255 * hash length") != TEST_OK) {
        printf("  expected %u, got %lu\n",
               255u * WC_SHA256_DIGEST_SIZE, (unsigned long)capacity);
        goto fail;
    }
    (void)psa_key_derivation_abort(&op);

    op = psa_key_derivation_operation_init();
    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXTRACT default capacity)") != TEST_OK) {
        goto fail;
    }
    st = psa_key_derivation_get_capacity(&op, &capacity);
    if (check_status(st, "psa_key_derivation_get_capacity(HKDF_EXTRACT)") != TEST_OK) {
        goto fail;
    }
    if (check_true(capacity == WC_SHA256_DIGEST_SIZE,
                   "HKDF_EXTRACT default capacity is hash length") != TEST_OK) {
        printf("  expected %u, got %lu\n",
               WC_SHA256_DIGEST_SIZE, (unsigned long)capacity);
        goto fail;
    }
    (void)psa_key_derivation_abort(&op);

    op = psa_key_derivation_operation_init();
    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXPAND default capacity)") != TEST_OK) {
        goto fail;
    }
    st = psa_key_derivation_get_capacity(&op, &capacity);
    if (check_status(st, "psa_key_derivation_get_capacity(HKDF_EXPAND)") != TEST_OK) {
        goto fail;
    }
    if (check_true(capacity == 255u * WC_SHA256_DIGEST_SIZE,
                   "HKDF_EXPAND default capacity is 255 * hash length") != TEST_OK) {
        printf("  expected %u, got %lu\n",
               255u * WC_SHA256_DIGEST_SIZE, (unsigned long)capacity);
        goto fail;
    }
    (void)psa_key_derivation_abort(&op);

    return TEST_OK;

fail:
    (void)psa_key_derivation_abort(&op);
    return TEST_FAIL;
}

static int test_kdf_set_capacity_cannot_increase_remaining_capacity(void)
{
    static const uint8_t secret[] = "hkdf capacity secret";
    static const uint8_t info[] = "hkdf capacity info";
    uint8_t output[8];
    size_t capacity = 0;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF monotonic capacity)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF monotonic capacity)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF monotonic capacity)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_set_capacity(&op, 16u);
    if (check_status(st, "psa_key_derivation_set_capacity(initial HKDF monotonic capacity)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF monotonic capacity)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_get_capacity(&op, &capacity);
    if (check_status(st, "psa_key_derivation_get_capacity(HKDF remaining capacity)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(capacity == 8u,
                   "psa_key_derivation_get_capacity tracks remaining HKDF capacity") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_set_capacity(&op, 9u);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_set_capacity rejects increasing remaining capacity") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    return ret;
}

static int test_kdf_pbkdf2_zero_cost_rejected(void)
{
    static const uint8_t password[] = "pbkdf2-password";
    static const uint8_t salt[] = "pbkdf2-salt";
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 zero cost)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        password, sizeof(password) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PBKDF2 salt)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, 0);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_input_integer rejects zero PBKDF2 cost") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    return ret;
}

static int test_kdf_pbkdf2_large_cost_rejected(void)
{
    static const uint8_t password[] = "pbkdf2-password";
    static const uint8_t salt[] = "pbkdf2-salt";
    uint8_t output[16];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 large cost)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        password, sizeof(password) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PBKDF2 large cost password)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PBKDF2 large cost salt)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                          0x80000000ULL);
    if (check_status(st, "psa_key_derivation_input_integer(PBKDF2 large cost)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_output_bytes rejects PBKDF2 cost above INT_MAX") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    return ret;
}

static int test_kdf_input_key_policy(void)
{
    static const uint8_t secret[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t info[] = "kdf-input-key";
    uint8_t output[16];
    size_t output_len = 0;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t derive_key = 0;
    psa_key_id_t no_usage_key = 0;
    psa_key_id_t verify_only_key = 0;
    psa_key_id_t raw_key = 0;
    psa_key_id_t password_key = 0;
    psa_key_id_t wrong_pbkdf2_key = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &derive_key);
    if (check_status(st, "psa_import_key(KDF derive key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF input key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, derive_key);
    if (check_status(st, "psa_key_derivation_input_key(HKDF derive key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO input key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(input key)") != TEST_OK) {
        goto cleanup;
    }
    output_len = sizeof(output);
    if (check_true(output_len == sizeof(output),
                   "psa_key_derivation_output_bytes(input key) length") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF input key)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &no_usage_key);
    if (check_status(st, "psa_import_key(KDF no usage key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF no usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, no_usage_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_input_key rejects missing DERIVE usage") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF no usage)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_DERIVATION);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &verify_only_key);
    if (check_status(st, "psa_import_key(KDF verify-only key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF verify-only)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, verify_only_key);
    if (check_status(st, "psa_key_derivation_input_key(HKDF verify-only key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO verify-only)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_verify_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_verify_bytes(verify-only key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF verify-only)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &raw_key);
    if (check_status(st, "psa_import_key(KDF raw key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF raw key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, raw_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_input_key rejects non-DERIVE secret key type") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF raw key)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_PASSWORD);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &password_key);
    if (check_status(st, "psa_import_key(PBKDF2 password key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, password_key);
    if (check_status(st, "psa_key_derivation_input_key(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &wrong_pbkdf2_key);
    if (check_status(st, "psa_import_key(PBKDF2 wrong type key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 wrong type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                      wrong_pbkdf2_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_input_key rejects non-PASSWORD PBKDF2 key type") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    if (wrong_pbkdf2_key != 0) {
        (void)psa_destroy_key(wrong_pbkdf2_key);
    }
    if (password_key != 0) {
        (void)psa_destroy_key(password_key);
    }
    if (raw_key != 0) {
        (void)psa_destroy_key(raw_key);
    }
    if (verify_only_key != 0) {
        (void)psa_destroy_key(verify_only_key);
    }
    if (no_usage_key != 0) {
        (void)psa_destroy_key(no_usage_key);
    }
    if (derive_key != 0) {
        (void)psa_destroy_key(derive_key);
    }
    psa_reset_key_attributes(&attrs);
    return ret;
}

static int test_kdf_verify_key_policy(void)
{
    static const uint8_t hkdf_secret[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t hkdf_info[] = "kdf-verify-key";
    static const uint8_t pbkdf2_password[] = "password";
    static const uint8_t pbkdf2_salt[] = "salt";
    uint8_t hkdf_expected[16];
    uint8_t pbkdf2_expected[16];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t hkdf_verify_key = 0;
    psa_key_id_t hkdf_no_usage_key = 0;
    psa_key_id_t hkdf_wrong_type_key = 0;
    psa_key_id_t pbkdf2_verify_key = 0;
    psa_key_id_t pbkdf2_wrong_type_key = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        hkdf_secret, sizeof(hkdf_secret));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        hkdf_info, sizeof(hkdf_info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_output_bytes(&op, hkdf_expected, sizeof(hkdf_expected));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF verify expected)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_DERIVATION);
    st = psa_import_key(&attrs, hkdf_expected, sizeof(hkdf_expected), &hkdf_verify_key);
    if (check_status(st, "psa_import_key(HKDF verify key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        hkdf_secret, sizeof(hkdf_secret));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        hkdf_info, sizeof(hkdf_info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_verify_key(&op, hkdf_verify_key);
    if (check_status(st, "psa_key_derivation_verify_key(HKDF verify usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF verify key)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    st = psa_import_key(&attrs, hkdf_expected, sizeof(hkdf_expected), &hkdf_no_usage_key);
    if (check_status(st, "psa_import_key(HKDF no verify usage key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF no verify usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        hkdf_secret, sizeof(hkdf_secret));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET no verify usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        hkdf_info, sizeof(hkdf_info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO no verify usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_verify_key(&op, hkdf_no_usage_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_verify_key rejects missing VERIFY_DERIVATION usage") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF no verify usage)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_DERIVATION);
    st = psa_import_key(&attrs, hkdf_expected, sizeof(hkdf_expected), &hkdf_wrong_type_key);
    if (check_status(st, "psa_import_key(HKDF wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        hkdf_secret, sizeof(hkdf_secret));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        hkdf_info, sizeof(hkdf_info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_verify_key(&op, hkdf_wrong_type_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_verify_key rejects non-RAW_DATA HKDF expected key") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        pbkdf2_password, sizeof(pbkdf2_password) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PASSWORD verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        pbkdf2_salt, sizeof(pbkdf2_salt) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SALT verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, 2);
    if (check_status(st, "psa_key_derivation_input_integer(COST verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_output_bytes(&op, pbkdf2_expected, sizeof(pbkdf2_expected));
    if (check_status(st, "psa_key_derivation_output_bytes(PBKDF2 verify expected)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(PBKDF2 verify expected)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_PASSWORD_HASH);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_DERIVATION);
    st = psa_import_key(&attrs, pbkdf2_expected, sizeof(pbkdf2_expected), &pbkdf2_verify_key);
    if (check_status(st, "psa_import_key(PBKDF2 verify key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        pbkdf2_password, sizeof(pbkdf2_password) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PASSWORD verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        pbkdf2_salt, sizeof(pbkdf2_salt) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SALT verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, 2);
    if (check_status(st, "psa_key_derivation_input_integer(COST verify key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_verify_key(&op, pbkdf2_verify_key);
    if (check_status(st, "psa_key_derivation_verify_key(PBKDF2 password hash)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(PBKDF2 verify key)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_DERIVATION);
    st = psa_import_key(&attrs, pbkdf2_expected, sizeof(pbkdf2_expected),
                        &pbkdf2_wrong_type_key);
    if (check_status(st, "psa_import_key(PBKDF2 wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        pbkdf2_password, sizeof(pbkdf2_password) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(PASSWORD wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        pbkdf2_salt, sizeof(pbkdf2_salt) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SALT wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, 2);
    if (check_status(st, "psa_key_derivation_input_integer(COST wrong expected key type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_verify_key(&op, pbkdf2_wrong_type_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_verify_key rejects non-PASSWORD_HASH PBKDF2 expected key") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    if (pbkdf2_wrong_type_key != 0) {
        (void)psa_destroy_key(pbkdf2_wrong_type_key);
    }
    if (pbkdf2_verify_key != 0) {
        (void)psa_destroy_key(pbkdf2_verify_key);
    }
    if (hkdf_no_usage_key != 0) {
        (void)psa_destroy_key(hkdf_no_usage_key);
    }
    if (hkdf_wrong_type_key != 0) {
        (void)psa_destroy_key(hkdf_wrong_type_key);
    }
    if (hkdf_verify_key != 0) {
        (void)psa_destroy_key(hkdf_verify_key);
    }
    psa_reset_key_attributes(&attrs);
    return ret;
}

static int test_kdf_key_agreement_policy(void)
{
    uint8_t peer_pub[128];
    size_t peer_pub_len = 0;
    uint8_t good_pub[128];
    size_t good_pub_len = 0;
    uint8_t expected_secret[128];
    size_t expected_secret_len = 0;
    uint8_t derived_secret[128];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t good_key = 0;
    psa_key_id_t peer_key = 0;
    psa_key_id_t no_usage_key = 0;
    psa_key_id_t public_key = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &good_key);
    if (check_status(st, "psa_generate_key(KDF ECDH derive key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_generate_key(&attrs, &peer_key);
    if (check_status(st, "psa_generate_key(KDF ECDH peer key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_export_public_key(peer_key, peer_pub, sizeof(peer_pub), &peer_pub_len);
    if (check_status(st, "psa_export_public_key(KDF ECDH peer key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_export_public_key(good_key, good_pub, sizeof(good_pub), &good_pub_len);
    if (check_status(st, "psa_export_public_key(KDF ECDH derive key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_raw_key_agreement(PSA_ALG_ECDH, good_key, peer_pub, peer_pub_len,
                               expected_secret, sizeof(expected_secret),
                               &expected_secret_len);
    if (check_status(st, "psa_raw_key_agreement(KDF ECDH expected secret)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_ECDH);
    if (check_status(st, "psa_key_derivation_setup(raw ECDH)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          good_key, peer_pub, peer_pub_len);
    if (check_status(st, "psa_key_derivation_key_agreement(derive key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_output_bytes(&op, derived_secret, expected_secret_len);
    if (check_status(st, "psa_key_derivation_output_bytes(raw ECDH)") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_key_derivation_key_agreement matches raw ECDH",
                     derived_secret, expected_secret, expected_secret_len) != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(raw ECDH success)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &no_usage_key);
    if (check_status(st, "psa_generate_key(KDF ECDH no usage key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_ECDH);
    if (check_status(st, "psa_key_derivation_setup(raw ECDH no usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          no_usage_key, peer_pub, peer_pub_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_key_agreement rejects missing DERIVE usage") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(raw ECDH no usage)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_import_key(&attrs, good_pub, good_pub_len, &public_key);
    if (check_status(st, "psa_import_key(KDF ECDH public key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_ECDH);
    if (check_status(st, "psa_key_derivation_setup(raw ECDH public key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          public_key, peer_pub, peer_pub_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_key_agreement rejects public key input") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    if (public_key != 0) {
        (void)psa_destroy_key(public_key);
    }
    if (no_usage_key != 0) {
        (void)psa_destroy_key(no_usage_key);
    }
    if (peer_key != 0) {
        (void)psa_destroy_key(peer_key);
    }
    if (good_key != 0) {
        (void)psa_destroy_key(good_key);
    }
    psa_reset_key_attributes(&attrs);
    return ret;
}

/* F-5550: a key whose policy fixes a KDF (e.g. ECDH+HKDF) must not be usable
 * for raw key agreement or for a different KDF; only the base algorithm was
 * being checked, which let the KDF domain-separation barrier be bypassed. */
static int test_ka_kdf_policy_separation(void)
{
    uint8_t peer_pub[128];
    size_t peer_pub_len = 0;
    uint8_t secret[128];
    size_t secret_len = 0;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t out_attrs = psa_key_attributes_init();
    psa_key_id_t hkdf_key = 0;
    psa_key_id_t peer_key = 0;
    psa_key_id_t out_key = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    /* Private key restricted to ECDH followed by HKDF-SHA256. */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
    st = psa_generate_key(&attrs, &hkdf_key);
    if (check_status(st, "psa_generate_key(ECDH+HKDF policy)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_generate_key(&attrs, &peer_key);
    if (check_status(st, "psa_generate_key(ECDH+HKDF peer)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_export_public_key(peer_key, peer_pub, sizeof(peer_pub),
                               &peer_pub_len);
    if (check_status(st, "psa_export_public_key(ECDH+HKDF peer)") != TEST_OK) {
        goto cleanup;
    }

    /* One-shot raw agreement must be rejected: it would expose the bare
     * shared secret, bypassing the HKDF the policy requires. */
    st = psa_raw_key_agreement(PSA_ALG_ECDH, hkdf_key, peer_pub, peer_pub_len,
                               secret, sizeof(secret), &secret_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_raw_key_agreement rejects HKDF-only policy key")
            != TEST_OK) {
        goto cleanup;
    }

    /* Multipart raw agreement (raw ECDH operation) must likewise be rejected. */
    st = psa_key_derivation_setup(&op, PSA_ALG_ECDH);
    if (check_status(st, "psa_key_derivation_setup(raw ECDH)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          hkdf_key, peer_pub, peer_pub_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_key_agreement rejects HKDF-only policy "
                   "key for raw op") != TEST_OK) {
        goto cleanup;
    }
    (void)psa_key_derivation_abort(&op);
    op = psa_key_derivation_operation_init();

    /* One-shot agreement with a different KDF (HKDF-Extract) must be rejected. */
    psa_set_key_type(&out_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&out_attrs, 256);
    psa_set_key_usage_flags(&out_attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&out_attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_key_agreement(hkdf_key, peer_pub, peer_pub_len,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH,
                              PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256)),
        &out_attrs, &out_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_agreement rejects mismatched KDF") != TEST_OK) {
        goto cleanup;
    }

    /* Sanity: the policy's own algorithm (ECDH+HKDF-SHA256) is still allowed. */
    st = psa_key_derivation_setup(&op,
        PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
    if (check_status(st, "psa_key_derivation_setup(ECDH+HKDF)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_key_agreement(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          hkdf_key, peer_pub, peer_pub_len);
    if (check_status(st, "psa_key_derivation_key_agreement(ECDH+HKDF allowed)")
            != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    if (out_key != 0) {
        (void)psa_destroy_key(out_key);
    }
    if (peer_key != 0) {
        (void)psa_destroy_key(peer_key);
    }
    if (hkdf_key != 0) {
        (void)psa_destroy_key(hkdf_key);
    }
    psa_reset_key_attributes(&attrs);
    psa_reset_key_attributes(&out_attrs);
    return ret;
}

static int test_kdf_tls12_psk_to_ms_rfc4279_order(void)
{
    static const uint8_t psk[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5 };
    static const uint8_t other_secret[] = { 0x10, 0x20, 0x30 };
    static const uint8_t seed[] = "clienthello||serverhello";
    uint8_t premaster[2u + sizeof(other_secret) + 2u + sizeof(psk)];
    uint8_t expected[48];
    uint8_t output[sizeof(expected)];
    size_t seed_len = sizeof(seed) - 1u;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    premaster[0] = 0x00;
    premaster[1] = (uint8_t)sizeof(other_secret);
    memcpy(premaster + 2u, other_secret, sizeof(other_secret));
    premaster[2u + sizeof(other_secret)] = 0x00;
    premaster[3u + sizeof(other_secret)] = (uint8_t)sizeof(psk);
    memcpy(premaster + 4u + sizeof(other_secret), psk, sizeof(psk));

    ret = wc_PRF_TLS(expected, (word32)sizeof(expected),
                     premaster, (word32)sizeof(premaster),
                     (const byte*)"master secret", 13u,
                     seed, (word32)seed_len,
                     1, WC_HASH_TYPE_SHA256, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_PRF_TLS(TLS12_PSK_TO_MS reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(TLS12_PSK_TO_MS)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SEED,
                                        seed, seed_len);
    if (check_status(st, "psa_key_derivation_input_bytes(SEED)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op,
                                        PSA_KEY_DERIVATION_INPUT_OTHER_SECRET,
                                        other_secret, sizeof(other_secret));
    if (check_status(st, "psa_key_derivation_input_bytes(OTHER_SECRET)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        psk, sizeof(psk));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(TLS12_PSK_TO_MS)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(TLS12_PSK_TO_MS)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(TLS12_PSK_TO_MS RFC4279)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_tls12_psk_to_ms_plain_psk_optional_other_secret(void)
{
    static const uint8_t psk[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5 };
    static const uint8_t seed[] = "clienthello||serverhello";
    uint8_t premaster[2u + sizeof(psk) + 2u + sizeof(psk)];
    uint8_t expected[48];
    uint8_t output[sizeof(expected)];
    size_t seed_len = sizeof(seed) - 1u;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    premaster[0] = 0x00;
    premaster[1] = (uint8_t)sizeof(psk);
    memset(premaster + 2u, 0, sizeof(psk));
    premaster[2u + sizeof(psk)] = 0x00;
    premaster[3u + sizeof(psk)] = (uint8_t)sizeof(psk);
    memcpy(premaster + 4u + sizeof(psk), psk, sizeof(psk));

    ret = wc_PRF_TLS(expected, (word32)sizeof(expected),
                     premaster, (word32)sizeof(premaster),
                     (const byte*)"master secret", 13u,
                     seed, (word32)seed_len,
                     1, WC_HASH_TYPE_SHA256, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_PRF_TLS(TLS12_PSK_TO_MS plain PSK reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(TLS12_PSK_TO_MS plain PSK)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SEED,
                                        seed, seed_len);
    if (check_status(st, "psa_key_derivation_input_bytes(SEED plain PSK)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        psk, sizeof(psk));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET plain PSK)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(TLS12_PSK_TO_MS plain PSK)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(TLS12_PSK_TO_MS plain PSK)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(TLS12_PSK_TO_MS plain PSK RFC4279)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_extract_optional_salt(void)
{
    static const uint8_t secret[] = "hkdf extract secret";
    uint8_t expected[WC_SHA256_DIGEST_SIZE];
    uint8_t output[sizeof(expected)];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF_Extract(WC_HASH_TYPE_SHA256,
                          NULL, 0,
                          secret, (word32)(sizeof(secret) - 1u),
                          expected);
    if (ret != 0) {
        printf("FAIL: wc_HKDF_Extract(HKDF_EXTRACT optional salt reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXTRACT optional salt)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(SALT HKDF_EXTRACT optional salt)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF_EXTRACT optional salt)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF_EXTRACT optional salt)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF_EXTRACT optional salt)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF_EXTRACT optional salt)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_extract_prefix_output(void)
{
    static const uint8_t secret[] = "hkdf extract secret";
    uint8_t expected[WC_SHA256_DIGEST_SIZE];
    uint8_t output[16];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF_Extract(WC_HASH_TYPE_SHA256,
                          NULL, 0,
                          secret, (word32)(sizeof(secret) - 1u),
                          expected);
    if (ret != 0) {
        printf("FAIL: wc_HKDF_Extract(HKDF_EXTRACT prefix output reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXTRACT prefix output)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(SALT HKDF_EXTRACT prefix output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF_EXTRACT prefix output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_set_capacity(&op, sizeof(expected));
    if (check_status(st, "psa_key_derivation_set_capacity(HKDF_EXTRACT prefix output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF_EXTRACT prefix output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF_EXTRACT prefix output)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF_EXTRACT prefix output)",
                     output, expected, sizeof(output)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_expand_optional_info(void)
{
    static const uint8_t prk[WC_SHA256_DIGEST_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t expected[42];
    uint8_t output[sizeof(expected)];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF_Expand(WC_HASH_TYPE_SHA256,
                         prk, (word32)sizeof(prk),
                         NULL, 0,
                         expected, (word32)sizeof(expected));
    if (ret != 0) {
        printf("FAIL: wc_HKDF_Expand(HKDF_EXPAND optional info reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXPAND optional info)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        prk, sizeof(prk));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF_EXPAND optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF_EXPAND optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF_EXPAND optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF_EXPAND optional info)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF_EXPAND optional info)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_optional_info(void)
{
    static const uint8_t secret[] = "hkdf secret";
    uint8_t expected[42];
    uint8_t output[sizeof(expected)];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF(WC_HASH_TYPE_SHA256,
                  secret, (word32)(sizeof(secret) - 1u),
                  NULL, 0,
                  NULL, 0,
                  expected, (word32)sizeof(expected));
    if (ret != 0) {
        printf("FAIL: wc_HKDF(HKDF optional info reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF optional info)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF optional info)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF optional info)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_output_bytes_are_sequential(void)
{
    static const uint8_t secret[] = "hkdf sequential output secret";
    static const uint8_t info[] = "hkdf sequential output info";
    uint8_t expected[32];
    uint8_t output_part1[16];
    uint8_t output_part2[16];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF(WC_HASH_TYPE_SHA256,
                  secret, (word32)(sizeof(secret) - 1u),
                  NULL, 0,
                  info, (word32)(sizeof(info) - 1u),
                  expected, (word32)sizeof(expected));
    if (ret != 0) {
        printf("FAIL: wc_HKDF(sequential output reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF sequential output)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF sequential output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF sequential output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_set_capacity(&op, sizeof(expected));
    if (check_status(st, "psa_key_derivation_set_capacity(HKDF sequential output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output_part1, sizeof(output_part1));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF sequential output first)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output_part2, sizeof(output_part2));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF sequential output second)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF sequential output)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF sequential output first)",
                     output_part1, expected, sizeof(output_part1)) != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF sequential output second)",
                     output_part2, expected + sizeof(output_part1),
                     sizeof(output_part2)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int run_named_test(const char* name, test_fn_t fn)
{
    int ret;

    fprintf(stderr, "RUN %s\n", name);
    ret = fn();
    if (ret == TEST_OK) {
        tests_passed++;
    }
    else if (ret == TEST_SKIPPED) {
        tests_skipped++;
        fprintf(stderr, "SKIP %s\n", name);
    }
    return ret;
}

static int test_hash_clone_for_algorithm(psa_algorithm_t alg, const char* label)
{
    static const uint8_t msg1[] = "hash clone prefix";
    static const uint8_t msg2[] = " + suffix";
    uint8_t digest1[PSA_HASH_MAX_SIZE];
    uint8_t digest2[PSA_HASH_MAX_SIZE];
    size_t digest1_len = 0;
    size_t digest2_len = 0;
    psa_hash_operation_t source = psa_hash_operation_init();
    psa_hash_operation_t clone = psa_hash_operation_init();
    psa_status_t st;

    st = psa_hash_setup(&source, alg);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, label) != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_hash_update(&source, msg1, sizeof(msg1) - 1u);
    if (check_status(st, "psa_hash_update(source prefix)") != TEST_OK) {
        (void)psa_hash_abort(&source);
        return TEST_FAIL;
    }
    st = psa_hash_clone(&source, &clone);
    if (check_status(st, "psa_hash_clone") != TEST_OK) {
        (void)psa_hash_abort(&source);
        return TEST_FAIL;
    }
    st = psa_hash_update(&source, msg2, sizeof(msg2) - 1u);
    if (check_status(st, "psa_hash_update(source suffix)") != TEST_OK) {
        (void)psa_hash_abort(&source);
        (void)psa_hash_abort(&clone);
        return TEST_FAIL;
    }
    st = psa_hash_update(&clone, msg2, sizeof(msg2) - 1u);
    if (check_status(st, "psa_hash_update(clone suffix)") != TEST_OK) {
        (void)psa_hash_abort(&source);
        (void)psa_hash_abort(&clone);
        return TEST_FAIL;
    }
    st = psa_hash_finish(&source, digest1, sizeof(digest1), &digest1_len);
    if (check_status(st, "psa_hash_finish(source)") != TEST_OK) {
        (void)psa_hash_abort(&clone);
        return TEST_FAIL;
    }
    st = psa_hash_finish(&clone, digest2, sizeof(digest2), &digest2_len);
    if (check_status(st, "psa_hash_finish(clone)") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_true(digest1_len == digest2_len,
                   "psa_hash_clone digest lengths") != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_buf_eq("psa_hash_clone digest equality", digest1, digest2,
                     digest1_len) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_hash_clone(void)
{
    int ret;

    ret = test_hash_clone_for_algorithm(PSA_ALG_SHA_256,
                                        "psa_hash_setup(SHA-256 clone)");
    if (ret != TEST_OK) {
        return ret;
    }
#ifdef WOLFSSL_SHA3
    ret = test_hash_clone_for_algorithm(PSA_ALG_SHA3_256,
                                        "psa_hash_setup(SHA3-256 clone)");
    if (ret != TEST_OK) {
        return ret;
    }
#endif

    return TEST_OK;
}

/* F-2422: CCM_STAR_NO_TAG multi-part cipher must allow multiple update calls.
 * Before the fix, the second update call would return PSA_ERROR_BAD_STATE. */
static int test_ccm_star_no_tag_multipart(void)
{
    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_cipher_operation_t op_single;
    psa_cipher_operation_t op_multi;
    /* 128-bit AES key */
    const uint8_t key_data[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    /* 13-byte nonce required for CCM_STAR_NO_TAG */
    const uint8_t nonce[13] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC
    };
    /* 32-byte plaintext to split into two 16-byte parts */
    const uint8_t plaintext[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t ct_single[32];
    uint8_t ct_multi[32];
    size_t out_len = 0;
    size_t total_multi = 0;

    /* Import AES-128 key for CCM_STAR_NO_TAG encrypt */
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_algorithm(&attr, PSA_ALG_CCM_STAR_NO_TAG);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    st = psa_import_key(&attr, key_data, sizeof(key_data), &key);
    if (check_status(st, "import key for CCM_STAR_NO_TAG") != TEST_OK)
        return TEST_FAIL;

    /* --- Single-call: encrypt all 32 bytes at once --- */
    memset(&op_single, 0, sizeof(op_single));
    st = psa_cipher_encrypt_setup(&op_single, key, PSA_ALG_CCM_STAR_NO_TAG);
    if (check_status(st, "cipher encrypt setup (single)") != TEST_OK)
        goto cleanup;

    st = psa_cipher_set_iv(&op_single, nonce, sizeof(nonce));
    if (check_status(st, "cipher set iv (single)") != TEST_OK)
        goto cleanup;

    st = psa_cipher_update(&op_single, plaintext, 32, ct_single, sizeof(ct_single),
                           &out_len);
    if (check_status(st, "cipher update (single 32B)") != TEST_OK)
        goto cleanup;
    if (check_true(out_len == 32, "single update produced 32 bytes") != TEST_OK)
        goto cleanup;

    st = psa_cipher_abort(&op_single);
    if (check_status(st, "cipher abort (single)") != TEST_OK)
        goto cleanup;

    /* --- Multi-call: encrypt as two 16-byte updates --- */
    memset(&op_multi, 0, sizeof(op_multi));
    st = psa_cipher_encrypt_setup(&op_multi, key, PSA_ALG_CCM_STAR_NO_TAG);
    if (check_status(st, "cipher encrypt setup (multi)") != TEST_OK)
        goto cleanup;

    st = psa_cipher_set_iv(&op_multi, nonce, sizeof(nonce));
    if (check_status(st, "cipher set iv (multi)") != TEST_OK)
        goto cleanup;

    /* First 16 bytes */
    st = psa_cipher_update(&op_multi, plaintext, 16, ct_multi, sizeof(ct_multi),
                           &out_len);
    if (check_status(st, "cipher update (multi part 1)") != TEST_OK)
        goto cleanup;
    if (check_true(out_len == 16, "multi update part 1 produced 16 bytes") != TEST_OK)
        goto cleanup;
    total_multi += out_len;

    /* Second 16 bytes - this is the call that would fail before the fix */
    st = psa_cipher_update(&op_multi, plaintext + 16, 16,
                           ct_multi + total_multi,
                           sizeof(ct_multi) - total_multi, &out_len);
    if (check_status(st, "cipher update (multi part 2)") != TEST_OK)
        goto cleanup;
    if (check_true(out_len == 16, "multi update part 2 produced 16 bytes") != TEST_OK)
        goto cleanup;
    total_multi += out_len;

    st = psa_cipher_abort(&op_multi);
    if (check_status(st, "cipher abort (multi)") != TEST_OK)
        goto cleanup;

    /* Verify: single-call and multi-call must produce identical ciphertext */
    if (check_true(total_multi == 32,
                   "multi total output is 32 bytes") != TEST_OK)
        goto cleanup;
    if (check_true(memcmp(ct_single, ct_multi, 32) == 0,
                   "single-call and multi-call ciphertext match") != TEST_OK)
        goto cleanup;

    psa_destroy_key(key);
    return TEST_OK;

cleanup:
    psa_cipher_abort(&op_single);
    psa_cipher_abort(&op_multi);
    psa_destroy_key(key);
    return TEST_FAIL;
}

/* F/3426: OFB decrypt setup must retain the forward AES key schedule.
 * Before the fix, decrypt setup keyed OFB with AES_DECRYPTION, which broke
 * round-trip decryption on software AES builds. */
static int test_cipher_round_trip(psa_algorithm_t alg, const char* label)
{
    static const uint8_t key_data[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    static const uint8_t iv[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    size_t ciphertext_len = 0;
    size_t decrypted_len = 0;
    size_t finish_len = 0;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    st = psa_import_key(&attr, key_data, sizeof(key_data), &key);
    if (check_status(st, "import key for cipher round trip") != TEST_OK)
        return TEST_FAIL;

    st = psa_cipher_encrypt_setup(&op, key, alg);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        result = TEST_SKIPPED;
        goto cleanup;
    }
    if (check_status(st, label) != TEST_OK)
        goto cleanup;
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(enc)") != TEST_OK)
        goto cleanup;
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext), ciphertext,
                           sizeof(ciphertext), &ciphertext_len);
    if (check_status(st, "psa_cipher_update(enc)") != TEST_OK)
        goto cleanup;
    st = psa_cipher_finish(&op, ciphertext + ciphertext_len,
                           sizeof(ciphertext) - ciphertext_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(enc)") != TEST_OK)
        goto cleanup;
    ciphertext_len += finish_len;
    (void)psa_cipher_abort(&op);

    if (check_true(ciphertext_len == sizeof(plaintext),
                   "psa_cipher_encrypt length") != TEST_OK)
        goto cleanup;

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key, alg);
    if (check_status(st, "psa_cipher_decrypt_setup") != TEST_OK)
        goto cleanup;
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(dec)") != TEST_OK)
        goto cleanup;
    st = psa_cipher_update(&op, ciphertext, sizeof(ciphertext), decrypted,
                           sizeof(decrypted), &decrypted_len);
    if (check_status(st, "psa_cipher_update(dec)") != TEST_OK)
        goto cleanup;
    st = psa_cipher_finish(&op, decrypted + decrypted_len,
                           sizeof(decrypted) - decrypted_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(dec)") != TEST_OK)
        goto cleanup;
    decrypted_len += finish_len;

    if (check_true(decrypted_len == sizeof(plaintext),
                   "psa_cipher_decrypt length") != TEST_OK)
        goto cleanup;
    if (check_buf_eq("psa_cipher_decrypt", decrypted, plaintext,
                     sizeof(plaintext)) != TEST_OK)
        goto cleanup;

    result = TEST_OK;

cleanup:
    (void)psa_cipher_abort(&op);
    if (key != 0)
        (void)psa_destroy_key(key);
    return result;
}

static int test_ofb_round_trip(void)
{
    return test_cipher_round_trip(PSA_ALG_OFB, "psa_cipher_encrypt_setup(OFB)");
}

static int test_cfb_round_trip(void)
{
    return test_cipher_round_trip(PSA_ALG_CFB, "psa_cipher_encrypt_setup(CFB)");
}

/* F-2416: Cipher setup error paths must ForceZero ctx before freeing.
 * This test exercises the cipher abort path and a setup-then-abort
 * sequence to verify no crash occurs from the cleanup code. It also
 * verifies that a double-abort is safe (returns SUCCESS, not crash). */
static int test_cipher_setup_cleanup(void)
{
    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_cipher_operation_t op;
    const uint8_t key_data[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    /* Import AES-128 key */
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    st = psa_import_key(&attr, key_data, sizeof(key_data), &key);
    if (check_status(st, "import key for cipher cleanup test") != TEST_OK)
        return TEST_FAIL;

    /* Test 1: encrypt setup + immediate abort (exercises cleanup path) */
    memset(&op, 0, sizeof(op));
    st = psa_cipher_encrypt_setup(&op, key, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "cipher encrypt setup for abort") != TEST_OK) {
        psa_destroy_key(key);
        return TEST_FAIL;
    }
    st = psa_cipher_abort(&op);
    if (check_status(st, "cipher abort after encrypt setup") != TEST_OK) {
        psa_destroy_key(key);
        return TEST_FAIL;
    }

    /* Test 2: decrypt setup + immediate abort */
    memset(&op, 0, sizeof(op));
    st = psa_cipher_decrypt_setup(&op, key, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "cipher decrypt setup for abort") != TEST_OK) {
        psa_destroy_key(key);
        return TEST_FAIL;
    }
    st = psa_cipher_abort(&op);
    if (check_status(st, "cipher abort after decrypt setup") != TEST_OK) {
        psa_destroy_key(key);
        return TEST_FAIL;
    }

    /* Test 3: double abort must not crash */
    st = psa_cipher_abort(&op);
    if (check_status(st, "cipher double abort") != TEST_OK) {
        psa_destroy_key(key);
        return TEST_FAIL;
    }

    psa_destroy_key(key);
    return TEST_OK;
}

/* F-2423: HKDF-Extract must accept output_bytes smaller than hash digest.
 * Before the fix, requesting fewer bytes than the digest returned
 * PSA_ERROR_INVALID_ARGUMENT because of a strict equality check. */
static int test_hkdf_extract_truncated_output(void)
{
    static const uint8_t secret[] = "hkdf extract truncation test";
    static const uint8_t salt[] = "some salt";
    uint8_t full[WC_SHA256_DIGEST_SIZE];
    uint8_t truncated[16]; /* half the digest */
    psa_key_derivation_operation_t op;
    psa_status_t st;
    int ret;

    /* Compute the full extract as reference using wolfCrypt directly */
    ret = wc_HKDF_Extract(WC_HASH_TYPE_SHA256,
                          salt, (word32)(sizeof(salt) - 1u),
                          secret, (word32)(sizeof(secret) - 1u),
                          full);
    if (ret != 0) {
        printf("FAIL: wc_HKDF_Extract reference (%d)\n", ret);
        return TEST_FAIL;
    }

    /* Now request only 16 bytes through PSA API */
    memset(&op, 0, sizeof(op));
    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    if (check_status(st, "setup(HKDF_EXTRACT truncated)") != TEST_OK)
        return TEST_FAIL;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt) - 1u);
    if (check_status(st, "input salt(HKDF_EXTRACT truncated)") != TEST_OK) {
        psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "input secret(HKDF_EXTRACT truncated)") != TEST_OK) {
        psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }

    st = psa_key_derivation_output_bytes(&op, truncated, sizeof(truncated));
    if (check_status(st, "output_bytes 16(HKDF_EXTRACT truncated)") != TEST_OK) {
        psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }

    st = psa_key_derivation_abort(&op);
    if (check_status(st, "abort(HKDF_EXTRACT truncated)") != TEST_OK)
        return TEST_FAIL;

    /* The first 16 bytes must match the full extract */
    if (check_buf_eq("HKDF_EXTRACT truncated output matches prefix",
                     truncated, full, sizeof(truncated)) != TEST_OK)
        return TEST_FAIL;

    return TEST_OK;
}

int main(int argc, char** argv)
{
    psa_status_t st;
    const char* only = argc > 1 ? argv[1] : NULL;

    st = psa_crypto_init();
    if (check_status(st, "psa_crypto_init") != TEST_OK) return TEST_FAIL;

    if (only == NULL || strcmp(only, "random") == 0) {
        if (run_named_test("random", test_random) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hash") == 0) {
        if (run_named_test("hash", test_hash) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hash_compare") == 0) {
        if (run_named_test("hash_compare", test_hash_compare) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hash_error_state") == 0) {
        if (run_named_test("hash_error_state",
                           test_hash_error_aborts_operation) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "hash_clone") == 0) {
        if (run_named_test("hash_clone", test_hash_clone) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "hmac") == 0) {
        if (run_named_test("hmac", test_hmac) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "cmac") == 0) {
        if (run_named_test("cmac", test_cmac) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "mac_verify_finish_at_least_length") == 0) {
        if (run_named_test("mac_verify_finish_at_least_length",
                           test_mac_verify_finish_accepts_longer_at_least_length_mac) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "mac_error_state") == 0) {
        if (run_named_test("mac_error_state",
                           test_mac_error_aborts_operation) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "alg_none_policy") == 0) {
        if (run_named_test("alg_none_policy",
                           test_algorithm_none_rejects_key_usage) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "secondary_algorithm_not_supported") == 0) {
        if (run_named_test("secondary_algorithm_not_supported",
                           test_secondary_algorithm_is_not_supported) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_cbc") == 0) {
        if (run_named_test("cipher_cbc", test_cipher_cbc) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "cipher_generate_iv") == 0) {
        if (run_named_test("cipher_generate_iv", test_cipher_generate_iv) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "cipher_algorithm_mismatch") == 0) {
        if (run_named_test("cipher_algorithm_mismatch",
                           test_cipher_rejects_algorithm_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "mac_algorithm_mismatch") == 0) {
        if (run_named_test("mac_algorithm_mismatch",
                           test_mac_rejects_algorithm_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "export_requires_usage") == 0) {
        if (run_named_test("export_requires_usage",
                           test_export_key_requires_usage_flag) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "export_oversized_persistent_length") == 0) {
        if (run_named_test("export_oversized_persistent_length",
                           test_export_key_rejects_oversized_persistent_length) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "export_zeroizes_buffer_on_short_read") == 0) {
        if (run_named_test("export_zeroizes_buffer_on_short_read",
                           test_export_key_zeroizes_buffer_on_short_read) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_short_write_leaves_no_persistent_key") == 0) {
        if (run_named_test("import_key_short_write_leaves_no_persistent_key",
                           test_import_key_short_write_leaves_no_persistent_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_rejects_duplicate_persistent_id") == 0) {
        if (run_named_test("import_key_rejects_duplicate_persistent_id",
                           test_import_key_rejects_duplicate_persistent_id) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_success") == 0) {
        if (run_named_test("copy_key_success",
                           test_copy_key_copies_material_and_attributes) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_requires_usage") == 0) {
        if (run_named_test("copy_key_requires_usage",
                           test_copy_key_requires_copy_usage_flag) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_inherits_unspecified_type") == 0) {
        if (run_named_test("copy_key_inherits_unspecified_type",
                           test_copy_key_inherits_unspecified_type) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_persistent_inherits_unspecified_type") == 0) {
        if (run_named_test("copy_key_persistent_inherits_unspecified_type",
                           test_copy_key_persistent_inherits_unspecified_type) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_attribute_mismatch") == 0) {
        if (run_named_test("copy_key_attribute_mismatch",
                           test_copy_key_rejects_attribute_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_persistent_requires_usage") == 0) {
        if (run_named_test("copy_key_persistent_requires_usage",
                           test_copy_key_requires_copy_usage_flag_persistent) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_cbc_pkcs7_multipart") == 0) {
        if (run_named_test("cipher_cbc_pkcs7_multipart",
                           test_cipher_cbc_pkcs7_multipart_decrypt) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_cbc_pkcs7_small_output") == 0) {
        if (run_named_test("cipher_cbc_pkcs7_small_output",
                           test_cipher_cbc_pkcs7_decrypt_update_small_output) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_error_state") == 0) {
        if (run_named_test("cipher_error_state",
                           test_cipher_error_aborts_operation) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_ccm_star_no_tag_multipart") == 0) {
        if (run_named_test("cipher_ccm_star_no_tag_multipart",
                           test_cipher_ccm_star_no_tag_multipart) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_gcm") == 0) {
        if (run_named_test("aead_gcm", test_aead_gcm) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "aead_encrypt_buffer_too_small") == 0) {
        if (run_named_test("aead_encrypt_buffer_too_small",
                           test_aead_encrypt_buffer_too_small) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_rejects_corrupted_tag") == 0) {
        if (run_named_test("aead_rejects_corrupted_tag",
                           test_aead_rejects_corrupted_tag) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_generate_nonce") == 0) {
        if (run_named_test("aead_generate_nonce",
                           test_aead_generate_nonce) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_gcm_multipart_zero_length") == 0) {
        if (run_named_test("aead_gcm_multipart_zero_length",
                           test_aead_gcm_multipart_zero_length_inputs) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_multipart_length_overflow") == 0) {
        if (run_named_test("aead_multipart_length_overflow",
                           test_aead_multipart_length_overflow_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_set_lengths_twice") == 0) {
        if (run_named_test("aead_set_lengths_twice",
                           test_aead_set_lengths_twice_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_word32_overflow") == 0) {
        if (run_named_test("aead_word32_overflow",
                           test_aead_finish_verify_word32_overflow_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_policy_mismatch") == 0) {
        if (run_named_test("aead_policy_mismatch",
                           test_aead_policy_mismatch_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_requires_decrypt_usage") == 0) {
        if (run_named_test("aead_requires_decrypt_usage",
                           test_aead_requires_decrypt_usage) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_direction_mismatch") == 0) {
        if (run_named_test("aead_direction_mismatch",
                           test_aead_direction_mismatch_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_gcm_short_tag") == 0) {
        if (run_named_test("aead_gcm_short_tag",
                           test_aead_gcm_rejects_short_tags) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_gcm_short_nonce") == 0) {
        if (run_named_test("aead_gcm_short_nonce",
                           test_aead_gcm_rejects_short_nonce) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_wildcard_alg_rejected") == 0) {
        if (run_named_test("aead_wildcard_alg_rejected",
                           test_aead_rejects_wildcard_alg) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_gcm_ccm_non_aes_key") == 0) {
        if (run_named_test("aead_gcm_ccm_non_aes_key",
                           test_gcm_ccm_reject_non_aes_key_type) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "chacha20_aes_reject") == 0) {
        if (run_named_test("chacha20_aes_reject",
                           test_chacha20_poly1305_rejects_aes_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "chacha20_import_key_size") == 0) {
        if (run_named_test("chacha20_import_key_size",
                           test_chacha20_import_rejects_invalid_key_size) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "chacha20_multipart_split_buffers") == 0) {
        if (run_named_test("chacha20_multipart_split_buffers",
                           test_chacha20_poly1305_multipart_finish_split_buffers) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_ecc") == 0) {
        if (run_named_test("asym_ecc", test_asym_ecc) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "psa_key_agreement") == 0) {
        if (run_named_test("psa_key_agreement",
                           test_psa_key_agreement) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_algorithm_mismatch_policy") == 0) {
        if (run_named_test("asym_algorithm_mismatch_policy",
                           test_asym_algorithm_mismatch_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_any_hash_policy") == 0) {
        if (run_named_test("asym_any_hash_policy",
                           test_asym_any_hash_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "rsa_pkcs1v15_raw_roundtrip_large_input") == 0) {
        if (run_named_test("rsa_pkcs1v15_raw_roundtrip_large_input",
                           test_rsa_pkcs1v15_raw_sign_hash_roundtrip_large_input) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "generate_key_rejects_public_key_type") == 0) {
        if (run_named_test("generate_key_rejects_public_key_type",
                           test_generate_key_rejects_public_key_type) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_volatile_key_id_wrap") == 0) {
        if (run_named_test("import_key_volatile_key_id_wrap",
                           test_import_key_rejects_wrapped_volatile_key_id) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_auto_id_vendor_range") == 0) {
        if (run_named_test("import_key_auto_id_vendor_range",
                           test_import_key_auto_id_uses_vendor_range) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_volatile_store_invalid_argument") == 0) {
        if (run_named_test("import_key_volatile_store_invalid_argument",
                           test_import_key_reports_volatile_store_invalid_argument) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_overflow_data_length") == 0) {
        if (run_named_test("import_key_overflow_data_length",
                           test_import_key_rejects_overflow_data_length) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "import_key_unknown_usage_bits") == 0) {
        if (run_named_test("import_key_unknown_usage_bits",
                           test_import_key_rejects_unknown_usage_bits) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_rsa_oaep_policy") == 0) {
        if (run_named_test("asym_rsa_oaep_policy",
                           test_asym_rsa_oaep_usage_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed25519_sig_len") == 0) {
        if (run_named_test("ed25519_sig_len", test_ed25519_signature_length) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed25519_bad_hash_len") == 0) {
        if (run_named_test("ed25519_bad_hash_len",
                           test_ed25519_rejects_bad_hash_length) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed448_bad_hash_len") == 0) {
        if (run_named_test("ed448_bad_hash_len",
                           test_ed448_rejects_bad_hash_length) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed448_sign_message") == 0) {
        if (run_named_test("ed448_sign_message",
                           test_ed448_sign_message) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed25519_export_pub") == 0) {
        if (run_named_test("ed25519_export_pub", test_ed25519_export_public_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed448_export_pub") == 0) {
        if (run_named_test("ed448_export_pub", test_ed448_export_public_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ecc_export_pub") == 0) {
        if (run_named_test("ecc_export_pub", test_ecc_export_public_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "x25519_key_usability") == 0) {
        if (run_named_test("x25519_key_usability",
                           test_x25519_key_usability) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "x448_key_usability") == 0) {
        if (run_named_test("x448_key_usability",
                           test_x448_key_usability) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_verify_bad_signature") == 0) {
        if (run_named_test("asym_verify_bad_signature",
                           test_asym_verify_rejects_bad_signatures) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_requires_verify_usage") == 0) {
        if (run_named_test("asym_requires_verify_usage",
                           test_asym_requires_verify_usage) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ml_dsa_verify_bad_signature") == 0) {
        if (run_named_test("ml_dsa_verify_bad_signature",
                           test_ml_dsa_verify_rejects_bad_signature) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_null_capacity") == 0) {
        if (run_named_test("kdf_null_capacity", test_kdf_null_capacity) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_default_capacity") == 0) {
        if (run_named_test("kdf_hkdf_default_capacity",
                           test_kdf_hkdf_default_capacity) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_monotonic_capacity") == 0) {
        if (run_named_test("kdf_monotonic_capacity",
                           test_kdf_set_capacity_cannot_increase_remaining_capacity) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_pbkdf2_zero_cost") == 0) {
        if (run_named_test("kdf_pbkdf2_zero_cost",
                           test_kdf_pbkdf2_zero_cost_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_pbkdf2_large_cost") == 0) {
        if (run_named_test("kdf_pbkdf2_large_cost",
                           test_kdf_pbkdf2_large_cost_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_input_key_policy") == 0) {
        if (run_named_test("kdf_input_key_policy", test_kdf_input_key_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_verify_key_policy") == 0) {
        if (run_named_test("kdf_verify_key_policy", test_kdf_verify_key_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_key_agreement_policy") == 0) {
        if (run_named_test("kdf_key_agreement_policy",
                           test_kdf_key_agreement_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ka_kdf_policy_separation") == 0) {
        if (run_named_test("ka_kdf_policy_separation",
                           test_ka_kdf_policy_separation) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "export_key_no_export_flag") == 0) {
        if (run_named_test("export_key_no_export_flag",
                           test_export_key_no_export_flag) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "mac_setup_truncated_too_short") == 0) {
        if (run_named_test("mac_setup_truncated_too_short",
                           test_mac_setup_truncated_too_short) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key") == 0) {
        if (run_named_test("copy_key", test_copy_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_output_bytes_consecutive") == 0) {
        if (run_named_test("kdf_output_bytes_consecutive",
                           test_kdf_output_bytes_consecutive) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "alg_none_not_permitted") == 0) {
        if (run_named_test("alg_none_not_permitted",
                           test_alg_none_not_permitted) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "mac_alg_mismatch") == 0) {
        if (run_named_test("mac_alg_mismatch",
                           test_mac_alg_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_alg_mismatch") == 0) {
        if (run_named_test("aead_alg_mismatch",
                           test_aead_alg_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_key_agreement_derive_check") == 0) {
        if (run_named_test("kdf_key_agreement_derive_check",
                           test_kdf_key_agreement_derive_check) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_input_key_checks") == 0) {
        if (run_named_test("kdf_input_key_checks",
                           test_kdf_input_key_checks) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asymmetric_alg_mismatch") == 0) {
        if (run_named_test("asymmetric_alg_mismatch",
                           test_asymmetric_alg_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_alg_mismatch") == 0) {
        if (run_named_test("cipher_alg_mismatch",
                           test_cipher_alg_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_requires_decrypt_usage") == 0) {
        if (run_named_test("cipher_requires_decrypt_usage",
                           test_cipher_requires_decrypt_usage) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_non_aes_key_type") == 0) {
        if (run_named_test("cipher_non_aes_key_type",
                           test_cipher_rejects_non_aes_key_type) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "mac_requires_verify_usage") == 0) {
        if (run_named_test("mac_requires_verify_usage",
                           test_mac_requires_verify_usage) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_tls12_psk_to_ms") == 0) {
        if (run_named_test("kdf_tls12_psk_to_ms",
                           test_kdf_tls12_psk_to_ms_rfc4279_order) == TEST_FAIL) {
            return TEST_FAIL;
        }
        if (run_named_test("kdf_tls12_psk_to_ms_plain_psk",
                           test_kdf_tls12_psk_to_ms_plain_psk_optional_other_secret) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_extract_optional_salt") == 0) {
        if (run_named_test("kdf_hkdf_extract_optional_salt",
                           test_kdf_hkdf_extract_optional_salt) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_extract_prefix_output") == 0) {
        if (run_named_test("kdf_hkdf_extract_prefix_output",
                           test_kdf_hkdf_extract_prefix_output) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_expand_optional_info") == 0) {
        if (run_named_test("kdf_hkdf_expand_optional_info",
                           test_kdf_hkdf_expand_optional_info) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_optional_info") == 0) {
        if (run_named_test("kdf_hkdf_optional_info",
                           test_kdf_hkdf_optional_info) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_output_bytes_are_sequential") == 0) {
        if (run_named_test("kdf_output_bytes_are_sequential",
                           test_kdf_output_bytes_are_sequential) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ccm_star_no_tag_multipart") == 0) {
        if (run_named_test("ccm_star_no_tag_multipart",
                           test_ccm_star_no_tag_multipart) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ofb_round_trip") == 0) {
        if (run_named_test("ofb_round_trip",
                           test_ofb_round_trip) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cfb_round_trip") == 0) {
        if (run_named_test("cfb_round_trip",
                           test_cfb_round_trip) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "hkdf_extract_truncated_output") == 0) {
        if (run_named_test("hkdf_extract_truncated_output",
                           test_hkdf_extract_truncated_output) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_setup_cleanup") == 0) {
        if (run_named_test("cipher_setup_cleanup",
                           test_cipher_setup_cleanup) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }

    printf("PSA API test: OK (passed=%d skipped=%d)\n",
           tests_passed, tests_skipped);
    return TEST_OK;
}
