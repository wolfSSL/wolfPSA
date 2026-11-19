/* psa_tf_psa_md_test.c
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

/* mbedtls/md.h on the digest of "abc" for each hash */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/md.h>
#include <mbedtls/psa_util.h>

#define BAD MBEDTLS_ERR_MD_BAD_INPUT_DATA

static const unsigned char abc[] = "abc";

static const struct {
    mbedtls_md_type_t type;
    const char* name;
    const char* hash;
} vectors[] = {
#if defined(PSA_WANT_ALG_MD5)
    { MBEDTLS_MD_MD5, "MD5", "900150983cd24fb0d6963f7d28e17f72" },
#endif /* PSA_WANT_ALG_MD5 */
#if defined(PSA_WANT_ALG_RIPEMD160)
    { MBEDTLS_MD_RIPEMD160, "RIPEMD-160",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
#endif /* PSA_WANT_ALG_RIPEMD160 */
#if defined(PSA_WANT_ALG_SHA_1)
    { MBEDTLS_MD_SHA1, "SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d" },
#endif /* PSA_WANT_ALG_SHA_1 */
#if defined(PSA_WANT_ALG_SHA_224)
    { MBEDTLS_MD_SHA224, "SHA-224",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_256)
    { MBEDTLS_MD_SHA256, "SHA-256",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
    { MBEDTLS_MD_SHA384, "SHA-384",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
    { MBEDTLS_MD_SHA512, "SHA-512",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
#endif /* PSA_WANT_ALG_SHA_512 */
#if defined(PSA_WANT_ALG_SHA3_224)
    { MBEDTLS_MD_SHA3_224, "SHA3-224",
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
#endif /* PSA_WANT_ALG_SHA3_224 */
#if defined(PSA_WANT_ALG_SHA3_256)
    { MBEDTLS_MD_SHA3_256, "SHA3-256",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
#endif /* PSA_WANT_ALG_SHA3_256 */
#if defined(PSA_WANT_ALG_SHA3_384)
    { MBEDTLS_MD_SHA3_384, "SHA3-384",
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c25"
        "96da7cf0e49be4b298d88cea927ac7f539f1edf228376d25" },
#endif /* PSA_WANT_ALG_SHA3_384 */
#if defined(PSA_WANT_ALG_SHA3_512)
    { MBEDTLS_MD_SHA3_512, "SHA3-512",
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
#endif /* PSA_WANT_ALG_SHA3_512 */
};

static int fails;

static void Check(int ok, const char* name, const char* what)
{
    printf("%s: %s %s\n", ok ? "PASS" : "FAIL", name, what);
    if (!ok) {
        fails++;
    }
}

static int Same(const unsigned char* out, const char* want)
{
    char hex[2 * MBEDTLS_MD_MAX_SIZE + 1];
    size_t len = strlen(want) / 2;
    size_t i;

    for (i = 0; i < len; i++) {
        (void)snprintf(hex + 2 * i, 3, "%02x", out[i]);
    }
    return memcmp(hex, want, 2 * len) == 0;
}

/* "abc" in two parts, cloned after the first into a context in use */
static int TwoParts(const mbedtls_md_info_t* info, const char* want)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_context_t copy;
    unsigned char out[MBEDTLS_MD_MAX_SIZE];
    unsigned char copyOut[MBEDTLS_MD_MAX_SIZE];
    int ok;

    mbedtls_md_init(&ctx);
    mbedtls_md_init(&copy);
    ok = mbedtls_md_setup(&ctx, info, 0) == 0 &&
        mbedtls_md_setup(&copy, info, 0) == 0 &&
        mbedtls_md_starts(&copy) == 0 &&
        mbedtls_md_update(&copy, abc, 3) == 0 &&
        mbedtls_md_starts(&ctx) == 0 &&
        mbedtls_md_update(&ctx, abc, 1) == 0 &&
        mbedtls_md_clone(&copy, &ctx) == 0 &&
        mbedtls_md_update(&ctx, abc + 1, 2) == 0 &&
        mbedtls_md_update(&copy, abc + 1, 2) == 0 &&
        mbedtls_md_finish(&ctx, out) == 0 &&
        mbedtls_md_finish(&copy, copyOut) == 0 &&
        Same(out, want) && Same(copyOut, want);
    /* Again on the same context */
    ok = ok && mbedtls_md_starts(&ctx) == 0 &&
        mbedtls_md_update(&ctx, abc, 3) == 0 &&
        mbedtls_md_finish(&ctx, out) == 0 && Same(out, want);
    mbedtls_md_free(&ctx);
    mbedtls_md_free(&copy);
    return ok;
}

static void Vectors(void)
{
    const mbedtls_md_info_t* info;
    unsigned char out[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_type_t type;
    size_t size;
    size_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        type = vectors[i].type;
        size = strlen(vectors[i].hash) / 2;
        info = mbedtls_md_info_from_type(type);
        Check(info != NULL && mbedtls_md_get_type(info) == type &&
            mbedtls_md_get_size(info) == size &&
            mbedtls_md_get_size_from_type(type) == size &&
            mbedtls_md_type_from_psa_alg(
                mbedtls_md_psa_alg_from_type(type)) == type,
            vectors[i].name, "info");
        Check(info != NULL && mbedtls_md(info, abc, 3, out) == 0 &&
            Same(out, vectors[i].hash), vectors[i].name, "in one call");
        Check(info != NULL && TwoParts(info, vectors[i].hash),
            vectors[i].name, "in two parts");
    }
}

static void BadInput(void)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(vectors[0].type);
    const mbedtls_md_info_t* other =
        mbedtls_md_info_from_type(vectors[1].type);
    mbedtls_md_context_t ctx;
    mbedtls_md_context_t dst;
    unsigned char buf[MBEDTLS_MD_MAX_SIZE] = { 0 };

    mbedtls_md_init(&ctx);
    mbedtls_md_init(&dst);
    Check(mbedtls_md_info_from_type(MBEDTLS_MD_NONE) == NULL &&
        mbedtls_md_get_size(NULL) == 0 &&
        mbedtls_md_get_type(NULL) == MBEDTLS_MD_NONE &&
        mbedtls_md_get_size_from_type(MBEDTLS_MD_NONE) == 0,
        "no", "md info");
    Check(mbedtls_md_setup(&ctx, NULL, 0) == BAD &&
        mbedtls_md_setup(NULL, info, 0) == BAD &&
        mbedtls_md(NULL, buf, 1, buf) == BAD, "NULL", "md info or context");
    Check(mbedtls_md_setup(&ctx, info, 1) == BAD, "HMAC", "setup");
    Check(mbedtls_md_starts(NULL) == BAD && mbedtls_md_starts(&ctx) == BAD &&
        mbedtls_md_update(NULL, buf, 1) == BAD &&
        mbedtls_md_update(&ctx, buf, 1) == BAD &&
        mbedtls_md_finish(NULL, buf) == BAD &&
        mbedtls_md_finish(&ctx, buf) == BAD, "no", "setup");
    Check(mbedtls_md_setup(&ctx, info, 0) == 0 &&
        mbedtls_md_update(&ctx, buf, 1) == PSA_ERROR_GENERIC_ERROR,
        "update", "before starts");
    Check(mbedtls_md_setup(&dst, other, 0) == 0 &&
        mbedtls_md_starts(&ctx) == 0 && mbedtls_md_clone(&dst, &ctx) == BAD &&
        mbedtls_md_clone(NULL, &ctx) == BAD &&
        mbedtls_md_clone(&dst, NULL) == BAD, "clone", "to another md");
    mbedtls_md_free(&ctx);
    mbedtls_md_free(&dst);
    mbedtls_md_free(NULL);
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    Vectors();
    BadInput();
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
