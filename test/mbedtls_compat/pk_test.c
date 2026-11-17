/* pk_test.c
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

/* Key parsing through the TF-PSA-Crypto 1.x API. The cases of
 * mbedtls_pk_parse_keyfile and mbedtls_pk_parse_public_keyfile come from
 * TF-PSA-Crypto's tests/suites/test_suite_pkparse.data, those without a
 * password. Run from framework/data_files in an Mbed TLS checkout. */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/pk.h>

#define INVALID MBEDTLS_ERR_PK_KEY_INVALID_FORMAT
#define ENCRYPTED MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE
#define NO_CURVE MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE
#define EC_KEY "ec_256_prv.pem"
#define RSA_PUB "rsa_pkcs8_2048_public.der"
#define EC_PUB "ec_256_pub.der"
#define X25519_PUB "ec_x25519_pub.der"
#define ECDH_HKDF \
    PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256))

typedef struct {
    const char* file;
    int ret;
    size_t bits;
} ParseCase;

static const ParseCase keyCases[] = {
    { "ec_256_prv.pem", 0, 256 },
    { "ec_256_prv.der", 0, 256 },
    { "ec_256_prv.pk8.pem", 0, 256 },
    { "ec_256_prv.pk8.der", 0, 256 },
    { "ec_384_prv.pem", 0, 384 },
    { "ec_521_prv.pem", 0, 521 },
    { "ec_prv.pk8nopub.pem", 0, 256 },
    { "ec_prv.pk8nopubparam.pem", 0, 256 },
    { "ec_prv.pk8param.pem", 0, 256 },
    { "format_gen.key", 0, 1024 },
    { "rsa_pkcs1_768_clear.der", 0, 768 },
    { "rsa_pkcs1_776_clear.der", 0, 776 },
    /* Not a multiple of 8 bits. Mbed TLS: INVALID */
    { "rsa_pkcs1_769_clear.der", 0, 769 },
    /* Compressed public key. Mbed TLS: 0 */
    { "ec_256_prv.comp.pem", INVALID, 0 },
    /* Encrypted keys are not supported. Mbed TLS: PASSWORD_REQUIRED */
    { "rsa_pkcs8_pbes2_pbkdf2_1024_aes128cbc.pem", ENCRYPTED, 0 },
    /* Not in Mbed TLS's cases */
    { "ec_224_prv.pem", NO_CURVE, 0 },
    { "server2.key", 0, 2048 },
    { "server5.crt", INVALID, 0 },
    { "missing.key", MBEDTLS_ERR_PK_FILE_IO_ERROR, 0 }
};

static const ParseCase publicCases[] = {
    { "rsa_pkcs8_2048_public.pem", 0, 2048 },
    { "rsa_pkcs8_2048_public.der", 0, 2048 },
    { "rsa_pkcs1_2048_public.pem", 0, 2048 },
    { "rsa_pkcs1_2048_public.der", 0, 2048 },
    { "ec_256_pub.pem", 0, 256 },
    { "ec_256_pub.der", 0, 256 },
    { "ec_384_pub.pem", 0, 384 },
    { "ec_521_pub.pem", 0, 521 },
    { "ec_x25519_pub.der", 0, 255 },
    { "ec_x448_pub.der", 0, 448 },
    { "ec_x25519_pub.pem", 0, 255 },
    { "ec_x448_pub.pem", 0, 448 },
    /* Compressed public keys. Mbed TLS: 0 */
    { "ec_256_pub.comp.pem", INVALID, 0 },
    { "ec_384_pub.comp.pem", INVALID, 0 },
    { "ec_521_pub.comp.pem", INVALID, 0 },
    /* Brainpool curves are not in the build. Mbed TLS: 0 */
    { "ec_bp256_pub.pem", INVALID, 0 },
    { "ec_bp256_pub.comp.pem", INVALID, 0 },
    { "ec_bp384_pub.pem", INVALID, 0 },
    { "ec_bp384_pub.comp.pem", INVALID, 0 },
    { "ec_bp512_pub.pem", INVALID, 0 },
    { "ec_bp512_pub.comp.pem", INVALID, 0 },
    /* Not in Mbed TLS's cases */
    { "rsa4096_pub.pem", 0, 4096 },
    { "ec_224_pub.pem", NO_CURVE, 0 },
    { "ec_256_prv.pem", INVALID, 0 },
    { "server5.crt", INVALID, 0 },
    { "missing.pem", MBEDTLS_ERR_PK_FILE_IO_ERROR, 0 }
};

/* What TF-PSA-Crypto allows a public key: verify, encrypt and ECDH */
static const struct {
    const char* file;
    psa_algorithm_t alg;
    psa_key_usage_t usage;
    int can;
} canDoCases[] = {
    { RSA_PUB, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_VERIFY_HASH, 1 },
    { RSA_PUB, PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_SHA_384),
        PSA_KEY_USAGE_VERIFY_HASH, 1 },
    { RSA_PUB, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), PSA_KEY_USAGE_ENCRYPT, 1 },
    { RSA_PUB, PSA_ALG_RSA_PKCS1V15_CRYPT, PSA_KEY_USAGE_ENCRYPT, 1 },
    { RSA_PUB, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_SIGN_HASH, 0 },
    { RSA_PUB, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), PSA_KEY_USAGE_DECRYPT, 0 },
    { RSA_PUB, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_VERIFY_HASH, 0 },
    { EC_PUB, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_USAGE_VERIFY_HASH, 1 },
    { EC_PUB, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384),
        PSA_KEY_USAGE_VERIFY_HASH, 1 },
    { EC_PUB, PSA_ALG_ECDH, PSA_KEY_USAGE_DERIVE_PUBLIC, 1 },
    { EC_PUB, ECDH_HKDF, PSA_KEY_USAGE_DERIVE_PUBLIC, 1 },
    { EC_PUB, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_USAGE_SIGN_HASH, 0 },
    { EC_PUB, PSA_ALG_ECDH, PSA_KEY_USAGE_DERIVE, 0 },
    { X25519_PUB, PSA_ALG_ECDH, PSA_KEY_USAGE_DERIVE_PUBLIC, 1 },
    { X25519_PUB, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_VERIFY_HASH, 0 }
};

typedef int (*ParseFile)(mbedtls_pk_context* pk, const char* file);

static int fails;

static void Check(int ok, const char* name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

static int ParseKeyFile(mbedtls_pk_context* pk, const char* file)
{
    return mbedtls_pk_parse_keyfile(pk, file, NULL);
}

static void Parse(const ParseCase* cases, size_t count, ParseFile parse,
    const char* label)
{
    mbedtls_pk_context pk;
    size_t bits;
    size_t i;
    int ret;

    for (i = 0; i < count; i++) {
        mbedtls_pk_init(&pk);
        ret = parse(&pk, cases[i].file);
        bits = mbedtls_pk_get_bitlen(&pk);
        if (ret == cases[i].ret && bits == cases[i].bits) {
            printf("PASS: %s %s\n", label, cases[i].file);
        }
        else {
            printf("FAIL: %s %s: returned %d, %u bits, expected %d, %u bits\n",
                label, cases[i].file, ret, (unsigned)bits, cases[i].ret,
                (unsigned)cases[i].bits);
            fails++;
        }
        mbedtls_pk_free(&pk);
    }
}

static void CanDo(void)
{
    mbedtls_pk_context pk;
    char name[32];
    size_t i;

    for (i = 0; i < sizeof(canDoCases) / sizeof(canDoCases[0]); i++) {
        (void)snprintf(name, sizeof(name), "can_do_psa case %u",
            (unsigned)i);
        mbedtls_pk_init(&pk);
        Check(mbedtls_pk_parse_public_keyfile(&pk, canDoCases[i].file) == 0 &&
            mbedtls_pk_can_do_psa(&pk, canDoCases[i].alg,
                canDoCases[i].usage) == canDoCases[i].can, name);
        mbedtls_pk_free(&pk);
    }
    mbedtls_pk_init(&pk);
    Check(mbedtls_pk_parse_keyfile(&pk, EC_KEY, NULL) == 0 &&
        mbedtls_pk_can_do_psa(&pk, ECDH_HKDF,
            PSA_KEY_USAGE_DERIVE_PUBLIC) == 0,
        "can_do_psa private key, ECDH with a KDF");
    mbedtls_pk_free(&pk);
}

/* The file in buf, with room for a byte after it */
static size_t ReadFile(const char* file, unsigned char* buf, size_t size)
{
    FILE* f;
    size_t len = 0;

    f = fopen(file, "rb");
    if (f != NULL) {
        len = fread(buf, 1, size - 1, f);
        (void)fclose(f);
    }
    return len;
}

/* The context has SubjectPublicKeyInfo DER, also from PKCS #1 */
static void PublicDer(void)
{
    unsigned char spki[512];
    unsigned char ec[128];
    size_t spkiLen;
    size_t ecLen;
    mbedtls_pk_context pk;

    spkiLen = ReadFile(RSA_PUB, spki, sizeof(spki));
    ecLen = ReadFile(EC_PUB, ec, sizeof(ec));

    mbedtls_pk_init(&pk);
    Check(spkiLen > 0 && mbedtls_pk_parse_public_keyfile(&pk,
        "rsa_pkcs1_2048_public.der") == 0 && pk.pub_len == spkiLen &&
        memcmp(pk.pub, spki, spkiLen) == 0, "PKCS #1 public key DER");
    mbedtls_pk_free(&pk);
    Check(ecLen > 0 && mbedtls_pk_parse_public_key(&pk, ec, ecLen) == 0 &&
        pk.pub_len == ecLen && memcmp(pk.pub, ec, ecLen) == 0,
        "EC public key DER");
    mbedtls_pk_free(&pk);

    /* Mbed TLS ignores data after SubjectPublicKeyInfo */
    ec[ecLen] = 0;
    Check(ecLen > 0 && mbedtls_pk_parse_public_key(&pk, ec, ecLen + 1) ==
        INVALID, "public key DER and a NUL");
    mbedtls_pk_free(&pk);

    /* Mbed TLS: INVALID_PUBKEY */
    if (ecLen > 0) {
        ec[ecLen - 1] ^= 1;
    }
    Check(ecLen > 0 && mbedtls_pk_parse_public_key(&pk, ec, ecLen) ==
        INVALID, "point not on the curve");
    mbedtls_pk_free(&pk);
}

/* Empty buffers, NULL and empty contexts, and a second key into one context */
static void BadInput(void)
{
    static const unsigned char der[] = { 0x30, 0x00 };
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    Check(mbedtls_pk_parse_key(&pk, der, 0, NULL, 0) == INVALID,
        "parse_key empty");
    Check(mbedtls_pk_parse_public_key(&pk, der, 0) == INVALID,
        "parse_public_key empty");
    Check(mbedtls_pk_parse_public_key(NULL, der, sizeof(der)) ==
        PSA_ERROR_INVALID_ARGUMENT, "parse_public_key NULL");
    Check(mbedtls_pk_get_bitlen(&pk) == 0 && mbedtls_pk_get_bitlen(NULL) == 0,
        "get_bitlen without a key");
    Check(mbedtls_pk_parse_keyfile(&pk, "server2.key", NULL) == 0 &&
        mbedtls_pk_parse_keyfile(&pk, "server5.key", NULL) ==
            PSA_ERROR_INVALID_ARGUMENT &&
        mbedtls_pk_parse_public_keyfile(&pk, EC_PUB) ==
            PSA_ERROR_INVALID_ARGUMENT, "a second key after a private key");
    mbedtls_pk_free(&pk);
    Check(mbedtls_pk_parse_public_keyfile(&pk, EC_PUB) == 0 &&
        mbedtls_pk_parse_public_keyfile(&pk, RSA_PUB) ==
            PSA_ERROR_INVALID_ARGUMENT &&
        mbedtls_pk_parse_keyfile(&pk, "server2.key", NULL) ==
            PSA_ERROR_INVALID_ARGUMENT, "a second key after a public key");
    mbedtls_pk_free(&pk);
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    Parse(keyCases, sizeof(keyCases) / sizeof(keyCases[0]), ParseKeyFile,
        "parse_keyfile");
    Parse(publicCases, sizeof(publicCases) / sizeof(publicCases[0]),
        mbedtls_pk_parse_public_keyfile, "parse_public_keyfile");
    CanDo();
    PublicDer();
    BadInput();
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
