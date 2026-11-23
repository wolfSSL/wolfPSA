/* psa_rsa_4096_test.c
 *
 * A 4096-bit key, PSA_VENDOR_RSA_MAX_KEY_BITS, signs, verifies, encrypts and
 * decrypts, and its exported public key verifies. A generated key signs.
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
#ifdef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif /* WOLFSSL_USER_SETTINGS */
/* Checked before wolfCrypt picks a default */
#if defined(SP_INT_BITS) || defined(SP_INT_DIGITS)
#define MATH_SIZE_SET 1
#else
#define MATH_SIZE_SET 0
#endif /* SP_INT_BITS || SP_INT_DIGITS */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <stdio.h>
#include <string.h>

#ifdef NO_RSA
int main(void)
{
    printf("RSA-4096 tests: skipped, NO_RSA\n");
    return 0;
}
#else
#define USE_CERT_BUFFERS_4096
#include <wolfssl/certs_test.h>

#define KEY_BITS  4096
#define KEY_BYTES (KEY_BITS / 8)

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *name,
                   const char *what)
{
    if (got != want) {
        printf("FAIL: %s %s: got %d want %d\n", name, what, (int)got,
               (int)want);
        failures++;
    }
}

static void check_bits(psa_key_id_t key, const char *name)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();

    expect(psa_get_key_attributes(key, &attrs), PSA_SUCCESS, name,
           "attributes");
    if (psa_get_key_bits(&attrs) != KEY_BITS) {
        printf("FAIL: %s bits: got %u\n", name,
               (unsigned)psa_get_key_bits(&attrs));
        failures++;
    }
    psa_reset_key_attributes(&attrs);
}

static psa_key_id_t import_key(psa_key_type_t type, const uint8_t *data,
                               size_t data_len, psa_key_usage_t usage,
                               psa_algorithm_t alg, const char *name)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attrs, type);
    psa_set_key_usage_flags(&attrs, usage);
    psa_set_key_algorithm(&attrs, alg);
    expect(psa_import_key(&attrs, data, data_len, &key), PSA_SUCCESS, name,
           "import");
    check_bits(key, name);
    return key;
}

/* Signs with pair and verifies with its exported public key */
static void sign_verify(psa_key_id_t pair, psa_algorithm_t alg,
                        const char *name)
{
    psa_key_id_t pub = PSA_KEY_ID_NULL;
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    uint8_t sig[KEY_BYTES];
    size_t sig_len = 0;
    uint8_t pub_der[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
        PSA_KEY_TYPE_RSA_KEY_PAIR, KEY_BITS)];
    size_t pub_len = 0;
    psa_status_t status;

    memset(hash, 0x2a, sizeof(hash));
    status = psa_sign_hash(pair, alg, hash, sizeof(hash), sig, sizeof(sig),
                           &sig_len);
    expect(status, PSA_SUCCESS, name, "sign");
    expect(psa_export_public_key(pair, pub_der, sizeof(pub_der), &pub_len),
           PSA_SUCCESS, name, "export public key");

    pub = import_key(PSA_KEY_TYPE_RSA_PUBLIC_KEY, pub_der, pub_len,
                     PSA_KEY_USAGE_VERIFY_HASH, alg, name);
    if (status == PSA_SUCCESS) {
        expect(psa_verify_hash(pub, alg, hash, sizeof(hash), sig, sig_len),
               PSA_SUCCESS, name, "verify");
        sig[0] ^= 0x01;
        expect(psa_verify_hash(pub, alg, hash, sizeof(hash), sig, sig_len),
               PSA_ERROR_INVALID_SIGNATURE, name, "verify, signature changed");
    }
    psa_destroy_key(pub);
}

static void check_sign(psa_algorithm_t alg, const char *name)
{
    psa_key_id_t pair = import_key(PSA_KEY_TYPE_RSA_KEY_PAIR,
        client_key_der_4096, sizeof_client_key_der_4096,
        PSA_KEY_USAGE_SIGN_HASH, alg, name);

    sign_verify(pair, alg, name);
    psa_destroy_key(pair);
}

static void check_generate(void)
{
    const psa_algorithm_t alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
    const char *name = "generated";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t pair = PSA_KEY_ID_NULL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attrs, alg);
    expect(psa_generate_key(&attrs, &pair), PSA_SUCCESS, name, "generate");
    check_bits(pair, name);
    sign_verify(pair, alg, name);
    psa_destroy_key(pair);
}

static void check_encrypt(psa_algorithm_t alg, const char *name)
{
    psa_key_id_t pair = import_key(PSA_KEY_TYPE_RSA_KEY_PAIR,
        client_key_der_4096, sizeof_client_key_der_4096,
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, alg, name);
    uint8_t msg[64];
    uint8_t out[KEY_BYTES];
    size_t out_len = 0;
    uint8_t plain[KEY_BYTES];
    size_t plain_len = 0;
    psa_status_t status;

    memset(msg, 0x5c, sizeof(msg));
    status = psa_asymmetric_encrypt(pair, alg, msg, sizeof(msg), NULL, 0,
                                    out, sizeof(out), &out_len);
    expect(status, PSA_SUCCESS, name, "encrypt");
    if (status == PSA_SUCCESS) {
        expect(psa_asymmetric_decrypt(pair, alg, out, out_len, NULL, 0,
                                      plain, sizeof(plain), &plain_len),
               PSA_SUCCESS, name, "decrypt");
        if (plain_len != sizeof(msg) ||
            memcmp(plain, msg, sizeof(msg)) != 0) {
            printf("FAIL: %s decrypt: wrong plaintext\n", name);
            failures++;
        }
    }
    psa_destroy_key(pair);
}

int main(void)
{
    static const struct {
        psa_algorithm_t alg;
        const char *name;
    } sigAlgs[] = {
        { PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), "v1.5" },
        { PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), "PSS" }
    }, cryptAlgs[] = {
        { PSA_ALG_RSA_PKCS1V15_CRYPT, "v1.5 crypt" },
        { PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), "OAEP" }
    };
    size_t i;

    /* Required unless the build sets a smaller math size */
    if (MATH_SIZE_SET && RSA_MAX_SIZE < KEY_BITS) {
        printf("RSA-4096 tests: skipped, RSA_MAX_SIZE %d\n",
               (int)RSA_MAX_SIZE);
        return 0;
    }
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    for (i = 0; i < sizeof(sigAlgs) / sizeof(sigAlgs[0]); i++) {
        check_sign(sigAlgs[i].alg, sigAlgs[i].name);
    }
    for (i = 0; i < sizeof(cryptAlgs) / sizeof(cryptAlgs[0]); i++) {
        check_encrypt(cryptAlgs[i].alg, cryptAlgs[i].name);
    }
    check_generate();

    if (failures == 0) {
        printf("RSA-4096 tests: all passed\n");
        return 0;
    }
    printf("RSA-4096 tests: %d failure(s)\n", failures);
    return 1;
}
#endif /* NO_RSA */
