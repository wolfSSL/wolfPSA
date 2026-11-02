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

/* Private key parsing through the TF-PSA-Crypto 1.x API. The cases of
 * mbedtls_pk_parse_keyfile come from TF-PSA-Crypto's
 * tests/suites/test_suite_pkparse.data, those without a password. Run from
 * framework/data_files in an Mbed TLS checkout. */

#include <stdio.h>

#include <psa/crypto.h>
#include <mbedtls/pk.h>

#define INVALID MBEDTLS_ERR_PK_KEY_INVALID_FORMAT
#define ENCRYPTED MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE

static const struct {
    const char* file;
    int ret;
} cases[] = {
    { "ec_256_prv.pem", 0 },
    { "ec_256_prv.der", 0 },
    { "ec_256_prv.pk8.pem", 0 },
    { "ec_256_prv.pk8.der", 0 },
    { "ec_384_prv.pem", 0 },
    { "ec_521_prv.pem", 0 },
    { "ec_prv.pk8nopub.pem", 0 },
    { "ec_prv.pk8nopubparam.pem", 0 },
    { "ec_prv.pk8param.pem", 0 },
    { "format_gen.key", 0 },
    { "rsa_pkcs1_768_clear.der", 0 },
    { "rsa_pkcs1_776_clear.der", 0 },
    /* Not a multiple of 8 bits. Mbed TLS: INVALID */
    { "rsa_pkcs1_769_clear.der", 0 },
    /* Compressed public key. Mbed TLS: 0 */
    { "ec_256_prv.comp.pem", INVALID },
    /* Encrypted keys are not supported. Mbed TLS: PASSWORD_REQUIRED */
    { "rsa_pkcs8_pbes2_pbkdf2_1024_aes128cbc.pem", ENCRYPTED },
    /* Not in Mbed TLS's cases */
    { "server2.key", 0 },
    { "server5.crt", INVALID },
    { "missing.key", MBEDTLS_ERR_PK_FILE_IO_ERROR }
};

/* An empty buffer, and a second key into one context, as in Mbed TLS */
static int BadInput(void)
{
    static const unsigned char der[] = { 0x30, 0x00 };
    mbedtls_pk_context pk;
    int ok;

    mbedtls_pk_init(&pk);
    ok = mbedtls_pk_parse_key(&pk, der, 0, NULL, 0) == INVALID &&
        mbedtls_pk_parse_keyfile(&pk, "server2.key", NULL) == 0 &&
        mbedtls_pk_parse_keyfile(&pk, "server5.key", NULL) ==
            PSA_ERROR_INVALID_ARGUMENT;
    mbedtls_pk_free(&pk);
    return ok;
}

int main(void)
{
    mbedtls_pk_context pk;
    size_t i;
    int fails = 0;
    int ret;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        mbedtls_pk_init(&pk);
        ret = mbedtls_pk_parse_keyfile(&pk, cases[i].file, NULL);
        if (ret == cases[i].ret) {
            printf("PASS: %s\n", cases[i].file);
        }
        else {
            printf("FAIL: %s: returned %d, expected %d\n", cases[i].file,
                ret, cases[i].ret);
            fails++;
        }
        mbedtls_pk_free(&pk);
    }
    if (BadInput()) {
        printf("PASS: bad input\n");
    }
    else {
        printf("FAIL: bad input\n");
        fails++;
    }
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
