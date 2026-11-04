/* psa_tf_psa_pk_test.c
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

/* mbedtls/pk.h on wolfSSL's test keys. PK_CERTS_DIR is wolfSSL's certs/. */

#include <stdio.h>

#include <psa/crypto.h>
#include <mbedtls/pk.h>

#define CERT(name) PK_CERTS_DIR "/" name
#define RSA_KEY CERT("server-key.pem")
#define EC_KEY CERT("ecc-key.pem")
#define INVALID MBEDTLS_ERR_PK_KEY_INVALID_FORMAT

static const struct {
    const char* file;
    int ret;
} parseCases[] = {
    { RSA_KEY, 0 },
    { CERT("server-key.der"), 0 },
    { CERT("server-keyPkcs8.pem"), 0 },
    { CERT("server-keyPkcs8.der"), 0 },
    { EC_KEY, 0 },
    { CERT("ecc-key.der"), 0 },
    { CERT("ecc-keyPkcs8.pem"), 0 },
    { CERT("ecc-keyPkcs8.der"), 0 },
    { CERT("ca-ecc384-key.pem"), 0 },
    { CERT("server-keyEnc.pem"), INVALID },
    { CERT("server-keyPkcs8Enc.pem"), INVALID },
    { CERT("server-cert.pem"), INVALID },
    { CERT("missing.key"), MBEDTLS_ERR_PK_FILE_IO_ERROR }
};

static const struct {
    const char* file;
    psa_algorithm_t alg;
    psa_key_usage_t usage;
    int can;
} canDoCases[] = {
    { RSA_KEY, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_SIGN_HASH, 1 },
    { RSA_KEY, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), PSA_KEY_USAGE_VERIFY_HASH, 1 },
    { RSA_KEY, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), PSA_KEY_USAGE_DECRYPT, 1 },
    { RSA_KEY, PSA_ALG_RSA_PKCS1V15_CRYPT, PSA_KEY_USAGE_ENCRYPT, 1 },
    { RSA_KEY, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), PSA_KEY_USAGE_DECRYPT, 0 },
    { RSA_KEY, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_USAGE_SIGN_HASH, 0 },
    { EC_KEY, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_USAGE_SIGN_HASH, 1 },
    { EC_KEY, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_VERIFY_HASH, 1 },
    { EC_KEY, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_USAGE_ENCRYPT, 0 },
    { EC_KEY, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), PSA_KEY_USAGE_SIGN_HASH, 0 }
};

static int fails;

static void Check(int ok, const char* name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

static void Parse(void)
{
    mbedtls_pk_context pk;
    size_t i;

    for (i = 0; i < sizeof(parseCases) / sizeof(parseCases[0]); i++) {
        mbedtls_pk_init(&pk);
        Check(mbedtls_pk_parse_keyfile(&pk, parseCases[i].file, NULL) ==
            parseCases[i].ret, parseCases[i].file);
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
        Check(mbedtls_pk_parse_keyfile(&pk, canDoCases[i].file, NULL) == 0 &&
            mbedtls_pk_can_do_psa(&pk, canDoCases[i].alg,
                canDoCases[i].usage) == canDoCases[i].can, name);
        mbedtls_pk_free(&pk);
    }
}

/* An empty buffer, a second key into one context, NULL and empty contexts */
static void BadInput(void)
{
    static const unsigned char der[] = { 0x30, 0x00 };
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    Check(mbedtls_pk_can_do_psa(&pk, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_SIGN_HASH) == 0, "can_do_psa without a key");
    Check(mbedtls_pk_can_do_psa(NULL, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_KEY_USAGE_SIGN_HASH) == 0, "can_do_psa NULL");
    Check(mbedtls_pk_parse_key(NULL, der, sizeof(der), NULL, 0) ==
        PSA_ERROR_INVALID_ARGUMENT, "parse_key NULL");
    Check(mbedtls_pk_parse_key(&pk, der, 0, NULL, 0) == INVALID,
        "parse_key empty");
    Check(mbedtls_pk_parse_keyfile(&pk, EC_KEY, NULL) == 0 &&
        mbedtls_pk_parse_keyfile(&pk, RSA_KEY, NULL) ==
            PSA_ERROR_INVALID_ARGUMENT, "parse_key second key");
    mbedtls_pk_free(&pk);
    mbedtls_pk_free(&pk);
    mbedtls_pk_free(NULL);
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    Parse();
    CanDo();
    BadInput();
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
