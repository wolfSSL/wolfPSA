/* psa_import_key_data_test.c
 *
 * psa_import_key() rejects RSA and ECC key data that does not describe a
 * valid key of the given type and size.
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
#include <stdio.h>
#include <string.h>

#define RSA_BITS 1024

static int failures;

static void check_import(psa_key_type_t type, size_t bits,
                         const uint8_t *data, size_t data_len,
                         psa_status_t want, size_t want_bits,
                         const char *what)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t status;

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    status = psa_import_key(&attrs, data, data_len, &key);
    if (status != want) {
        printf("FAIL: %s: got %d want %d\n", what, (int)status, (int)want);
        failures++;
    }
    else if (status == PSA_SUCCESS &&
             (psa_get_key_attributes(key, &got) != PSA_SUCCESS ||
              psa_get_key_bits(&got) != want_bits)) {
        printf("FAIL: %s: bits %u want %u\n", what,
               (unsigned)psa_get_key_bits(&got), (unsigned)want_bits);
        failures++;
    }
    psa_destroy_key(key);
}

static psa_status_t generate_export(psa_key_type_t type, size_t bits,
                                    uint8_t *pair, size_t pair_size,
                                    size_t *pair_len, uint8_t *pub,
                                    size_t pub_size, size_t *pub_len)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t status;

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    status = psa_generate_key(&attrs, &key);
    if (status == PSA_SUCCESS) {
        status = psa_export_key(key, pair, pair_size, pair_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_export_public_key(key, pub, pub_size, pub_len);
    }
    psa_destroy_key(key);
    return status;
}

/* RSAPublicKey with a 128-byte modulus whose top byte is 0x3f: 1022 bits */
static void check_rsa_odd_size(void)
{
    uint8_t der[139];

    memset(der, 0xff, sizeof(der));
    memcpy(der, "\x30\x81\x88\x02\x81\x80\x3f", 7);
    memcpy(der + sizeof(der) - 5, "\x02\x03\x01\x00\x01", 5);
    check_import(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 0, der, sizeof(der),
                 PSA_ERROR_NOT_SUPPORTED, 0, "RSA 1022-bit public key");
}

static void check_rsa(void)
{
    static uint8_t pair[PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(RSA_BITS) + 1];
    uint8_t pub[PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(RSA_BITS)];
    size_t pair_len = 0;
    size_t pub_len = 0;
    psa_status_t status;

    status = generate_export(PSA_KEY_TYPE_RSA_KEY_PAIR, RSA_BITS, pair,
                             sizeof(pair) - 1, &pair_len, pub, sizeof(pub),
                             &pub_len);
    if (status != PSA_SUCCESS) {
        printf("FAIL: generate and export RSA key: %d\n", (int)status);
        failures++;
        return;
    }

    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pair, pair_len, PSA_SUCCESS,
                 RSA_BITS, "RSA key pair");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, RSA_BITS, pair, pair_len,
                 PSA_SUCCESS, RSA_BITS, "RSA key pair, bits given");
    check_import(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 0, pub, pub_len, PSA_SUCCESS,
                 RSA_BITS, "RSA public key");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 2 * RSA_BITS, pair, pair_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair, wrong bits");
    pair[pair_len] = 0;
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, RSA_BITS, pair, pair_len + 1,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair, trailing data");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pair, pair_len - 1,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair, truncated");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pub, pub_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA public key as pair");
    check_import(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 0, pair, pair_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair as public");
    check_rsa_odd_size();
}

/* The order n of secp256r1 */
static const uint8_t p256_n[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

static const struct {
    uint8_t last;
    psa_status_t want;
    const char *what;
} p256_scalars[] = {
    { 0x50, PSA_SUCCESS, "ECC secp256r1 d = n - 1" },
    { 0x51, PSA_ERROR_INVALID_ARGUMENT, "ECC secp256r1 d = n" },
    { 0x52, PSA_ERROR_INVALID_ARGUMENT, "ECC secp256r1 d = n + 1" },
};

static void check_ecc(void)
{
    const psa_key_type_t type =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    uint8_t d[sizeof(p256_n)];
    uint8_t pair[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(256)];
    uint8_t pub[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
    size_t pair_len = 0;
    size_t pub_len = 0;
    size_t i;

    memset(d, 0, sizeof(d));
    check_import(type, 0, d, sizeof(d), PSA_ERROR_INVALID_ARGUMENT, 0,
                 "ECC secp256r1 d = 0");
    for (i = 0; i < sizeof(p256_scalars) / sizeof(p256_scalars[0]); i++) {
        memcpy(d, p256_n, sizeof(d));
        d[sizeof(d) - 1] = p256_scalars[i].last;
        check_import(type, 0, d, sizeof(d), p256_scalars[i].want, 256,
                     p256_scalars[i].what);
    }

    if (generate_export(type, 256, pair, sizeof(pair), &pair_len, pub,
                        sizeof(pub), &pub_len) != PSA_SUCCESS) {
        printf("FAIL: generate and export ECC key\n");
        failures++;
        return;
    }
    check_import(type, 0, pair, pair_len, PSA_SUCCESS, 256,
                 "ECC secp256r1 key pair");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pair, pair_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "ECC key pair as RSA");
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

    check_rsa();
    check_ecc();

    if (failures == 0) {
        printf("Import key data tests: all passed\n");
        return 0;
    }
    printf("Import key data tests: %d failure(s)\n", failures);
    return 1;
}
