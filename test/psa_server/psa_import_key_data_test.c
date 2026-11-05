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

#define RSA_BITS  2048
#define RSA_BYTES (RSA_BITS / 8)

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

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_ECC_SECP_R1_256)
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
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE || PSA_WANT_ECC_SECP_R1_256 */

#ifdef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
static size_t der_header(uint8_t *der, uint8_t tag, size_t len)
{
    size_t i = 0;

    der[i++] = tag;
    if (len >= 0x100) {
        der[i++] = 0x82;
        der[i++] = (uint8_t)(len >> 8);
    }
    else if (len >= 0x80) {
        der[i++] = 0x81;
    }
    der[i++] = (uint8_t)len;
    return i;
}

/* RSAPublicKey with an n_len-byte modulus top || ff .. ff and a 1-byte e */
static size_t rsa_public_der(uint8_t *der, size_t n_len, uint8_t top,
                             uint8_t e)
{
    uint8_t n_hdr[4];
    size_t pad = (top & 0x80) ? 1 : 0;
    size_t n_hdr_len = der_header(n_hdr, 0x02, pad + n_len);
    size_t i = der_header(der, 0x30, n_hdr_len + pad + n_len + 3);

    memcpy(der + i, n_hdr, n_hdr_len);
    i += n_hdr_len;
    if (pad) {
        der[i++] = 0;
    }
    der[i++] = top;
    memset(der + i, 0xff, n_len - 1);
    i += n_len - 1;
    der[i++] = 0x02;
    der[i++] = 0x01;
    der[i++] = e;
    return i;
}

static const struct {
    size_t n_len;
    uint8_t top;
    uint8_t e;
    psa_status_t want;
    size_t want_bits;
    const char *what;
} rsa_public_keys[] = {
    { RSA_BYTES, 0xc5, 3, PSA_SUCCESS, RSA_BITS, "RSA public key, e = 3" },
    { RSA_BYTES, 0x7f, 3, PSA_ERROR_NOT_SUPPORTED, 0,
      "RSA public key, n not a whole number of bytes" },
    { 1, 0xc5, 3, PSA_ERROR_NOT_SUPPORTED, 0, "RSA public key, 8-bit n" },
    { RSA_BYTES, 0xc5, 0, PSA_ERROR_INVALID_ARGUMENT, 0,
      "RSA public key, e = 0" },
    { RSA_BYTES, 0xc5, 1, PSA_ERROR_INVALID_ARGUMENT, 0,
      "RSA public key, e = 1" },
    { RSA_BYTES, 0xc5, 4, PSA_ERROR_INVALID_ARGUMENT, 0,
      "RSA public key, e = 4" },
};

static void check_rsa_public(void)
{
    uint8_t der[RSA_BYTES + 16];
    size_t der_len;
    size_t i;

    for (i = 0; i < sizeof(rsa_public_keys) / sizeof(rsa_public_keys[0]);
         i++) {
        der_len = rsa_public_der(der, rsa_public_keys[i].n_len,
                                 rsa_public_keys[i].top,
                                 rsa_public_keys[i].e);
        check_import(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 0, der, der_len,
                     rsa_public_keys[i].want, rsa_public_keys[i].want_bits,
                     rsa_public_keys[i].what);
    }
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
    check_import(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 2 * RSA_BITS, pub, pub_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA public key, wrong bits");
    pair[pair_len] = 0;
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, RSA_BITS, pair, pair_len + 1,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair, trailing data");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pair, pair_len - 1,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair, truncated");
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pub, pub_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA public key as pair");
    check_import(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 0, pair, pair_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "RSA key pair as public");
    check_rsa_public();
}
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE */

#ifdef PSA_WANT_ECC_SECP_R1_256
/* The order n of each curve. None ends in 0x00 or 0xff, so n - 1 and n + 1
 * differ from n only in the last byte. */
static const uint8_t p256_n[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
#ifdef PSA_WANT_ECC_SECP_R1_384
static const uint8_t p384_n[48] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
    0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
};
#endif /* PSA_WANT_ECC_SECP_R1_384 */
#ifdef PSA_WANT_ECC_SECP_R1_521
static const uint8_t p521_n[66] = {
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
    0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
    0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09
};
#endif /* PSA_WANT_ECC_SECP_R1_521 */

static const struct {
    size_t bits;
    const uint8_t *n;
    size_t n_len;
} secp_r1_orders[] = {
    { 256, p256_n, sizeof(p256_n) },
#ifdef PSA_WANT_ECC_SECP_R1_384
    { 384, p384_n, sizeof(p384_n) },
#endif
#ifdef PSA_WANT_ECC_SECP_R1_521
    { 521, p521_n, sizeof(p521_n) },
#endif
};

static const struct {
    int delta;
    psa_status_t want;
    const char *what;
} scalars[] = {
    { -1, PSA_SUCCESS, "n - 1" },
    { 0, PSA_ERROR_INVALID_ARGUMENT, "n" },
    { 1, PSA_ERROR_INVALID_ARGUMENT, "n + 1" },
};

static void check_ecc_scalars(size_t bits, const uint8_t *n, size_t n_len)
{
    const psa_key_type_t type =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    uint8_t d[PSA_BITS_TO_BYTES(521)];
    char what[64];
    size_t i;

    memset(d, 0, sizeof(d));
    snprintf(what, sizeof(what), "ECC secp%ur1 d = 0", (unsigned)bits);
    check_import(type, 0, d, n_len, PSA_ERROR_INVALID_ARGUMENT, 0, what);
    for (i = 0; i < sizeof(scalars) / sizeof(scalars[0]); i++) {
        memcpy(d, n, n_len);
        d[n_len - 1] = (uint8_t)(d[n_len - 1] + scalars[i].delta);
        snprintf(what, sizeof(what), "ECC secp%ur1 d = %s", (unsigned)bits,
                 scalars[i].what);
        check_import(type, 0, d, n_len, scalars[i].want, bits, what);
    }
}

static void check_ecc(void)
{
    const psa_key_type_t type =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    const psa_key_type_t pub_type =
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
    uint8_t pair[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(256)];
    uint8_t pub[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
    size_t pair_len = 0;
    size_t pub_len = 0;
    size_t i;

    for (i = 0; i < sizeof(secp_r1_orders) / sizeof(secp_r1_orders[0]);
         i++) {
        check_ecc_scalars(secp_r1_orders[i].bits, secp_r1_orders[i].n,
                          secp_r1_orders[i].n_len);
    }

    if (generate_export(type, 256, pair, sizeof(pair), &pair_len, pub,
                        sizeof(pub), &pub_len) != PSA_SUCCESS) {
        printf("FAIL: generate and export ECC key\n");
        failures++;
        return;
    }
    check_import(type, 0, pair, pair_len, PSA_SUCCESS, 256,
                 "ECC secp256r1 key pair");
    check_import(pub_type, 0, pub, pub_len, PSA_SUCCESS, 256,
                 "ECC secp256r1 public key");
#ifdef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC
    check_import(PSA_KEY_TYPE_RSA_KEY_PAIR, 0, pair, pair_len,
                 PSA_ERROR_INVALID_ARGUMENT, 0, "ECC key pair as RSA");
#endif
    memset(pub + 1, 0x11, pub_len - 1);
    check_import(pub_type, 0, pub, pub_len, PSA_ERROR_INVALID_ARGUMENT, 0,
                 "ECC secp256r1 public key not on the curve");
}
#endif /* PSA_WANT_ECC_SECP_R1_256 */

#ifdef PSA_WANT_ECC_MONTGOMERY_255
/* X25519 private keys are clamped, so any 32 bytes are valid */
static void check_x25519(void)
{
    uint8_t d[32];

    memset(d, 0xff, sizeof(d));
    check_import(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 0, d,
                 sizeof(d), PSA_SUCCESS, 255, "X25519 key pair, all 0xff");
}
#endif /* PSA_WANT_ECC_MONTGOMERY_255 */

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

#ifdef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
    check_rsa();
#endif
#ifdef PSA_WANT_ECC_SECP_R1_256
    check_ecc();
#endif
#ifdef PSA_WANT_ECC_MONTGOMERY_255
    check_x25519();
#endif

    if (failures == 0) {
        printf("Import key data tests: all passed\n");
        return 0;
    }
    printf("Import key data tests: %d failure(s)\n", failures);
    return 1;
}
