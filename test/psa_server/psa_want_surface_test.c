/* psa_want_surface_test.c
 *
 * The PSA_WANT_* and MBEDTLS_*_C macros seen through psa/crypto.h match what
 * the library supports, and buffers of the *_MAX_SIZE macros are large
 * enough for it.
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

#include <wolfpsa/psa/crypto.h>

#include <stdio.h>
#include <string.h>

/* A macro is defined when its expansion differs from its name */
#define STRINGIFY(m) #m
#define EXPANDED(m) STRINGIFY(m)
#define IS_DEFINED(m) (strcmp(EXPANDED(m), #m) != 0)

#define NOT_CHECKED (-1)
/* A family macro: the library may leave out the parameter set */
#define FAMILY_WANT(defined) ((defined) ? NOT_CHECKED : 0)

struct want_case {
    const char* name;
    psa_key_type_t type;
    size_t bits;
    psa_algorithm_t alg;
    int want;    /* the PSA_WANT_* macros of the type and algorithm */
    int feature; /* the MBEDTLS_*_C macros, or NOT_CHECKED */
};

static int failures;

static psa_status_t run_export(psa_key_id_t key)
{
    uint8_t pub[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    uint8_t pair[PSA_EXPORT_KEY_PAIR_MAX_SIZE];
    size_t len = 0;
    psa_status_t status;

    status = psa_export_public_key(key, pub, sizeof(pub), &len);
    if (status == PSA_SUCCESS) {
        status = psa_export_key(key, pair, sizeof(pair), &len);
    }
    return status;
}

static psa_status_t run_ecdh(psa_key_id_t key)
{
    uint8_t pub[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    uint8_t secret[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE];
    size_t pubLen = 0;
    size_t len = 0;
    psa_status_t status;

    status = run_export(key);
    if (status == PSA_SUCCESS) {
        status = psa_export_public_key(key, pub, sizeof(pub), &pubLen);
    }
    if (status == PSA_SUCCESS) {
        status = psa_raw_key_agreement(PSA_ALG_ECDH, key, pub, pubLen, secret,
            sizeof(secret), &len);
    }
    return status;
}

static psa_status_t run_aead(psa_key_id_t key, psa_key_type_t type,
    psa_algorithm_t alg)
{
    uint8_t nonce[PSA_AEAD_NONCE_MAX_SIZE];
    uint8_t msg[16];
    uint8_t out[PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(sizeof(msg))];
    size_t len = 0;

    memset(nonce, 0, sizeof(nonce));
    memset(msg, 0, sizeof(msg));
    return psa_aead_encrypt(key, alg, nonce, PSA_AEAD_NONCE_LENGTH(type, alg),
        NULL, 0, msg, sizeof(msg), out, sizeof(out), &len);
}

static psa_status_t run_mac(psa_key_id_t key, psa_algorithm_t alg)
{
    uint8_t msg[16];
    uint8_t mac[PSA_MAC_MAX_SIZE];
    size_t len = 0;

    memset(msg, 0, sizeof(msg));
    return psa_mac_compute(key, alg, msg, sizeof(msg), mac, sizeof(mac), &len);
}

/* Returns PSA_SUCCESS, or PSA_ERROR_NOT_SUPPORTED when the library does not
 * support the case */
static psa_status_t run_case(const struct want_case* c)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t status;

    psa_set_key_type(&attr, c->type);
    psa_set_key_bits(&attr, c->bits);
    psa_set_key_algorithm(&attr, c->alg);
    if (PSA_ALG_IS_KEY_AGREEMENT(c->alg)) {
        psa_set_key_usage_flags(&attr,
            PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    }
    else if (PSA_ALG_IS_AEAD(c->alg)) {
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    }
    else if (PSA_ALG_IS_MAC(c->alg)) {
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    }
    else {
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    }

    status = psa_generate_key(&attr, &key);
    if (status == PSA_SUCCESS) {
        if (PSA_ALG_IS_KEY_AGREEMENT(c->alg)) {
            status = run_ecdh(key);
        }
        else if (PSA_ALG_IS_AEAD(c->alg)) {
            status = run_aead(key, c->type, c->alg);
        }
        else if (PSA_ALG_IS_MAC(c->alg)) {
            status = run_mac(key, c->alg);
        }
        else {
            status = run_export(key);
        }
        (void)psa_destroy_key(key);
    }
    return status;
}

static void check_case(const struct want_case* c)
{
    psa_status_t status = run_case(c);
    int supported = (status == PSA_SUCCESS);

    if (status != PSA_SUCCESS && status != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL %s: status %d\n", c->name, (int)status);
        failures++;
    }
    else if (c->want != NOT_CHECKED && supported != c->want) {
        printf("FAIL %s: supported %d, PSA_WANT_ macros %d\n", c->name,
            supported, c->want);
        failures++;
    }
    else if (c->feature != NOT_CHECKED && supported != c->feature) {
        printf("FAIL %s: supported %d, MBEDTLS_*_C macros %d\n", c->name,
            supported, c->feature);
        failures++;
    }
    else {
        printf("ok %s: supported %d\n", c->name, supported);
    }
}

int main(void)
{
    const psa_key_type_t ecc =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    const psa_key_type_t mont =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
    const psa_key_type_t ed =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS);
    const int ecdh = IS_DEFINED(PSA_WANT_ALG_ECDH) &&
        IS_DEFINED(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE);
    const int eddsa = IS_DEFINED(PSA_WANT_ALG_PURE_EDDSA) &&
        IS_DEFINED(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE);
    const int aes = IS_DEFINED(PSA_WANT_KEY_TYPE_AES);
    const int aesC = IS_DEFINED(MBEDTLS_AES_C);
    const struct want_case cases[] = {
        { "secp256r1 ECDH", ecc, 256, PSA_ALG_ECDH,
            ecdh && IS_DEFINED(PSA_WANT_ECC_SECP_R1_256), NOT_CHECKED },
        { "secp384r1 ECDH", ecc, 384, PSA_ALG_ECDH,
            ecdh && IS_DEFINED(PSA_WANT_ECC_SECP_R1_384), NOT_CHECKED },
        { "secp521r1 ECDH", ecc, 521, PSA_ALG_ECDH,
            ecdh && IS_DEFINED(PSA_WANT_ECC_SECP_R1_521), NOT_CHECKED },
        { "X25519", mont, 255, PSA_ALG_ECDH,
            ecdh && IS_DEFINED(PSA_WANT_ECC_MONTGOMERY_255), NOT_CHECKED },
        { "X448", mont, 448, PSA_ALG_ECDH,
            ecdh && IS_DEFINED(PSA_WANT_ECC_MONTGOMERY_448), NOT_CHECKED },
        { "Ed25519 export", ed, 255, PSA_ALG_PURE_EDDSA,
            eddsa && IS_DEFINED(PSA_WANT_ECC_TWISTED_EDWARDS_255),
            NOT_CHECKED },
        { "Ed448 export", ed, 448, PSA_ALG_PURE_EDDSA,
            eddsa && IS_DEFINED(PSA_WANT_ECC_TWISTED_EDWARDS_448),
            NOT_CHECKED },
        { "AES-128-GCM", PSA_KEY_TYPE_AES, 128, PSA_ALG_GCM,
            aes && IS_DEFINED(PSA_WANT_ALG_GCM),
            aesC && IS_DEFINED(MBEDTLS_GCM_C) },
        { "AES-128-CCM", PSA_KEY_TYPE_AES, 128, PSA_ALG_CCM,
            aes && IS_DEFINED(PSA_WANT_ALG_CCM),
            aesC && IS_DEFINED(MBEDTLS_CCM_C) },
        { "ChaCha20-Poly1305", PSA_KEY_TYPE_CHACHA20, 256,
            PSA_ALG_CHACHA20_POLY1305,
            IS_DEFINED(PSA_WANT_KEY_TYPE_CHACHA20) &&
                IS_DEFINED(PSA_WANT_ALG_CHACHA20_POLY1305),
            IS_DEFINED(MBEDTLS_CHACHAPOLY_C) },
        { "HMAC-SHA-256", PSA_KEY_TYPE_HMAC, 256,
            PSA_ALG_HMAC(PSA_ALG_SHA_256),
            IS_DEFINED(PSA_WANT_KEY_TYPE_HMAC) &&
                IS_DEFINED(PSA_WANT_ALG_HMAC), NOT_CHECKED },
        { "ML-KEM-1024 export", PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 1024,
            PSA_ALG_ML_KEM, FAMILY_WANT(IS_DEFINED(PSA_WANT_KEY_TYPE_ML_KEM)),
            NOT_CHECKED },
        { "ML-DSA-87 export", PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 256,
            PSA_ALG_ML_DSA, FAMILY_WANT(IS_DEFINED(PSA_WANT_KEY_TYPE_ML_DSA)),
            NOT_CHECKED },
    };
    size_t i;
    psa_status_t status;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status %d\n", (int)status);
        return 1;
    }

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_case(&cases[i]);
    }

    mbedtls_psa_crypto_free();

    if (failures != 0) {
        printf("PSA_WANT surface test: FAIL (%d)\n", failures);
        return 1;
    }
    printf("PSA_WANT surface test: OK\n");
    return 0;
}
