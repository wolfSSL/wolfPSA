/* psa_ecc_direct_test.c
 *
 * Runs against a library built from test/secure-set/user_settings.h: raw
 * r||s ECDSA under NO_ASN, refused imports of compiled-out key families,
 * borrowed one-shot AEAD with overlapping buffers, streamed multipart GCM
 * AAD, and streamed HKDF.
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

/* P-256 through PSA, run against the generic ecc.c build (test/secure-set) and
 * the WOLFPSA_ECC_SP_DIRECT build (test/ecc-direct): both must answer alike. */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#ifndef NO_ASN
#error "build this test against test/secure-set or test/ecc-direct"
#endif

#define P256_ALG PSA_ALG_ECDSA(PSA_ALG_SHA_256)
#define P256_PAIR PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)
#define P256_PUB PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)

static int g_failures;

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

/* RFC 6979 A.2.5: P-256 key, and its SHA-256 "sample" signature. */
static const uint8_t k_priv[32] = {
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57,
    0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
    0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
};
static const uint8_t k_pub[65] = {
    0x04,
    0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74,
    0xC6, 0x35, 0x6D, 0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
    0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
    0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9,
    0x56, 0x28, 0xBC, 0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
    0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99
};
static const uint8_t k_sig[64] = {
    0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C,
    0xD4, 0x5E, 0x81, 0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
    0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
    0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1,
    0xB6, 0xE2, 0x9F, 0x65, 0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
    0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8
};
static const uint8_t k_n[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};
static const uint8_t k_p[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* (0, y0) is on P-256, so (p, y0) is the same point with a non-canonical x. */
static const uint8_t k_y0[32] = {
    0x66, 0x48, 0x5C, 0x78, 0x0E, 0x2F, 0x83, 0xD7, 0x24, 0x33, 0xBD, 0x5D,
    0x84, 0xA0, 0x6B, 0xB6, 0x54, 0x1C, 0x2A, 0xF3, 0x1D, 0xAE, 0x87, 0x17,
    0x28, 0xBF, 0x85, 0x6A, 0x17, 0x4F, 0x93, 0xF4
};

static void point_x0(uint8_t *pt, const uint8_t *x)
{
    pt[0] = 0x04;
    if (x != NULL) {
        memcpy(pt + 1, x, 32);
    }
    else {
        memset(pt + 1, 0, 32);
    }
    memcpy(pt + 33, k_y0, 32);
}

static psa_status_t import(psa_key_type_t type, const uint8_t *data,
                           size_t len, psa_key_usage_t usage,
                           psa_algorithm_t alg, psa_key_id_t *id)
{
    psa_key_attributes_t attr = psa_key_attributes_init();

    *id = PSA_KEY_ID_NULL;
    psa_set_key_type(&attr, type);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);
    return psa_import_key(&attr, data, len, id);
}

static psa_status_t import_once(psa_key_type_t type, const uint8_t *data,
                                size_t len)
{
    psa_key_id_t id;
    psa_status_t st = import(type, data, len, PSA_KEY_USAGE_VERIFY_HASH,
                             P256_ALG, &id);

    if (id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(id);
    }
    return st;
}

static psa_status_t verify_pub(const uint8_t *pub, const uint8_t *hash,
                               const uint8_t *sig)
{
    psa_key_id_t id;
    psa_status_t st = import(P256_PUB, pub, 65, PSA_KEY_USAGE_VERIFY_HASH,
                             P256_ALG, &id);

    if (st == PSA_SUCCESS) {
        st = psa_verify_hash(id, P256_ALG, hash, 32, sig, 64);
    }
    if (id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(id);
    }
    return st;
}

static void test_known_answer(const uint8_t *hash)
{
    psa_key_id_t id;
    uint8_t pub[65];
    size_t len = 0;

    check(import(P256_PAIR, k_priv, sizeof(k_priv), PSA_KEY_USAGE_EXPORT |
                 PSA_KEY_USAGE_VERIFY_HASH, P256_ALG, &id) == PSA_SUCCESS,
          "import the RFC 6979 private key");
    check(psa_export_public_key(id, pub, sizeof(pub), &len) == PSA_SUCCESS &&
          len == sizeof(k_pub) && memcmp(pub, k_pub, len) == 0,
          "public key of the RFC 6979 scalar matches A.2.5");
    check(psa_export_public_key(id, pub, sizeof(pub) - 1, &len) ==
          PSA_ERROR_BUFFER_TOO_SMALL, "public export into 64 bytes refused");
    check(psa_verify_hash(id, P256_ALG, hash, 32, k_sig, 64) == PSA_SUCCESS,
          "key pair verifies the RFC 6979 signature");
    (void)psa_destroy_key(id);
    check(verify_pub(k_pub, hash, k_sig) == PSA_SUCCESS,
          "public key verifies the RFC 6979 signature");
}

/* r or s of 0 or n would let sp_ecc_verify_256 accept a forgery. */
static void test_signature_range(const uint8_t *hash)
{
    uint8_t sig[64];

    memset(sig, 0, sizeof(sig));
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "r = s = 0 rejected");
    memcpy(sig, k_sig, sizeof(sig));
    memset(sig, 0, 32);
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "r = 0 rejected");
    memcpy(sig, k_sig, sizeof(sig));
    memset(sig + 32, 0, 32);
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "s = 0 rejected");
    memcpy(sig, k_n, 32);
    memcpy(sig + 32, k_sig + 32, 32);
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "r = n rejected");
    memcpy(sig, k_sig, 32);
    memcpy(sig + 32, k_n, 32);
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "s = n rejected");
    memset(sig, 0xFF, sizeof(sig));
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "r = s = 2^256 - 1 rejected");
    memcpy(sig, k_sig, sizeof(sig));
    sig[63] ^= 1;
    check(verify_pub(k_pub, hash, sig) == PSA_ERROR_INVALID_SIGNATURE,
          "flipped s rejected");
}

static void test_key_import(void)
{
    uint8_t d[32];
    uint8_t pt[65];

    memset(d, 0, sizeof(d));
    check(import_once(P256_PAIR, d, 32) == PSA_ERROR_INVALID_ARGUMENT,
          "scalar 0 refused");
    check(import_once(P256_PAIR, k_n, 32) == PSA_ERROR_INVALID_ARGUMENT,
          "scalar n refused");
    memset(d, 0xFF, sizeof(d));
    check(import_once(P256_PAIR, d, 32) == PSA_ERROR_INVALID_ARGUMENT,
          "scalar 2^256 - 1 refused");
    memcpy(d, k_n, sizeof(d));
    d[31] -= 1;
    check(import_once(P256_PAIR, d, 32) == PSA_SUCCESS, "scalar n - 1 accepted");
    memset(d, 0, sizeof(d));
    d[31] = 1;
    check(import_once(P256_PAIR, d, 32) == PSA_SUCCESS, "scalar 1 accepted");
    check(import_once(P256_PAIR, k_priv, 31) == PSA_ERROR_INVALID_ARGUMENT,
          "31-byte scalar refused");

    check(import_once(P256_PUB, k_pub, sizeof(k_pub)) == PSA_SUCCESS,
          "RFC 6979 point accepted");
    memcpy(pt, k_pub, sizeof(pt));
    pt[0] = 0x02;
    check(import_once(P256_PUB, pt, sizeof(pt)) == PSA_ERROR_INVALID_ARGUMENT,
          "point with prefix 0x02 refused");
    memcpy(pt, k_pub, sizeof(pt));
    pt[64] ^= 1;
    check(import_once(P256_PUB, pt, sizeof(pt)) == PSA_ERROR_INVALID_ARGUMENT,
          "point off the curve refused");
    memset(pt, 0, sizeof(pt));
    pt[0] = 0x04;
    check(import_once(P256_PUB, pt, sizeof(pt)) == PSA_ERROR_INVALID_ARGUMENT,
          "point (0, 0) refused");
    point_x0(pt, NULL);
    check(import_once(P256_PUB, pt, sizeof(pt)) == PSA_SUCCESS,
          "point (0, y0) accepted");
    point_x0(pt, k_p);
    check(import_once(P256_PUB, pt, sizeof(pt)) == PSA_ERROR_INVALID_ARGUMENT,
          "point (0, y0) written with x = p refused");
    memcpy(pt, k_pub, sizeof(pt));
    memcpy(pt + 33, k_p, 32);
    check(import_once(P256_PUB, pt, sizeof(pt)) == PSA_ERROR_INVALID_ARGUMENT,
          "point with y = p refused");
}

/* PSA signs and wolfCrypt verifies, then the other way round. */
static void test_sign_cross(const uint8_t *hash)
{
    ecc_key key;
    WC_RNG rng;
    psa_key_id_t id;
    uint8_t sig[64];
    word32 sig_len = sizeof(sig);
    size_t len = 0;
    int res = 0;
    int ok;

    ok = import(P256_PAIR, k_priv, sizeof(k_priv), PSA_KEY_USAGE_SIGN_HASH |
                PSA_KEY_USAGE_VERIFY_HASH, P256_ALG, &id) == PSA_SUCCESS &&
         psa_sign_hash(id, P256_ALG, hash, 32, sig, sizeof(sig), &len) ==
         PSA_SUCCESS && len == sizeof(sig);
    check(ok, "PSA signs with the RFC 6979 key");
    ok = ok && wc_ecc_init(&key) == 0 &&
         wc_ecc_import_x963_ex(k_pub, sizeof(k_pub), &key,
                               ECC_SECP256R1) == 0 &&
         wc_ecc_verify_hash(sig, sizeof(sig), hash, 32, &res, &key) == 0 &&
         res == 1;
    wc_ecc_free(&key);
    check(ok, "wolfCrypt verifies the PSA signature");

    ok = wc_InitRng(&rng) == 0 && wc_ecc_init(&key) == 0 &&
         wc_ecc_import_private_key_ex(k_priv, sizeof(k_priv), NULL, 0, &key,
                                      ECC_SECP256R1) == 0 &&
         wc_ecc_sign_hash(hash, 32, sig, &sig_len, &rng, &key) == 0 &&
         sig_len == sizeof(sig);
    wc_ecc_free(&key);
    (void)wc_FreeRng(&rng);
    check(ok && psa_verify_hash(id, P256_ALG, hash, 32, sig, sizeof(sig)) ==
          PSA_SUCCESS, "PSA verifies the wolfCrypt signature");
    (void)psa_destroy_key(id);

    check(psa_sign_hash(PSA_KEY_ID_NULL, P256_ALG, hash, 32, sig, sizeof(sig),
                        &len) != PSA_SUCCESS, "sign with no key refused");
    ok = import(P256_PAIR, k_priv, sizeof(k_priv), PSA_KEY_USAGE_SIGN_HASH,
                PSA_ALG_ECDSA(PSA_ALG_SHA_256), &id) == PSA_SUCCESS;
    check(ok && psa_sign_hash(id, P256_ALG, hash, 32, sig, 63, &len) ==
          PSA_ERROR_BUFFER_TOO_SMALL, "sign into 63 bytes refused");
    (void)psa_destroy_key(id);
}

/* ECDH: PSA against wolfCrypt for the same pair, then off-curve peers. */
static void test_ecdh(void)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t a = PSA_KEY_ID_NULL;
    ecc_key priv;
    ecc_key peer;
    WC_RNG rng;
    uint8_t peer_pub[65];
    uint8_t z[32];
    uint8_t ref[32];
    uint8_t bad[65];
    word32 peer_len = sizeof(peer_pub);
    word32 ref_len = sizeof(ref);
    size_t len = 0;
    int ok;

    ok = wc_InitRng(&rng) == 0 && wc_ecc_init(&peer) == 0 &&
         wc_ecc_make_key_ex(&rng, 32, &peer, ECC_SECP256R1) == 0 &&
         wc_ecc_export_x963(&peer, peer_pub, &peer_len) == 0;
    check(ok, "wolfCrypt peer key");

    psa_set_key_type(&attr, P256_PAIR);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    ok = psa_import_key(&attr, k_priv, sizeof(k_priv), &a) == PSA_SUCCESS &&
         psa_raw_key_agreement(PSA_ALG_ECDH, a, peer_pub, sizeof(peer_pub), z,
                               sizeof(z), &len) == PSA_SUCCESS &&
         len == sizeof(z);
    check(ok, "PSA ECDH with the wolfCrypt peer");

    ok = wc_ecc_init(&priv) == 0 &&
         wc_ecc_import_private_key_ex(k_priv, sizeof(k_priv), NULL, 0, &priv,
                                      ECC_SECP256R1) == 0 &&
         wc_ecc_set_rng(&priv, &rng) == 0 &&
         wc_ecc_shared_secret(&priv, &peer, ref, &ref_len) == 0 &&
         ref_len == sizeof(ref) && memcmp(z, ref, sizeof(ref)) == 0;
    check(ok, "PSA ECDH secret equals wolfCrypt's");
    wc_ecc_free(&priv);
    wc_ecc_free(&peer);
    (void)wc_FreeRng(&rng);

    memcpy(bad, peer_pub, sizeof(bad));
    bad[64] ^= 1;
    check(psa_raw_key_agreement(PSA_ALG_ECDH, a, bad, sizeof(bad), z,
                                sizeof(z), &len) != PSA_SUCCESS,
          "ECDH with a peer off the curve refused");
    point_x0(bad, NULL);
    check(psa_raw_key_agreement(PSA_ALG_ECDH, a, bad, sizeof(bad), z,
                                sizeof(z), &len) == PSA_SUCCESS,
          "ECDH with the peer (0, y0) agrees");
    point_x0(bad, k_p);
    check(psa_raw_key_agreement(PSA_ALG_ECDH, a, bad, sizeof(bad), z,
                                sizeof(z), &len) != PSA_SUCCESS,
          "ECDH with (0, y0) written as x = p refused");
    memset(bad, 0, sizeof(bad));
    bad[0] = 0x04;
    check(psa_raw_key_agreement(PSA_ALG_ECDH, a, bad, sizeof(bad), z,
                                sizeof(z), &len) != PSA_SUCCESS,
          "ECDH with the peer (0, 0) refused");
    check(psa_raw_key_agreement(PSA_ALG_ECDH, a, peer_pub, sizeof(peer_pub),
                                z, 31, &len) == PSA_ERROR_BUFFER_TOO_SMALL,
          "ECDH into 31 bytes refused");
    (void)psa_destroy_key(a);
}

static void test_generate(const uint8_t *hash)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    uint8_t pub[65];
    uint8_t sig[64];
    size_t len = 0;
    int ok;

    psa_set_key_type(&attr, P256_PAIR);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, P256_ALG);
    ok = psa_generate_key(&attr, &id) == PSA_SUCCESS &&
         psa_export_public_key(id, pub, sizeof(pub), &len) == PSA_SUCCESS &&
         len == sizeof(pub) && pub[0] == 0x04 &&
         psa_sign_hash(id, P256_ALG, hash, 32, sig, sizeof(sig), &len) ==
         PSA_SUCCESS;
    check(ok, "generated key exports a point and signs");
    check(ok && verify_pub(pub, hash, sig) == PSA_SUCCESS,
          "its exported point verifies the signature");
    (void)psa_destroy_key(id);
}

int main(void)
{
    uint8_t hash[32];
    size_t len = 0;

    check(psa_crypto_init() == PSA_SUCCESS, "psa_crypto_init");
    check(psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)"sample", 6,
                           hash, sizeof(hash), &len) == PSA_SUCCESS,
          "hash the RFC 6979 message");
    test_known_answer(hash);
    test_signature_range(hash);
    test_key_import();
    test_sign_cross(hash);
    test_ecdh();
    test_generate(hash);
    printf("%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
