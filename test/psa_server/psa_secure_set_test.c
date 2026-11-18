/* psa_secure_set_test.c
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

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

#ifndef NO_ASN
#error "build this test against test/secure-set/user_settings.h"
#endif

static int g_failures;

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

/* RFC 6979 A.2.5: P-256, SHA-256, message "sample". */
static const uint8_t k_6979_priv[32] = {
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57,
    0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
    0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
};
static const uint8_t k_6979_sig[64] = {
    0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C,
    0xD4, 0x5E, 0x81, 0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
    0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
    0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1,
    0xB6, 0xE2, 0x9F, 0x65, 0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
    0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8
};

static psa_key_id_t ecc_key(psa_algorithm_t alg, const uint8_t *priv)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, alg);
    if (priv != NULL) {
        st = psa_import_key(&attr, priv, 32, &id);
    }
    else {
        st = psa_generate_key(&attr, &id);
    }
    return (st == PSA_SUCCESS) ? id : PSA_KEY_ID_NULL;
}

static void test_ecdsa_raw(void)
{
    const psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    const psa_algorithm_t det = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    uint8_t hash[32];
    uint8_t sig[72];
    uint8_t sig2[72];
    psa_key_id_t k;
    size_t len = 0;
    size_t len2 = 0;
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)"sample", 6, hash,
                          sizeof(hash), &len);
    check(st == PSA_SUCCESS, "hash the RFC 6979 message");

    k = ecc_key(alg, NULL);
    check(k != PSA_KEY_ID_NULL, "generate P-256 key");
    st = psa_sign_hash(k, alg, hash, sizeof(hash), sig, sizeof(sig), &len);
    check(st == PSA_SUCCESS && len == 64, "sign writes fixed-width r||s");
    check(psa_verify_hash(k, alg, hash, sizeof(hash), sig, len) ==
          PSA_SUCCESS, "verify the raw signature");
    sig[10] ^= 1;
    check(psa_verify_hash(k, alg, hash, sizeof(hash), sig, len) ==
          PSA_ERROR_INVALID_SIGNATURE, "tampered signature rejected");
    sig[10] ^= 1;
    check(psa_verify_hash(k, alg, hash, sizeof(hash), sig, 63) ==
          PSA_ERROR_INVALID_SIGNATURE, "short signature rejected");
    check(psa_verify_hash(k, alg, hash, sizeof(hash), sig, 65) ==
          PSA_ERROR_INVALID_SIGNATURE, "long signature rejected");
    check(psa_sign_hash(k, alg, hash, sizeof(hash), sig, 63, &len) ==
          PSA_ERROR_BUFFER_TOO_SMALL, "sign into a short buffer refused");
    (void)psa_destroy_key(k);

    k = ecc_key(det, k_6979_priv);
    check(k != PSA_KEY_ID_NULL, "import the RFC 6979 key");
    st = psa_sign_hash(k, det, hash, sizeof(hash), sig, sizeof(sig), &len);
    check(st == PSA_SUCCESS && len == 64 &&
          memcmp(sig, k_6979_sig, sizeof(k_6979_sig)) == 0,
          "deterministic ECDSA matches RFC 6979 A.2.5");
    st = psa_sign_hash(k, det, hash, sizeof(hash), sig2, sizeof(sig2), &len2);
    check(st == PSA_SUCCESS && len2 == len && memcmp(sig, sig2, len) == 0,
          "deterministic ECDSA repeats");
    check(psa_verify_hash(k, det, hash, sizeof(hash), k_6979_sig, 64) ==
          PSA_SUCCESS, "verify the RFC 6979 signature");
    (void)psa_destroy_key(k);
}

static psa_status_t import_type(psa_key_type_t type, size_t bits)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    uint8_t data[64];
    psa_status_t st;

    memset(data, 0x42, sizeof(data));
    psa_set_key_type(&attr, type);
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    st = psa_import_key(&attr, data,
                        (bits != 0 && bits / 8 <= sizeof(data)) ? bits / 8 : 32,
                        &id);
    if (id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(id);
    }
    return st;
}

static void test_import_families_off(void)
{
    check(import_type(PSA_KEY_TYPE_CHACHA20, 256) == PSA_ERROR_NOT_SUPPORTED,
          "ChaCha20 import refused without HAVE_CHACHA");
    check(import_type(PSA_KEY_TYPE_DES, 192) == PSA_ERROR_NOT_SUPPORTED,
          "DES import refused under NO_DES3");
    check(import_type(PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY, 0) ==
          PSA_ERROR_NOT_SUPPORTED, "ML-DSA import refused");
    check(import_type(PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY, 0) ==
          PSA_ERROR_NOT_SUPPORTED, "ML-KEM import refused");
    check(import_type(PSA_KEY_TYPE_LMS_PUBLIC_KEY, 0) ==
          PSA_ERROR_NOT_SUPPORTED, "LMS import refused");
    check(import_type(PSA_KEY_TYPE_XMSS_PUBLIC_KEY, 0) ==
          PSA_ERROR_NOT_SUPPORTED, "XMSS import refused");
    check(import_type(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 0) ==
          PSA_ERROR_NOT_SUPPORTED, "RSA public key import refused under NO_RSA");
    check(import_type(PSA_KEY_TYPE_RSA_KEY_PAIR, 0) ==
          PSA_ERROR_NOT_SUPPORTED, "RSA key pair import refused under NO_RSA");
    check(import_type(PSA_KEY_TYPE_RSA_PUBLIC_KEY, 2048) ==
          PSA_ERROR_NOT_SUPPORTED, "RSA import with declared bits refused");
    check(import_type(PSA_KEY_TYPE_AES, 128) == PSA_SUCCESS,
          "AES import still accepted");
}

static psa_status_t import_p256_pub(const uint8_t* data, size_t len,
                                    size_t bits)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    st = psa_import_key(&attr, data, len, &id);
    if (id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(id);
    }
    return st;
}

static const uint8_t p256_n[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};

static psa_status_t import_p256_priv(const uint8_t* scalar)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    st = psa_import_key(&attr, scalar, 32, &id);
    if (id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(id);
    }
    return st;
}

/* The family guards must leave the ECC import checks in a build with
 * neither LMS nor XMSS. */
static void test_import_ecc_checked(void)
{
    uint8_t point[65];

    memset(point, 0x42, sizeof(point));
    point[0] = 0x05;
    check(import_p256_pub(point, sizeof(point), 256) ==
          PSA_ERROR_INVALID_ARGUMENT, "P-256 point without 0x04 refused");
    point[0] = 0x04;
    check(import_p256_pub(point, sizeof(point) - 1, 256) ==
          PSA_ERROR_INVALID_ARGUMENT, "P-256 point of even length refused");
    check(import_p256_pub(point, sizeof(point), 384) ==
          PSA_ERROR_INVALID_ARGUMENT, "P-256 point declared as 384 bits refused");
    check(import_p256_pub(point, sizeof(point), 256) ==
          PSA_ERROR_INVALID_ARGUMENT, "P-256 point off the curve refused");
    memset(point, 0, 32);
    check(import_p256_priv(point) == PSA_ERROR_INVALID_ARGUMENT,
          "P-256 zero scalar refused");
    check(import_p256_priv(p256_n) == PSA_ERROR_INVALID_ARGUMENT,
          "P-256 scalar equal to n refused");
}

#define MSG 40
#define AAD 13
#define TAG 16

/* Seal and open with the output placed against the inputs at each offset. */
static void aead_overlap(psa_algorithm_t alg, const char *name)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t pt[MSG];
    uint8_t aad[AAD];
    uint8_t ref[MSG + TAG];
    uint8_t buf[MSG + TAG + 32];
    char what[96];
    psa_key_id_t k = PSA_KEY_ID_NULL;
    size_t nlen = sizeof(nonce);
    size_t len = 0;
    size_t i;
    int ok;
    int shift;

    memset(key, 0x21, sizeof(key));
    memset(nonce, 0x07, sizeof(nonce));
    for (i = 0; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i * 3 + 1);
    }
    for (i = 0; i < sizeof(aad); i++) {
        aad[i] = (uint8_t)(0xA0 + i);
    }
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);
    ok = psa_import_key(&attr, key, sizeof(key), &k) == PSA_SUCCESS &&
         psa_aead_encrypt(k, alg, nonce, nlen, aad, sizeof(aad), pt,
                          sizeof(pt), ref, sizeof(ref), &len) == PSA_SUCCESS &&
         len == sizeof(ref);
    snprintf(what, sizeof(what), "%s disjoint reference", name);
    check(ok, what);

    for (shift = -8; shift <= 8; shift += 4) {
        size_t in_off = 16 + (size_t)(shift < 0 ? 0 : shift);
        size_t out_off = 16 + (size_t)(shift < 0 ? -shift : 0);

        memset(buf, 0, sizeof(buf));
        memcpy(buf + in_off, pt, sizeof(pt));
        ok = psa_aead_encrypt(k, alg, nonce, nlen, aad, sizeof(aad),
                              buf + in_off, sizeof(pt), buf + out_off,
                              sizeof(ref), &len) == PSA_SUCCESS &&
             len == sizeof(ref) && memcmp(buf + out_off, ref, len) == 0;
        snprintf(what, sizeof(what), "%s seal, output %+d bytes from input",
                 name, -shift);
        check(ok, what);

        memset(buf, 0, sizeof(buf));
        memcpy(buf + in_off, ref, sizeof(ref));
        ok = psa_aead_decrypt(k, alg, nonce, nlen, aad, sizeof(aad),
                              buf + in_off, sizeof(ref), buf + out_off,
                              sizeof(pt), &len) == PSA_SUCCESS &&
             len == sizeof(pt) && memcmp(buf + out_off, pt, len) == 0;
        snprintf(what, sizeof(what), "%s open, output %+d bytes from input",
                 name, -shift);
        check(ok, what);
    }

    memset(buf, 0, sizeof(buf));
    memcpy(buf, aad, sizeof(aad));
    memcpy(buf + 32, pt, sizeof(pt));
    ok = psa_aead_encrypt(k, alg, nonce, nlen, buf, sizeof(aad), buf + 32,
                          sizeof(pt), buf + 4, sizeof(ref) + 20, &len) ==
         PSA_SUCCESS && len == sizeof(ref) &&
         memcmp(buf + 4, ref, len) == 0;
    snprintf(what, sizeof(what), "%s seal, output over the AAD", name);
    check(ok, what);
    snprintf(what, sizeof(what), "%s open refuses a NULL ciphertext", name);
    check(psa_aead_decrypt(k, alg, nonce, nlen, aad, sizeof(aad), NULL,
                           sizeof(ref), buf, sizeof(buf), &len) ==
          PSA_ERROR_INVALID_ARGUMENT, what);
    (void)psa_destroy_key(k);
}

static const uint8_t k_hkdf_ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const uint8_t k_hkdf_salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c
};
static const uint8_t k_hkdf_info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

static psa_status_t hkdf_start(psa_key_derivation_operation_t *op,
                               psa_algorithm_t alg, const uint8_t *secret,
                               size_t secret_len)
{
    psa_status_t st = psa_key_derivation_setup(op, alg);

    if (st == PSA_SUCCESS && PSA_ALG_IS_HKDF(alg)) {
        st = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            k_hkdf_salt, sizeof(k_hkdf_salt));
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(op,
                                            PSA_KEY_DERIVATION_INPUT_SECRET,
                                            secret, secret_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            k_hkdf_info, sizeof(k_hkdf_info));
    }
    return st;
}

/* Reads the whole 255-block stream in uneven chunks and compares wolfCrypt. */
static void hkdf_stream(psa_algorithm_t alg, const char *name)
{
    static uint8_t ref[255 * 32];
    static uint8_t out[255 * 32];
    static const size_t chunks[] = { 1, 15, 26, 32, 33, 64, 100 };
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t prk[32];
    uint8_t extra;
    char what[96];
    size_t done = 0;
    size_t n;
    size_t i = 0;
    psa_status_t st;
    int ret;

    ret = wc_HKDF_Extract(WC_SHA256, k_hkdf_salt, sizeof(k_hkdf_salt),
                          k_hkdf_ikm, sizeof(k_hkdf_ikm), prk);
    if (ret == 0) {
        ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), k_hkdf_info,
                             sizeof(k_hkdf_info), ref, sizeof(ref));
    }
    snprintf(what, sizeof(what), "%s wolfCrypt reference", name);
    check(ret == 0, what);

    if (PSA_ALG_IS_HKDF(alg)) {
        st = hkdf_start(&op, alg, k_hkdf_ikm, sizeof(k_hkdf_ikm));
    }
    else {
        st = hkdf_start(&op, alg, prk, sizeof(prk));
    }
    while (st == PSA_SUCCESS && done < sizeof(out)) {
        n = chunks[i++ % (sizeof(chunks) / sizeof(chunks[0]))];
        if (n > sizeof(out) - done) {
            n = sizeof(out) - done;
        }
        st = psa_key_derivation_output_bytes(&op, out + done, n);
        done += n;
    }
    snprintf(what, sizeof(what), "%s streams 255 blocks equal to wolfCrypt",
             name);
    check(st == PSA_SUCCESS && memcmp(out, ref, sizeof(ref)) == 0, what);
    snprintf(what, sizeof(what), "%s refuses output past 255 blocks", name);
    check(psa_key_derivation_output_bytes(&op, &extra, 1) ==
          PSA_ERROR_INSUFFICIENT_DATA, what);
    (void)psa_key_derivation_abort(&op);
}

/* Multipart GCM with its AAD in pieces matches the one-shot, and the streamed
 * AAD leaves no buffered mode for a later update with no output. */
static void aead_stream_aad(void)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[600];
    uint8_t pt[100];
    uint8_t ref[sizeof(pt) + TAG];
    uint8_t ct[sizeof(pt) + TAG];
    uint8_t out[sizeof(pt)];
    psa_key_id_t k = PSA_KEY_ID_NULL;
    size_t len = 0;
    size_t got = 0;
    size_t tag_len = 0;
    size_t i;
    int ok;

    memset(key, 0x33, sizeof(key));
    memset(nonce, 0x09, sizeof(nonce));
    for (i = 0; i < sizeof(aad); i++) {
        aad[i] = (uint8_t)(i * 5 + 3);
    }
    for (i = 0; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i + 0x40);
    }
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    ok = psa_import_key(&attr, key, sizeof(key), &k) == PSA_SUCCESS &&
         psa_aead_encrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce), aad,
                          sizeof(aad), pt, sizeof(pt), ref, sizeof(ref),
                          &len) == PSA_SUCCESS && len == sizeof(ref);
    check(ok, "GCM one-shot reference with a 600-byte AAD");

    ok = psa_aead_encrypt_setup(&op, k, PSA_ALG_GCM) == PSA_SUCCESS &&
         psa_aead_set_nonce(&op, nonce, sizeof(nonce)) == PSA_SUCCESS &&
         psa_aead_update_ad(&op, aad, 7) == PSA_SUCCESS &&
         psa_aead_update_ad(&op, aad + 7, 300) == PSA_SUCCESS &&
         psa_aead_update_ad(&op, aad + 307, sizeof(aad) - 307) ==
         PSA_SUCCESS &&
         psa_aead_update(&op, pt, sizeof(pt), ct, sizeof(ct), &got) ==
         PSA_SUCCESS && got == sizeof(pt) &&
         psa_aead_finish(&op, NULL, 0, &len, ct + got, TAG, &tag_len) ==
         PSA_SUCCESS && tag_len == TAG && memcmp(ct, ref, sizeof(ref)) == 0;
    check(ok, "GCM multipart AAD in three pieces matches the one-shot");
    (void)psa_aead_abort(&op);

    ok = psa_aead_decrypt_setup(&op, k, PSA_ALG_GCM) == PSA_SUCCESS &&
         psa_aead_set_nonce(&op, nonce, sizeof(nonce)) == PSA_SUCCESS &&
         psa_aead_update_ad(&op, aad, 301) == PSA_SUCCESS &&
         psa_aead_update_ad(&op, aad + 301, sizeof(aad) - 301) ==
         PSA_SUCCESS &&
         psa_aead_update(&op, ref, sizeof(pt), out, sizeof(out), &got) ==
         PSA_SUCCESS && got == sizeof(pt) &&
         psa_aead_verify(&op, NULL, 0, &len, ref + sizeof(pt), TAG) ==
         PSA_SUCCESS && memcmp(out, pt, sizeof(pt)) == 0;
    check(ok, "GCM multipart decrypt with streamed AAD verifies");
    (void)psa_aead_abort(&op);

    ok = psa_aead_encrypt_setup(&op, k, PSA_ALG_GCM) == PSA_SUCCESS &&
         psa_aead_set_nonce(&op, nonce, sizeof(nonce)) == PSA_SUCCESS &&
         psa_aead_update_ad(&op, aad, 16) == PSA_SUCCESS &&
         psa_aead_update(&op, pt, sizeof(pt), NULL, 0, &got) != PSA_SUCCESS;
    check(ok, "an update with no output after streamed AAD is refused");
    (void)psa_aead_abort(&op);
    (void)psa_destroy_key(k);
}

int main(void)
{
    check(psa_crypto_init() == PSA_SUCCESS, "psa_crypto_init");
    test_ecdsa_raw();
    test_import_families_off();
    test_import_ecc_checked();
    aead_overlap(PSA_ALG_GCM, "GCM");
    aead_overlap(PSA_ALG_CCM, "CCM");
    aead_stream_aad();
    hkdf_stream(PSA_ALG_HKDF(PSA_ALG_SHA_256), "HKDF");
    hkdf_stream(PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256), "HKDF-Expand");
    printf("%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
