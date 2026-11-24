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
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfpsa/psa_ccm.h>
#include <wolfpsa/psa_gcm.h>

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

static psa_status_t kdf_setup_status(psa_algorithm_t alg)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st = psa_key_derivation_setup(&op, alg);

    (void)psa_key_derivation_abort(&op);
    return st;
}

static void test_kdf_families_off(void)
{
#ifndef WOLFSSL_HAVE_PRF
    check(kdf_setup_status(PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256)) ==
          PSA_ERROR_NOT_SUPPORTED, "TLS 1.2 PRF refused under NO_KDF");
    check(kdf_setup_status(PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256)) ==
          PSA_ERROR_NOT_SUPPORTED, "TLS 1.2 PSK-to-MS refused under NO_KDF");
#else
    check(0, "secure-set builds without the TLS 1.2 PRF");
#endif
    check(kdf_setup_status(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) ==
          PSA_ERROR_NOT_SUPPORTED, "PBKDF2 refused under NO_PBKDF2");
    check(kdf_setup_status(PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS,
          "HKDF still accepted");
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

        for (i = 0; i < 2; i++) {
            memset(buf, 0, sizeof(buf));
            memcpy(buf + in_off, ref, sizeof(ref));
            buf[in_off + (i == 0 ? sizeof(ref) - 1 : 0)] ^= 0x01;
            ok = psa_aead_decrypt(k, alg, nonce, nlen, aad, sizeof(aad),
                                  buf + in_off, sizeof(ref), buf + out_off,
                                  sizeof(pt), &len) ==
                 PSA_ERROR_INVALID_SIGNATURE;
            snprintf(what, sizeof(what),
                     "%s open refuses a forged %s, output %+d bytes from input",
                     name, i == 0 ? "tag" : "ciphertext", -shift);
            check(ok, what);
        }
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
    memset(out, 0xA5, sizeof(out));

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
/* One-shot and multipart CCM (AD fed in uneven pieces) match wolfCrypt's
 * one-shot CCM across the AD block and length-prefix boundaries. */
static int ccm_parts(psa_key_id_t k, int decrypt, const uint8_t *nonce,
                     const uint8_t *ad, size_t ad_len, const uint8_t *in,
                     size_t msg_len, uint8_t *out, const uint8_t *tag_in,
                     uint8_t *tag_out)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_status_t st;
    size_t off = 0;
    size_t n;
    size_t got = 0;
    size_t len = 0;
    size_t tag_len = 0;

    st = decrypt ? psa_aead_decrypt_setup(&op, k, PSA_ALG_CCM) :
                   psa_aead_encrypt_setup(&op, k, PSA_ALG_CCM);
    if (st == PSA_SUCCESS) {
        st = psa_aead_set_lengths(&op, ad_len, msg_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_aead_set_nonce(&op, nonce, 13);
    }
    while (st == PSA_SUCCESS && off < ad_len) {
        n = (ad_len - off < 7 + off % 5) ? ad_len - off : 7 + off % 5;
        st = psa_aead_update_ad(&op, ad + off, n);
        off += n;
    }
    if (st == PSA_SUCCESS) {
        st = psa_aead_update(&op, in, msg_len, out, msg_len, &got);
    }
    if (st == PSA_SUCCESS && got != msg_len) {
        st = PSA_ERROR_GENERIC_ERROR;
    }
    if (st == PSA_SUCCESS && decrypt) {
        st = psa_aead_verify(&op, NULL, 0, &len, tag_in, TAG);
    }
    else if (st == PSA_SUCCESS) {
        st = psa_aead_finish(&op, NULL, 0, &len, tag_out, TAG, &tag_len);
        if (st == PSA_SUCCESS && tag_len != TAG) {
            st = PSA_ERROR_GENERIC_ERROR;
        }
    }
    (void)psa_aead_abort(&op);
    return (int)st;
}

static void ccm_stream_ad(void)
{
    static const size_t ad_lens[] = {
        1, 13, 14, 15, 16, 30, 700, 0xFEFF, 0xFF00, 0xFF0F
    };
    static uint8_t ad[0xFF0F];
    static Aes aes;
    psa_key_attributes_t attr = psa_key_attributes_init();
    uint8_t key[16];
    uint8_t nonce[13];
    uint8_t pt[33];
    uint8_t ref[sizeof(pt) + TAG];
    uint8_t wc[sizeof(pt) + TAG];
    uint8_t ct[sizeof(pt)];
    uint8_t tag[TAG];
    uint8_t out[sizeof(pt)];
    char what[128];
    psa_key_id_t k = PSA_KEY_ID_NULL;
    size_t len = 0;
    size_t m;
    size_t i;
    size_t j;
    int ok;

    memset(key, 0x5C, sizeof(key));
    memset(nonce, 0x0B, sizeof(nonce));
    for (i = 0; i < sizeof(ad); i++) {
        ad[i] = (uint8_t)(i * 3 + 1);
    }
    for (i = 0; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i + 0x61);
    }
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CCM);
    check(psa_import_key(&attr, key, sizeof(key), &k) == PSA_SUCCESS &&
          wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
          wc_AesCcmSetKey(&aes, key, sizeof(key)) == 0,
          "import the CCM key");
    for (i = 0; i < sizeof(ad_lens) / sizeof(ad_lens[0]); i++) {
        for (m = 0; m <= sizeof(pt); m += sizeof(pt)) {
            ok = wc_AesCcmEncrypt(&aes, wc, pt, (word32)m, nonce,
                                  sizeof(nonce), wc + m, TAG, ad,
                                  (word32)ad_lens[i]) == 0 &&
                 psa_aead_encrypt(k, PSA_ALG_CCM, nonce, sizeof(nonce), ad,
                                  ad_lens[i], pt, m, ref, sizeof(ref),
                                  &len) == PSA_SUCCESS && len == m + TAG &&
                 memcmp(ref, wc, m + TAG) == 0 &&
                 ccm_parts(k, 0, nonce, ad, ad_lens[i], pt, m, ct, NULL,
                           tag) == PSA_SUCCESS &&
                 memcmp(ct, wc, m) == 0 && memcmp(tag, wc + m, TAG) == 0 &&
                 wolfPSA_AesCcmEncrypt(key, sizeof(key),
                                       nonce, sizeof(nonce), ad,
                                       (word32)ad_lens[i], pt, (word32)m, ct,
                                       tag, TAG) == 0 &&
                 memcmp(ct, wc, m) == 0 && memcmp(tag, wc + m, TAG) == 0;
            snprintf(what, sizeof(what),
                     "CCM one-shot, multipart and helper, %zu-byte AD, "
                     "%zu-byte message, match wolfCrypt",
                     ad_lens[i], m);
            check(ok, what);
            ok = ccm_parts(k, 1, nonce, ad, ad_lens[i], ref, m, out,
                           ref + m, NULL) == PSA_SUCCESS &&
                 memcmp(out, pt, m) == 0;
            memset(out, 0xAA, sizeof(out));
            ok = ok && wolfPSA_AesCcmDecrypt(key, sizeof(key),
                                             nonce, sizeof(nonce), ad,
                                             (word32)ad_lens[i], ref,
                                             (word32)m, ref + m, TAG,
                                             out) == 0 &&
                 memcmp(out, pt, m) == 0;
            ad[ad_lens[i] - 1] ^= 0x80;
            memset(out, 0xAA, sizeof(out));
            ok = ok && wolfPSA_AesCcmDecrypt(key, sizeof(key),
                                             nonce, sizeof(nonce), ad,
                                             (word32)ad_lens[i], ref,
                                             (word32)m, ref + m, TAG,
                                             out) == AES_CCM_AUTH_E;
            for (j = 0; j < m; j++) {
                ok = ok && out[j] == 0;
            }
            ok = ok && ccm_parts(k, 1, nonce, ad, ad_lens[i], ref, m, out,
                                 ref + m, NULL) ==
                 PSA_ERROR_INVALID_SIGNATURE;
            memset(out, 0xAA, sizeof(out));
            ok = ok && psa_aead_decrypt(k, PSA_ALG_CCM, nonce, sizeof(nonce),
                                        ad, ad_lens[i], ref, m + TAG, out,
                                        sizeof(out), &len) ==
                 PSA_ERROR_INVALID_SIGNATURE;
            for (j = 0; j < m; j++) {
                ok = ok && out[j] == 0;
            }
            ad[ad_lens[i] - 1] ^= 0x80;
            snprintf(what, sizeof(what),
                     "CCM opens with a %zu-byte AD and all reject a "
                     "changed last AD byte, releasing no plaintext",
                     ad_lens[i]);
            check(ok, what);
        }
    }
    /* ref holds the last loop's sealing: the longest AD, the full message */
    memcpy(out, ref, sizeof(out));
    check(wolfPSA_AesCcmDecrypt(key, sizeof(key), nonce,
                                sizeof(nonce), ad, sizeof(ad), out,
                                sizeof(out), ref + sizeof(pt), TAG,
                                out) == 0 && memcmp(out, pt, sizeof(pt)) == 0,
          "wolfPSA_AesCcmDecrypt opens in place");
    check(wolfPSA_AesCcmEncrypt(key, sizeof(key), nonce, 6, ad,
                                1, pt, sizeof(pt), ct, tag, TAG) ==
          BAD_FUNC_ARG &&
          wolfPSA_AesCcmEncrypt(key, sizeof(key), nonce,
                                sizeof(nonce), ad, 1, pt, sizeof(pt), ct,
                                tag, 5) == BAD_FUNC_ARG &&
          wolfPSA_AesCcmEncrypt(NULL, sizeof(key), nonce,
                                sizeof(nonce), ad, 1, pt, sizeof(pt), ct,
                                tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesCcmEncrypt(key, sizeof(key), nonce,
                                sizeof(nonce), NULL, 1, pt, sizeof(pt), ct,
                                tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesCcmEncrypt(key, 15, nonce, sizeof(nonce),
                                ad, 1, pt, sizeof(pt), ct, tag, TAG) != 0,
          "wolfPSA_AesCcmEncrypt refuses a short nonce, an odd tag, a NULL "
          "key or AD, and a bad key length");
    wc_AesFree(&aes);
    (void)psa_destroy_key(k);
}

/* One-shot GCM, now on the GCM stream, and the GCM helper match wolfCrypt's
 * one-shot GCM across nonce, AAD, message and tag lengths. */
static void gcm_oneshot_wc(void)
{
    static const size_t aad_lens[] = { 0, 1, 15, 16, 17, 600 };
    static const size_t msg_lens[] = { 0, 1, 16, 33 };
    static const size_t iv_lens[] = { 12, 1, 16, 24 };
    static const size_t tag_lens[] = { TAG, 12 };
    static uint8_t aad[600];
    static Aes aes;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_algorithm_t alg;
    uint8_t key[32];
    uint8_t nonce[PSA_AEAD_NONCE_MAX_SIZE + 1];
    uint8_t pt[33];
    uint8_t wc[sizeof(pt) + TAG];
    uint8_t ref[sizeof(pt) + TAG];
    uint8_t ct[sizeof(pt)];
    uint8_t tag[TAG];
    uint8_t out[sizeof(pt)];
    char what[160];
    psa_key_id_t k = PSA_KEY_ID_NULL;
    size_t len = 0;
    size_t a;
    size_t m;
    size_t n;
    size_t t;
    size_t j;
    word32 ms;
    word32 ts;
    int ok;

    memset(key, 0x4E, sizeof(key));
    for (j = 0; j < sizeof(nonce); j++) {
        nonce[j] = (uint8_t)(j * 7 + 2);
    }
    for (j = 0; j < sizeof(aad); j++) {
        aad[j] = (uint8_t)(j * 11 + 5);
    }
    for (j = 0; j < sizeof(pt); j++) {
        pt[j] = (uint8_t)(j + 0x30);
    }
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr,
                          PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                              PSA_ALG_GCM, 12));
    check(psa_import_key(&attr, key, sizeof(key), &k) == PSA_SUCCESS &&
          wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
          wc_AesGcmSetKey(&aes, key, sizeof(key)) == 0,
          "import the GCM key");
    for (n = 0; n < sizeof(iv_lens) / sizeof(iv_lens[0]); n++) {
    for (t = 0; t < sizeof(tag_lens) / sizeof(tag_lens[0]); t++) {
    for (a = 0; a < sizeof(aad_lens) / sizeof(aad_lens[0]); a++) {
    for (m = 0; m < sizeof(msg_lens) / sizeof(msg_lens[0]); m++) {
        ms = (word32)msg_lens[m];
        ts = (word32)tag_lens[t];
        alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_lens[t]);
        /* wolfCrypt binds a key's tag length on first use, so each case
         * gets a fresh reference key. */
        wc_AesFree(&aes);
        ok = wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
             wc_AesGcmSetKey(&aes, key, sizeof(key)) == 0 &&
             wc_AesGcmEncrypt(&aes, wc, pt, ms, nonce, (word32)iv_lens[n],
                              wc + ms, ts, aad, (word32)aad_lens[a]) == 0 &&
             wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce,
                                   (word32)iv_lens[n], aad,
                                   (word32)aad_lens[a], pt, ms, ct, tag,
                                   ts) == 0 &&
             memcmp(ct, wc, ms) == 0 && memcmp(tag, wc + ms, ts) == 0;
        if (iv_lens[n] >= 12) {
            ok = ok && psa_aead_encrypt(k, alg, nonce, iv_lens[n], aad,
                                        aad_lens[a],
                                        pt, ms, ref, sizeof(ref), &len) ==
                 PSA_SUCCESS && len == ms + ts &&
                 memcmp(ref, wc, ms + ts) == 0;
        }
        memset(out, 0xAA, sizeof(out));
        ok = ok && wolfPSA_AesGcmDecrypt(key, sizeof(key), nonce,
                                         (word32)iv_lens[n], aad,
                                         (word32)aad_lens[a], wc, ms,
                                         wc + ms, ts, out) == 0 &&
             memcmp(out, pt, ms) == 0;
        wc[ms + ts - 1] ^= 0x01;
        memset(out, 0xAA, sizeof(out));
        ok = ok && wolfPSA_AesGcmDecrypt(key, sizeof(key), nonce,
                                         (word32)iv_lens[n], aad,
                                         (word32)aad_lens[a], wc, ms,
                                         wc + ms, ts, out) == AES_GCM_AUTH_E;
        for (j = 0; j < ms; j++) {
            ok = ok && out[j] == 0;
        }
        if (iv_lens[n] >= 12) {
            memset(out, 0xAA, sizeof(out));
            ok = ok && psa_aead_decrypt(k, alg, nonce, iv_lens[n], aad,
                                        aad_lens[a],
                                        wc, ms + ts, out, sizeof(out),
                                        &len) == PSA_ERROR_INVALID_SIGNATURE;
            for (j = 0; j < ms; j++) {
                ok = ok && out[j] == 0;
            }
        }
        snprintf(what, sizeof(what),
                 "GCM %zu-byte IV, %zu-byte tag, AAD %zu, message %zu "
                 "matches wolfCrypt", iv_lens[n], tag_lens[t], aad_lens[a],
                 msg_lens[m]);
        check(ok, what);
    }
    }
    }
    }
    wc_AesFree(&aes);
    ok = wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
         wc_AesGcmSetKey(&aes, key, sizeof(key)) == 0 &&
         wc_AesGcmEncrypt(&aes, wc, pt, sizeof(pt), nonce, 12,
                          wc + sizeof(pt), TAG, aad, 1) == 0;
    memcpy(out, wc, sizeof(out));
    check(ok && wolfPSA_AesGcmDecrypt(key, sizeof(key), nonce, 12, aad, 1,
                                      out, sizeof(out), wc + sizeof(pt), TAG,
                                      out) == 0 &&
          memcmp(out, pt, sizeof(pt)) == 0,
          "wolfPSA_AesGcmDecrypt opens in place");
    check(wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 0, aad, 1, pt,
                                sizeof(pt), ct, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 12, aad, 1, pt,
                                sizeof(pt), ct, tag, 5) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(NULL, sizeof(key), nonce, 12, aad, 1, pt,
                                sizeof(pt), ct, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 12, NULL, 1, pt,
                                sizeof(pt), ct, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, 15, nonce, 12, aad, 1, pt, sizeof(pt),
                                ct, tag, TAG) != 0,
          "wolfPSA_AesGcmEncrypt refuses an empty nonce, an odd tag, a NULL "
          "key or AAD, and a bad key length");
    wc_AesFree(&aes);
    ok = wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
         wc_AesGcmSetKey(&aes, key, sizeof(key)) == 0 &&
         wc_AesGcmEncrypt(&aes, wc, pt, sizeof(pt), nonce,
                          PSA_AEAD_NONCE_MAX_SIZE, wc + sizeof(pt), TAG, aad,
                          1) == 0 &&
         wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce,
                               PSA_AEAD_NONCE_MAX_SIZE, aad, 1, pt,
                               sizeof(pt), ct, tag, TAG) == 0 &&
         memcmp(ct, wc, sizeof(pt)) == 0 &&
         memcmp(tag, wc + sizeof(pt), TAG) == 0;
    check(ok, "wolfPSA_AesGcmEncrypt matches wolfCrypt at the longest nonce");
    wc_AesFree(&aes);
    ok = wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
         wc_AesGcmSetKey(&aes, key, sizeof(key)) == 0 &&
         wc_AesGcmEncrypt(&aes, wc, NULL, 0, nonce, 12, wc, TAG, aad,
                          16) == 0 &&
         wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 12, aad, 16, NULL, 0,
                               NULL, tag, TAG) == 0 &&
         memcmp(tag, wc, TAG) == 0 &&
         wolfPSA_AesGcmDecrypt(key, sizeof(key), nonce, 12, aad, 16, NULL, 0,
                               tag, TAG, NULL) == 0;
    check(ok, "wolfPSA_AesGcm* take an empty message with NULL buffers");
    check(wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce,
                                PSA_AEAD_NONCE_MAX_SIZE + 1, aad, 1, pt,
                                sizeof(pt), ct, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, sizeof(key), NULL, 12, aad, 1, pt,
                                sizeof(pt), ct, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 12, aad, 1, pt,
                                sizeof(pt), ct, NULL, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 12, aad, 1, NULL,
                                sizeof(pt), ct, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmEncrypt(key, sizeof(key), nonce, 12, aad, 1, pt,
                                sizeof(pt), NULL, tag, TAG) == BAD_FUNC_ARG &&
          wolfPSA_AesGcmDecrypt(key, sizeof(key), nonce, 12, aad, 1, ct,
                                sizeof(pt), NULL, TAG, out) == BAD_FUNC_ARG,
          "wolfPSA_AesGcm* refuse an overlong nonce and NULL nonce, tag, "
          "input or output");
    wc_AesFree(&aes);
    (void)psa_destroy_key(k);
}

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
    test_kdf_families_off();
    test_import_ecc_checked();
    aead_overlap(PSA_ALG_GCM, "GCM");
    aead_overlap(PSA_ALG_CCM, "CCM");
    aead_stream_aad();
    ccm_stream_ad();
    gcm_oneshot_wc();
    hkdf_stream(PSA_ALG_HKDF(PSA_ALG_SHA_256), "HKDF");
    hkdf_stream(PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256), "HKDF-Expand");
    printf("%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
