/* psa_ascon_xchacha_test.c
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

/*
 * Coverage test for:
 *   - Ascon-Hash256      (PSA_ALG_ASCON_HASH256)
 *   - Ascon-AEAD128      (PSA_ALG_ASCON_AEAD128 / PSA_KEY_TYPE_ASCON)
 *   - XChaCha20-Poly1305 (PSA_ALG_XCHACHA20_POLY1305 / PSA_KEY_TYPE_XCHACHA20)
 *
 * All three algorithms are compiled-in conditionally (HAVE_ASCON / HAVE_XCHACHA).
 * When the linked library was not built with the relevant feature, import / hash
 * setup will return PSA_ERROR_NOT_SUPPORTED and the individual test sub-function
 * prints "SKIP" and returns 0 so the overall test still exits 0.
 *
 * TEST VECTOR PROVENANCE
 * ----------------------
 * Ascon-Hash256 KATs:
 *   Source: wolfSSL wolfcrypt/test/test.c :: ascon_hash256_test()
 *           and wolfssl/tests/api/test_ascon_kats.h
 *   Origin: https://github.com/ascon/ascon-c
 *           crypto_hash/asconhash256/LWC_HASH_KAT_256.txt  (NIST SP 800-232)
 *   Message: byte stream 0x00 0x01 ... 0x(N-1) of length N.
 *   KATs used:
 *     hash_kat[0]: N=0  (empty message)
 *     hash_kat[2]: N=2  (message {0x00, 0x01})
 *
 * Ascon-AEAD128 KATs:
 *   Source: wolfSSL wolfssl/tests/api/test_ascon_kats.h
 *           (verbatim from ascon-c tests/api/ascon.c)
 *   Origin: crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt (NIST SP 800-232)
 *   KAT used (index 33 in the reference file, first entry with PT="00"):
 *     Key   = 000102030405060708090A0B0C0D0E0F
 *     Nonce = 000102030405060708090A0B0C0D0E0F
 *     PT    = 00   (1 byte, value 0x00)
 *     AD    = ""   (empty)
 *     CT||T = E79F58F1F541FC51B5D438F8E1DD03F147
 *             (1 byte CT = 0xE7, then 16-byte tag)
 *
 * XChaCha20-Poly1305 KAT:
 *   Source: wolfSSL wolfcrypt/test/test.c :: xchacha20_poly1305_oneshot_test()
 *   Origin: draft-irtf-cfrg-xchacha §A.3
 *   Plaintext: "Ladies and Gentlemen of the class of '99: ..."
 *   Key, IV, AAD, Ciphertext, Tag reproduced verbatim from wolfSSL source.
 */

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <wolfpsa/psa/crypto.h>

/* -------------------------------------------------------------------------
 * Helper utilities
 * ---------------------------------------------------------------------- */

static int expect_status(const char *label, psa_status_t status,
                         psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s: status=%d expected=%d\n", label,
               (int)status, (int)expected);
        return 1;
    }
    return 0;
}

static int expect_buf_eq(const char *label, const uint8_t *a,
                         const uint8_t *b, size_t len)
{
    if (memcmp(a, b, len) != 0) {
        printf("FAIL %s: buffer mismatch\n", label);
        return 1;
    }
    return 0;
}

/* =========================================================================
 * Test 1 — Ascon-Hash256
 * ====================================================================== */

/*
 * KATs from wolfSSL wolfcrypt/test/test.c hash_output[] table
 * (NIST SP 800-232 / ascon-c LWC_HASH_KAT_256.txt)
 * Message is the byte stream { 0x00, 0x01, ..., 0x(N-1) }.
 */

/* N=0: hash of empty message */
static const uint8_t ascon_hash256_kat0_msg[] = { 0 };  /* unused — length 0 */
static const uint8_t ascon_hash256_kat0_digest[32] = {
    0x0B, 0x3B, 0xE5, 0x85, 0x0F, 0x2F, 0x6B, 0x98,
    0xCA, 0xF2, 0x9F, 0x8F, 0xDE, 0xA8, 0x9B, 0x64,
    0xA1, 0xFA, 0x70, 0xAA, 0x24, 0x9B, 0x8F, 0x83,
    0x9B, 0xD5, 0x3B, 0xAA, 0x30, 0x4D, 0x92, 0xB2
};

/* N=2: hash of { 0x00, 0x01 } */
static const uint8_t ascon_hash256_kat2_msg[2] = { 0x00, 0x01 };
static const uint8_t ascon_hash256_kat2_digest[32] = {
    0x61, 0x15, 0xE7, 0xC9, 0xC4, 0x08, 0x1C, 0x27,
    0x97, 0xFC, 0x8F, 0xE1, 0xBC, 0x57, 0xA8, 0x36,
    0xAF, 0xA1, 0xC5, 0x38, 0x1E, 0x55, 0x6D, 0xD5,
    0x83, 0x86, 0x0C, 0xA2, 0xDF, 0xB4, 0x8D, 0xD2
};

static int test_ascon_hash256(void)
{
    uint8_t out[32];
    size_t out_len = 0;
    psa_hash_operation_t op;
    psa_status_t st;

    /* --- Runtime size check -------------------------------------------- */
    if (PSA_HASH_LENGTH(PSA_ALG_ASCON_HASH256) != 32u) {
        printf("FAIL ascon_hash256 PSA_HASH_LENGTH: got %u expected 32\n",
               (unsigned)PSA_HASH_LENGTH(PSA_ALG_ASCON_HASH256));
        return 1;
    }

    /* --- KAT 0: one-shot, empty message --------------------------------- */
    memset(out, 0, sizeof(out));
    out_len = 0;
    st = psa_hash_compute(PSA_ALG_ASCON_HASH256,
                          ascon_hash256_kat0_msg, 0,
                          out, sizeof(out), &out_len);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP ascon_hash256 (not supported by this build)\n");
        return 0;
    }
    if (expect_status("ascon_hash256 KAT0 compute", st, PSA_SUCCESS) != 0)
        return 1;
    if (out_len != 32u) {
        printf("FAIL ascon_hash256 KAT0 length: got %zu expected 32\n",
               out_len);
        return 1;
    }
    if (expect_buf_eq("ascon_hash256 KAT0 digest",
                      out, ascon_hash256_kat0_digest, 32) != 0)
        return 1;

    /* --- KAT 2: one-shot, 2-byte message -------------------------------- */
    memset(out, 0, sizeof(out));
    out_len = 0;
    st = psa_hash_compute(PSA_ALG_ASCON_HASH256,
                          ascon_hash256_kat2_msg, sizeof(ascon_hash256_kat2_msg),
                          out, sizeof(out), &out_len);
    if (expect_status("ascon_hash256 KAT2 compute", st, PSA_SUCCESS) != 0)
        return 1;
    if (expect_buf_eq("ascon_hash256 KAT2 digest",
                      out, ascon_hash256_kat2_digest, 32) != 0)
        return 1;

    /* --- Multipart equals one-shot (KAT2, split into 2 chunks: 1+1) ---- */
    memset(out, 0, sizeof(out));
    out_len = 0;
    op = psa_hash_operation_init();
    st = psa_hash_setup(&op, PSA_ALG_ASCON_HASH256);
    if (expect_status("ascon_hash256 multipart setup", st, PSA_SUCCESS) != 0)
        return 1;
    st = psa_hash_update(&op, ascon_hash256_kat2_msg, 1);
    if (expect_status("ascon_hash256 multipart update1", st, PSA_SUCCESS) != 0) {
        (void)psa_hash_abort(&op);
        return 1;
    }
    st = psa_hash_update(&op, ascon_hash256_kat2_msg + 1, 1);
    if (expect_status("ascon_hash256 multipart update2", st, PSA_SUCCESS) != 0) {
        (void)psa_hash_abort(&op);
        return 1;
    }
    st = psa_hash_finish(&op, out, sizeof(out), &out_len);
    if (expect_status("ascon_hash256 multipart finish", st, PSA_SUCCESS) != 0)
        return 1;
    if (out_len != 32u) {
        printf("FAIL ascon_hash256 multipart length: got %zu expected 32\n",
               out_len);
        return 1;
    }
    if (expect_buf_eq("ascon_hash256 multipart digest",
                      out, ascon_hash256_kat2_digest, 32) != 0)
        return 1;

    /* --- psa_hash_compare ------------------------------------------------ */
    st = psa_hash_compare(PSA_ALG_ASCON_HASH256,
                          ascon_hash256_kat2_msg,
                          sizeof(ascon_hash256_kat2_msg),
                          ascon_hash256_kat2_digest, 32);
    if (expect_status("ascon_hash256 hash_compare", st, PSA_SUCCESS) != 0)
        return 1;

    printf("ascon_hash256: OK\n");
    return 0;
}

/* =========================================================================
 * Test 2 — Ascon-AEAD128
 * ====================================================================== */

/*
 * KAT from wolfSSL tests/api/test_ascon_kats.h
 * (NIST SP 800-232 / ascon-c LWC_AEAD_KAT_128_128.txt, first PT="00" entry)
 *
 * Key   = 000102030405060708090A0B0C0D0E0F
 * Nonce = 000102030405060708090A0B0C0D0E0F
 * PT    = 00                               (1 byte)
 * AD    = ""                               (empty)
 * CT    = E7                               (1 byte)
 * Tag   = 9F58F1F541FC51B5D438F8E1DD03F1 47 (16 bytes)
 *         (full CT||Tag hex: E79F58F1F541FC51B5D438F8E1DD03F147)
 */
static const uint8_t ascon_aead128_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static const uint8_t ascon_aead128_nonce[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static const uint8_t ascon_aead128_pt[1]  = { 0x00 };
/* CT (1 byte) concatenated with 16-byte tag */
static const uint8_t ascon_aead128_ct_tag[17] = {
    0xE7,                                           /* ciphertext byte */
    0x9F, 0x58, 0xF1, 0xF5, 0x41, 0xFC, 0x51, 0xB5,
    0xD4, 0x38, 0xF8, 0xE1, 0xDD, 0x03, 0xF1, 0x47  /* 16-byte tag */
};

static int test_ascon_aead128(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    /* output buffer: plaintext length (1) + tag (16) = 17 bytes max */
    uint8_t enc_out[17];
    uint8_t dec_out[1];
    size_t enc_out_len = 0;
    size_t dec_out_len = 0;
    psa_aead_operation_t setup_op = PSA_AEAD_OPERATION_INIT;
    psa_status_t st;

    /* Import the 128-bit Ascon key */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ASCON);
    psa_set_key_bits(&attrs, 128u);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ASCON_AEAD128);

    st = psa_import_key(&attrs, ascon_aead128_key, sizeof(ascon_aead128_key),
                        &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP ascon_aead128 (not supported by this build)\n");
        return 0;
    }
    if (expect_status("ascon_aead128 import_key", st, PSA_SUCCESS) != 0)
        return 1;

    /* --- Encrypt KAT ----------------------------------------------------- */
    memset(enc_out, 0, sizeof(enc_out));
    enc_out_len = 0;
    st = psa_aead_encrypt(key_id, PSA_ALG_ASCON_AEAD128,
                          ascon_aead128_nonce, sizeof(ascon_aead128_nonce),
                          NULL, 0,  /* no AD */
                          ascon_aead128_pt, sizeof(ascon_aead128_pt),
                          enc_out, sizeof(enc_out), &enc_out_len);
    if (expect_status("ascon_aead128 encrypt KAT", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (enc_out_len != sizeof(ascon_aead128_ct_tag)) {
        printf("FAIL ascon_aead128 encrypt length: got %zu expected %zu\n",
               enc_out_len, sizeof(ascon_aead128_ct_tag));
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (expect_buf_eq("ascon_aead128 encrypt ct||tag",
                      enc_out, ascon_aead128_ct_tag,
                      sizeof(ascon_aead128_ct_tag)) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }

    /* --- Decrypt roundtrip ----------------------------------------------- */
    memset(dec_out, 0, sizeof(dec_out));
    dec_out_len = 0;
    st = psa_aead_decrypt(key_id, PSA_ALG_ASCON_AEAD128,
                          ascon_aead128_nonce, sizeof(ascon_aead128_nonce),
                          NULL, 0,
                          ascon_aead128_ct_tag, sizeof(ascon_aead128_ct_tag),
                          dec_out, sizeof(dec_out), &dec_out_len);
    if (expect_status("ascon_aead128 decrypt roundtrip", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (dec_out_len != sizeof(ascon_aead128_pt)) {
        printf("FAIL ascon_aead128 decrypt length: got %zu expected %zu\n",
               dec_out_len, sizeof(ascon_aead128_pt));
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (expect_buf_eq("ascon_aead128 decrypt plaintext",
                      dec_out, ascon_aead128_pt,
                      sizeof(ascon_aead128_pt)) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }

    /* --- Tampered tag must be rejected -----------------------------------
     * PSA 1.4 spec: psa_aead_decrypt must return PSA_ERROR_INVALID_SIGNATURE
     * on authentication failure (ASCON_AUTH_E from wolfCrypt). */
    {
        uint8_t tampered[17];
        memcpy(tampered, ascon_aead128_ct_tag, sizeof(tampered));
        tampered[16] ^= 0xFF;  /* flip last byte of tag */
        memset(dec_out, 0, sizeof(dec_out));
        dec_out_len = 0;
        st = psa_aead_decrypt(key_id, PSA_ALG_ASCON_AEAD128,
                              ascon_aead128_nonce, sizeof(ascon_aead128_nonce),
                              NULL, 0,
                              tampered, sizeof(tampered),
                              dec_out, sizeof(dec_out), &dec_out_len);
        if (st != PSA_ERROR_INVALID_SIGNATURE) {
            printf("FAIL ascon_aead128 tampered tag: got status=%d, "
                   "expected PSA_ERROR_INVALID_SIGNATURE (%d)\n",
                   (int)st, (int)PSA_ERROR_INVALID_SIGNATURE);
            (void)psa_destroy_key(key_id);
            return 1;
        }
    }

    /* --- Wrong nonce length (12 bytes) must return INVALID_ARGUMENT ------ */
    {
        static const uint8_t short_nonce[12] = { 0 };
        st = psa_aead_encrypt(key_id, PSA_ALG_ASCON_AEAD128,
                              short_nonce, sizeof(short_nonce),
                              NULL, 0,
                              ascon_aead128_pt, sizeof(ascon_aead128_pt),
                              enc_out, sizeof(enc_out), &enc_out_len);
        if (expect_status("ascon_aead128 wrong nonce length",
                          st, PSA_ERROR_INVALID_ARGUMENT) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }
    }

    /* --- Multipart setup must return PSA_ERROR_NOT_SUPPORTED ------------- */
    /* This is always true regardless of HAVE_ASCON (see psa_aead.c:268-271) */
    st = psa_aead_encrypt_setup(&setup_op, key_id, PSA_ALG_ASCON_AEAD128);
    if (expect_status("ascon_aead128 multipart setup",
                      st, PSA_ERROR_NOT_SUPPORTED) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }

    (void)psa_destroy_key(key_id);
    printf("ascon_aead128: OK\n");
    return 0;
}

/* =========================================================================
 * Test 3 — XChaCha20-Poly1305
 * ====================================================================== */

/*
 * KAT from wolfSSL wolfcrypt/test/test.c :: xchacha20_poly1305_oneshot_test()
 * Origin: draft-irtf-cfrg-xchacha §A.3
 * Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer
 *             you only one tip for the future, sunscreen would be it."
 */
static const uint8_t xchacha_pt[] = {
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, /* Ladies a */
    0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, /* nd Gentl */
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, /* emen of  */
    0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, /* the clas */
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, /* s of '99 */
    0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, /* : If I c */
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, /* ould off */
    0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, /* er you o */
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, /* nly one  */
    0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, /* tip for  */
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, /* the futu */
    0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, /* re, suns */
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, /* creen wo */
    0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, /* uld be i */
    0x74, 0x2e                                       /* t.       */
};
#define XCHACHA_PT_LEN  (sizeof(xchacha_pt))  /* 114 bytes */

static const uint8_t xchacha_aad[] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
};

static const uint8_t xchacha_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

/* 24-byte XChaCha nonce */
static const uint8_t xchacha_nonce[24] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
};

/* reference ciphertext (114 bytes) */
static const uint8_t xchacha_ct[114] = {
    0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
    0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
    0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
    0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
    0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
    0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
    0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
    0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
    0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
    0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
    0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
    0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
    0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
    0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
    0xb5, 0x2e
};

/* reference authentication tag (16 bytes) */
static const uint8_t xchacha_tag[16] = {
    0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
    0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49
};

static int test_xchacha20_poly1305(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    /* encrypt output: ciphertext (114) + tag (16) = 130 bytes */
    uint8_t enc_out[130];
    uint8_t dec_out[114];
    size_t enc_out_len = 0;
    size_t dec_out_len = 0;
    psa_aead_operation_t setup_op = PSA_AEAD_OPERATION_INIT;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_XCHACHA20);
    psa_set_key_bits(&attrs, 256u);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_XCHACHA20_POLY1305);

    st = psa_import_key(&attrs, xchacha_key, sizeof(xchacha_key), &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP xchacha20_poly1305 (not supported by this build)\n");
        return 0;
    }
    if (expect_status("xchacha20_poly1305 import_key", st, PSA_SUCCESS) != 0)
        return 1;

    /* --- Encrypt KAT ----------------------------------------------------- */
    memset(enc_out, 0, sizeof(enc_out));
    enc_out_len = 0;
    st = psa_aead_encrypt(key_id, PSA_ALG_XCHACHA20_POLY1305,
                          xchacha_nonce, sizeof(xchacha_nonce),
                          xchacha_aad, sizeof(xchacha_aad),
                          xchacha_pt, sizeof(xchacha_pt),
                          enc_out, sizeof(enc_out), &enc_out_len);
    if (expect_status("xchacha20_poly1305 encrypt KAT", st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (enc_out_len != sizeof(xchacha_ct) + sizeof(xchacha_tag)) {
        printf("FAIL xchacha20_poly1305 encrypt length: got %zu expected %zu\n",
               enc_out_len, sizeof(xchacha_ct) + sizeof(xchacha_tag));
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (expect_buf_eq("xchacha20_poly1305 ciphertext",
                      enc_out, xchacha_ct, sizeof(xchacha_ct)) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (expect_buf_eq("xchacha20_poly1305 tag",
                      enc_out + sizeof(xchacha_ct), xchacha_tag,
                      sizeof(xchacha_tag)) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }

    /* --- Decrypt roundtrip ----------------------------------------------- */
    memset(dec_out, 0, sizeof(dec_out));
    dec_out_len = 0;
    st = psa_aead_decrypt(key_id, PSA_ALG_XCHACHA20_POLY1305,
                          xchacha_nonce, sizeof(xchacha_nonce),
                          xchacha_aad, sizeof(xchacha_aad),
                          enc_out, enc_out_len,
                          dec_out, sizeof(dec_out), &dec_out_len);
    if (expect_status("xchacha20_poly1305 decrypt roundtrip",
                      st, PSA_SUCCESS) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (dec_out_len != sizeof(xchacha_pt)) {
        printf("FAIL xchacha20_poly1305 decrypt length: got %zu expected %zu\n",
               dec_out_len, sizeof(xchacha_pt));
        (void)psa_destroy_key(key_id);
        return 1;
    }
    if (expect_buf_eq("xchacha20_poly1305 decrypt plaintext",
                      dec_out, xchacha_pt, sizeof(xchacha_pt)) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }

    /* --- Tampered ciphertext must be rejected ----------------------------- */
    {
        uint8_t tampered[130];
        memcpy(tampered, enc_out, enc_out_len);
        tampered[0] ^= 0xFF;  /* corrupt first ciphertext byte */
        memset(dec_out, 0, sizeof(dec_out));
        dec_out_len = 0;
        st = psa_aead_decrypt(key_id, PSA_ALG_XCHACHA20_POLY1305,
                              xchacha_nonce, sizeof(xchacha_nonce),
                              xchacha_aad, sizeof(xchacha_aad),
                              tampered, enc_out_len,
                              dec_out, sizeof(dec_out), &dec_out_len);
        if (expect_status("xchacha20_poly1305 tampered ciphertext",
                          st, PSA_ERROR_INVALID_SIGNATURE) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }
    }

    /* --- 12-byte nonce must return INVALID_ARGUMENT ---------------------- */
    {
        static const uint8_t short_nonce[12] = { 0 };
        st = psa_aead_encrypt(key_id, PSA_ALG_XCHACHA20_POLY1305,
                              short_nonce, sizeof(short_nonce),
                              NULL, 0,
                              xchacha_pt, sizeof(xchacha_pt),
                              enc_out, sizeof(enc_out), &enc_out_len);
        if (expect_status("xchacha20_poly1305 short nonce",
                          st, PSA_ERROR_INVALID_ARGUMENT) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }
    }

    /* --- Multipart setup must return NOT_SUPPORTED ----------------------- */
    st = psa_aead_encrypt_setup(&setup_op, key_id, PSA_ALG_XCHACHA20_POLY1305);
    if (expect_status("xchacha20_poly1305 multipart setup",
                      st, PSA_ERROR_NOT_SUPPORTED) != 0) {
        (void)psa_destroy_key(key_id);
        return 1;
    }

    (void)psa_destroy_key(key_id);
    printf("xchacha20_poly1305: OK\n");
    return 0;
}

/* =========================================================================
 * Test 4 — Key policy: XCHACHA20 key used with CHACHA20_POLY1305 algorithm
 * ====================================================================== */

static int test_xchacha_key_policy(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t enc_out[130];
    size_t enc_out_len = 0;
    psa_status_t st;

    /* Import an XChaCha20 key bound to the XCHACHA20_POLY1305 algorithm */
    psa_set_key_type(&attrs, PSA_KEY_TYPE_XCHACHA20);
    psa_set_key_bits(&attrs, 256u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_XCHACHA20_POLY1305);

    st = psa_import_key(&attrs, xchacha_key, sizeof(xchacha_key), &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP xchacha_key_policy (not supported by this build)\n");
        return 0;
    }
    if (expect_status("xchacha_key_policy import_key", st, PSA_SUCCESS) != 0)
        return 1;

    /*
     * Attempt to use the XChaCha20 key with CHACHA20_POLY1305 (wrong
     * algorithm).  The PSA spec and wolfPSA implementation must reject this;
     * either PSA_ERROR_NOT_PERMITTED or PSA_ERROR_INVALID_ARGUMENT is
     * acceptable — what matters is that PSA_SUCCESS must not be returned.
     */
    st = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                          xchacha_nonce, 12u,  /* ChaCha uses 12-byte nonce */
                          NULL, 0,
                          xchacha_pt, sizeof(xchacha_pt),
                          enc_out, sizeof(enc_out), &enc_out_len);
    if (st == PSA_SUCCESS) {
        printf("FAIL xchacha_key_policy: XCHACHA20 key accepted "
               "CHACHA20_POLY1305 alg (should have been rejected)\n");
        (void)psa_destroy_key(key_id);
        return 1;
    }
    printf("xchacha_key_policy: correctly rejected with status=%d\n",
           (int)st);

    (void)psa_destroy_key(key_id);
    printf("xchacha_key_policy: OK\n");
    return 0;
}

/* =========================================================================
 * Test 5 — Shortened / at-least-this-length tag variants must be rejected
 *
 * The one-shot XChaCha20-Poly1305 and Ascon-AEAD128 paths only implement the
 * native 16-byte tag. A shortened-tag (or at-least-this-length) algorithm must
 * be rejected with PSA_ERROR_NOT_SUPPORTED rather than silently producing or
 * requiring a 16-byte tag while the caller expects a shorter one.
 * ====================================================================== */

static int test_aead_shortened_tag_rejected(void)
{
    psa_key_attributes_t attrs;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t enc_out[130];
    uint8_t dec_out[130];
    size_t out_len = 0;
    psa_status_t st;
    psa_algorithm_t xch_short =
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_XCHACHA20_POLY1305, 12);
    psa_algorithm_t xch_atleast =
        PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_XCHACHA20_POLY1305,
                                                   16);
    psa_algorithm_t asc_short =
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_ASCON_AEAD128, 12);

    /* --- XChaCha20-Poly1305 --------------------------------------------- */
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_XCHACHA20);
    psa_set_key_bits(&attrs, 256u);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_XCHACHA20_POLY1305);

    st = psa_import_key(&attrs, xchacha_key, sizeof(xchacha_key), &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP aead_shortened_tag xchacha (not supported by this build)\n");
    }
    else {
        if (expect_status("shortened xchacha import", st, PSA_SUCCESS) != 0)
            return 1;

        out_len = 0;
        st = psa_aead_encrypt(key_id, xch_short,
                              xchacha_nonce, sizeof(xchacha_nonce),
                              NULL, 0, xchacha_pt, sizeof(xchacha_pt),
                              enc_out, sizeof(enc_out), &out_len);
        if (expect_status("xchacha shortened-tag encrypt rejected",
                          st, PSA_ERROR_NOT_SUPPORTED) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }

        out_len = 0;
        st = psa_aead_encrypt(key_id, xch_atleast,
                              xchacha_nonce, sizeof(xchacha_nonce),
                              NULL, 0, xchacha_pt, sizeof(xchacha_pt),
                              enc_out, sizeof(enc_out), &out_len);
        if (expect_status("xchacha at-least-tag encrypt rejected",
                          st, PSA_ERROR_NOT_SUPPORTED) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }

        out_len = 0;
        st = psa_aead_decrypt(key_id, xch_short,
                              xchacha_nonce, sizeof(xchacha_nonce),
                              NULL, 0, enc_out, sizeof(xchacha_pt) + 12u,
                              dec_out, sizeof(dec_out), &out_len);
        if (expect_status("xchacha shortened-tag decrypt rejected",
                          st, PSA_ERROR_NOT_SUPPORTED) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }

        (void)psa_destroy_key(key_id);
    }

    /* --- Ascon-AEAD128 -------------------------------------------------- */
    key_id = PSA_KEY_ID_NULL;
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ASCON);
    psa_set_key_bits(&attrs, 128u);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ASCON_AEAD128);

    st = psa_import_key(&attrs, ascon_aead128_key, sizeof(ascon_aead128_key),
                        &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP aead_shortened_tag ascon (not supported by this build)\n");
    }
    else {
        if (expect_status("shortened ascon import", st, PSA_SUCCESS) != 0)
            return 1;

        out_len = 0;
        st = psa_aead_encrypt(key_id, asc_short,
                              ascon_aead128_nonce, sizeof(ascon_aead128_nonce),
                              NULL, 0, ascon_aead128_pt,
                              sizeof(ascon_aead128_pt),
                              enc_out, sizeof(enc_out), &out_len);
        if (expect_status("ascon shortened-tag encrypt rejected",
                          st, PSA_ERROR_NOT_SUPPORTED) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }

        out_len = 0;
        st = psa_aead_decrypt(key_id, asc_short,
                              ascon_aead128_nonce, sizeof(ascon_aead128_nonce),
                              NULL, 0, ascon_aead128_ct_tag,
                              sizeof(ascon_aead128_pt) + 12u,
                              dec_out, sizeof(dec_out), &out_len);
        if (expect_status("ascon shortened-tag decrypt rejected",
                          st, PSA_ERROR_NOT_SUPPORTED) != 0) {
            (void)psa_destroy_key(key_id);
            return 1;
        }

        (void)psa_destroy_key(key_id);
    }

    printf("aead_shortened_tag_rejected: OK\n");
    return 0;
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(void)
{
    psa_status_t st;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init: status=%d\n", (int)st);
        return 1;
    }

    if (test_ascon_hash256() != 0)
        return 1;

    if (test_ascon_aead128() != 0)
        return 1;

    if (test_xchacha20_poly1305() != 0)
        return 1;

    if (test_xchacha_key_policy() != 0)
        return 1;

    if (test_aead_shortened_tag_rejected() != 0)
        return 1;

    printf("psa_ascon_xchacha_test: all tests passed\n");
    return 0;
}
