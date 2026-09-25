/* psa_aead_multipart_test.c
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

/* F-12493: the PSA multipart AEAD output-size contract.
 *
 * A conforming caller sizes its update() output buffer with
 * PSA_AEAD_UPDATE_OUTPUT_SIZE() and its finish()/verify() ciphertext buffer
 * with PSA_AEAD_FINISH_OUTPUT_SIZE()/PSA_AEAD_VERIFY_OUTPUT_SIZE().  The
 * implementation must therefore emit the payload from update() and leave at
 * most the trailing block (16 bytes for block-cipher AEAD, zero for
 * ChaCha20-Poly1305) for the final call.  This test feeds a multi-block
 * payload in chunks using exactly those spec-sized buffers and checks that
 * the reassembled ciphertext + tag (or plaintext) matches the one-shot
 * reference.  With the old buffering design update() emitted zero bytes and
 * finish() demanded the whole payload, so the spec-sized final buffer came
 * back PSA_ERROR_BUFFER_TOO_SMALL.
 */

#include <stdio.h>
#include <string.h>

#include <wolfpsa/psa/crypto.h>

#define TEST_OK    0
#define TEST_FAIL  1

static int g_failures = 0;

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("  FAIL: %s\n", what);
        g_failures++;
    }
}

static int check_status(psa_status_t st, const char *what)
{
    if (st != PSA_SUCCESS) {
        printf("  FAIL: %s -> status %d\n", what, (int)st);
        g_failures++;
        return TEST_FAIL;
    }
    return TEST_OK;
}

/* Multipart encrypt: feed pt in `chunk`-sized pieces with spec-sized output
 * buffers, finish with a FINISH_OUTPUT_SIZE buffer, and compare the
 * reassembled ciphertext + tag against the one-shot reference. */
static void test_multipart_encrypt(psa_key_id_t key_id, psa_algorithm_t alg,
                                   int is_ccm,
                                   psa_key_type_t key_type, size_t key_bits,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *pt, size_t pt_len,
                                   size_t chunk)
{
    uint8_t ref[512 + PSA_AEAD_TAG_MAX_SIZE];
    size_t ref_len = 0;
    uint8_t mp_ct[512];
    size_t mp_ct_len = 0;
    uint8_t tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t tag_len = 0;
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    size_t off;

    (void)key_bits;

    st = psa_aead_encrypt(key_id, alg, nonce, nonce_len, aad, aad_len,
                          pt, pt_len, ref, sizeof(ref), &ref_len);
    if (st != PSA_SUCCESS) {
        check_status(st, "oneshot encrypt (reference)");
        return;
    }
    if (ref_len < pt_len) {
        check(0, "oneshot ref shorter than payload");
        return;
    }

    st = psa_aead_encrypt_setup(&op, key_id, alg);
    check_status(st, "encrypt_setup");
    if (st != PSA_SUCCESS) return;
    if (is_ccm) {
        st = psa_aead_set_lengths(&op, aad_len, pt_len);
        check_status(st, "set_lengths");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    }
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "set_nonce");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "update_ad");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }

    for (off = 0; off < pt_len; off += chunk) {
        size_t n = (pt_len - off < chunk) ? (pt_len - off) : chunk;
        uint8_t out[PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, 64)];
        size_t out_len = 0;

        st = psa_aead_update(&op, pt + off, n, out, sizeof(out), &out_len);
        check_status(st, "update");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
        if (out_len > n) {
            check(0, "update emitted more than input");
            psa_aead_abort(&op);
            return;
        }
        memcpy(mp_ct + mp_ct_len, out, out_len);
        mp_ct_len += out_len;
    }

    {
        size_t fin_size = PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg);
        uint8_t fin_ct[fin_size > 0 ? fin_size : 1];
        uint8_t fin_tag[PSA_AEAD_TAG_MAX_SIZE];
        size_t fin_ct_len = 0;
        size_t fin_tag_len = 0;

        st = psa_aead_finish(&op, fin_ct, fin_size, &fin_ct_len,
                             fin_tag, sizeof(fin_tag), &fin_tag_len);
        check_status(st, "finish (spec-sized buffer)");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
        memcpy(mp_ct + mp_ct_len, fin_ct, fin_ct_len);
        mp_ct_len += fin_ct_len;
        memcpy(tag, fin_tag, fin_tag_len);
        tag_len = fin_tag_len;
    }
    psa_aead_abort(&op);

    /* AEAD ciphertext is 1:1 with the plaintext; the tag follows it in the
     * one-shot reference output. */
    check(mp_ct_len == pt_len, "reassembled ciphertext length");
    if (mp_ct_len == pt_len) {
        check(memcmp(mp_ct, ref, pt_len) == 0, "reassembled ciphertext");
    }
    check(tag_len == ref_len - pt_len, "tag length");
    if (tag_len == ref_len - pt_len && tag_len > 0) {
        check(memcmp(tag, ref + pt_len, tag_len) == 0, "authentication tag");
    }
}

/* Multipart decrypt: same contract on the verify() path. */
static void test_multipart_decrypt(psa_key_id_t key_id, psa_algorithm_t alg,
                                   int is_ccm,
                                   psa_key_type_t key_type, size_t key_bits,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ct, size_t ct_len,
                                   size_t chunk)
{
    uint8_t ref[512];
    size_t ref_len = 0;
    uint8_t mp_pt[512];
    size_t mp_pt_len = 0;
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    size_t off;
    size_t tag_len;

    st = psa_aead_decrypt(key_id, alg, nonce, nonce_len, aad, aad_len,
                          ct, ct_len, ref, sizeof(ref), &ref_len);
    if (st != PSA_SUCCESS) {
        check_status(st, "oneshot decrypt (reference)");
        return;
    }
    tag_len = PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);
    if (tag_len == 0 || ct_len < tag_len) {
        check(0, "reference: no tag");
        return;
    }

    st = psa_aead_decrypt_setup(&op, key_id, alg);
    check_status(st, "decrypt_setup");
    if (st != PSA_SUCCESS) return;
    if (is_ccm) {
        st = psa_aead_set_lengths(&op, aad_len, ct_len - tag_len);
        check_status(st, "set_lengths");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    }
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "set_nonce");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "update_ad");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }

    for (off = 0; off < ct_len - tag_len; off += chunk) {
        size_t n = (ct_len - tag_len - off < chunk) ?
                   (ct_len - tag_len - off) : chunk;
        uint8_t out[PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, 64)];
        size_t out_len = 0;

        st = psa_aead_update(&op, ct + off, n, out, sizeof(out), &out_len);
        check_status(st, "update (decrypt)");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
        if (out_len > n) {
            check(0, "update emitted more than input (decrypt)");
            psa_aead_abort(&op);
            return;
        }
        memcpy(mp_pt + mp_pt_len, out, out_len);
        mp_pt_len += out_len;
    }

    {
        size_t ver_size = PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg);
        uint8_t ver_pt[ver_size > 0 ? ver_size : 1];
        size_t ver_pt_len = 0;

        st = psa_aead_verify(&op, ver_pt, ver_size, &ver_pt_len,
                             ct + ct_len - tag_len, tag_len);
        check_status(st, "verify (spec-sized buffer)");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
        memcpy(mp_pt + mp_pt_len, ver_pt, ver_pt_len);
        mp_pt_len += ver_pt_len;
    }
    psa_aead_abort(&op);

    check(mp_pt_len == ref_len, "reassembled plaintext length");
    if (mp_pt_len == ref_len) {
        check(memcmp(mp_pt, ref, ref_len) == 0, "reassembled plaintext");
    }
}

/* Streaming decrypt with a corrupted tag must fail with
 * PSA_ERROR_INVALID_SIGNATURE: the streaming CCM tag comparison, the
 * ChaCha20-Poly1305 CheckTag failure, and the GCM DecryptFinal
 * authentication failure must all reject a flipped tag. */
static void test_multipart_decrypt_bad_tag(psa_key_id_t key_id,
                                           psa_algorithm_t alg, int is_ccm,
                                           psa_key_type_t key_type,
                                           size_t key_bits,
                                           const uint8_t *nonce,
                                           size_t nonce_len,
                                           const uint8_t *aad, size_t aad_len,
                                           const uint8_t *ct, size_t ct_len)
{
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    size_t tag_len;
    size_t off;
    size_t n;
    size_t out_len = 0;
    size_t ver_size;
    size_t ver_pt_len = 0;
    uint8_t bad_tag[PSA_AEAD_TAG_MAX_SIZE];
    uint8_t out[PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, 64)];
    uint8_t ver_pt[PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE];

    tag_len = PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);
    if (tag_len == 0 || ct_len < tag_len) {
        check(0, "bad tag: no tag in reference");
        return;
    }

    ver_size = PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg);

    st = psa_aead_decrypt_setup(&op, key_id, alg);
    check_status(st, "bad tag: decrypt_setup");
    if (st != PSA_SUCCESS) {
        return;
    }
    if (is_ccm) {
        st = psa_aead_set_lengths(&op, aad_len, ct_len - tag_len);
        check_status(st, "bad tag: set_lengths");
        if (st != PSA_SUCCESS) {
            psa_aead_abort(&op);
            return;
        }
    }
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "bad tag: set_nonce");
    if (st != PSA_SUCCESS) {
        psa_aead_abort(&op);
        return;
    }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "bad tag: update_ad");
    if (st != PSA_SUCCESS) {
        psa_aead_abort(&op);
        return;
    }

    for (off = 0; off < ct_len - tag_len; off += 16) {
        n = (ct_len - tag_len - off < 16) ?
            (ct_len - tag_len - off) : 16;
        st = psa_aead_update(&op, ct + off, n, out, sizeof(out), &out_len);
        check_status(st, "bad tag: update");
        if (st != PSA_SUCCESS) {
            psa_aead_abort(&op);
            return;
        }
    }

    memcpy(bad_tag, ct + ct_len - tag_len, tag_len);
    bad_tag[0] ^= 0x01;
    st = psa_aead_verify(&op, ver_pt, ver_size, &ver_pt_len,
                         bad_tag, tag_len);
    if (st != PSA_ERROR_INVALID_SIGNATURE) {
        printf("  FAIL: bad tag verify -> status %d (expected %d)\n",
               (int)st, (int)PSA_ERROR_INVALID_SIGNATURE);
        g_failures++;
    }
    psa_aead_abort(&op);
}

/* In-place streaming CCM: psa_aead_update() with in == out must produce
 * the same ciphertext and tag as non-overlapping buffers (PSA spec: 
 * overlapping input and output buffers give the same result). Before the
 * fix the CBC-MAC authenticated the ciphertext bytes on in-place
 * encryption, so the tag diverged from the one-shot reference. */
static void test_inplace_ccm(psa_key_id_t key_id, psa_algorithm_t alg,
                             psa_key_type_t key_type,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *pt, size_t pt_len)
{
    uint8_t ref[512 + PSA_AEAD_TAG_MAX_SIZE];
    size_t ref_len = 0;
    uint8_t buf[512];
    uint8_t tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t tag_len = 0;
    uint8_t fin_ct[PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) > 0 ?
                   PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) : 1];
    size_t fin_ct_len = 0;
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;
    size_t off;

    st = psa_aead_encrypt(key_id, alg, nonce, nonce_len, aad, aad_len,
                          pt, pt_len, ref, sizeof(ref), &ref_len);
    if (st != PSA_SUCCESS) {
        check_status(st, "inplace: oneshot reference");
        return;
    }

    memcpy(buf, pt, pt_len);
    st = psa_aead_encrypt_setup(&op, key_id, alg);
    check_status(st, "inplace: encrypt_setup");
    if (st != PSA_SUCCESS) {
        return;
    }
    st = psa_aead_set_lengths(&op, aad_len, pt_len);
    check_status(st, "inplace: set_lengths");
    if (st != PSA_SUCCESS) {
        psa_aead_abort(&op);
        return;
    }
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "inplace: set_nonce");
    if (st != PSA_SUCCESS) {
        psa_aead_abort(&op);
        return;
    }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "inplace: update_ad");
    if (st != PSA_SUCCESS) {
        psa_aead_abort(&op);
        return;
    }

    /* Small chunks force several CBC-MAC blocks; in == out throughout. */
    for (off = 0; off < pt_len; off += 5) {
        size_t n = (pt_len - off < 5) ? (pt_len - off) : 5;
        size_t out_len = 0;

        st = psa_aead_update(&op, buf + off, n, buf + off,
                             (size_t)(sizeof(buf) - off), &out_len);
        check_status(st, "inplace: update (in == out)");
        if (st != PSA_SUCCESS) {
            psa_aead_abort(&op);
            return;
        }
        if (out_len != n) {
            check(0, "inplace: update length mismatch");
            psa_aead_abort(&op);
            return;
        }
    }

    st = psa_aead_finish(&op, fin_ct, sizeof(fin_ct), &fin_ct_len,
                         tag, sizeof(tag), &tag_len);
    check_status(st, "inplace: finish");
    if (st != PSA_SUCCESS) {
        psa_aead_abort(&op);
        return;
    }
    psa_aead_abort(&op);

    check(tag_len == ref_len - pt_len, "inplace: tag length");
    check(memcmp(buf, ref, pt_len) == 0,
          "inplace: ciphertext matches reference");
    if (tag_len == ref_len - pt_len && tag_len > 0) {
        check(memcmp(tag, ref + pt_len, tag_len) == 0,
              "inplace: tag matches reference");
    }
}

/* psa_aead_update_ad() must be rejected once payload streaming has started.
 * The AAD is fed to the streaming primitive in one shot on the first
 * psa_aead_update(), so AAD appended after that would never be authenticated
 * and the operation would still produce a valid-looking tag. */
static void test_late_update_ad(psa_key_id_t key_id, psa_algorithm_t alg,
                                int is_ccm, psa_key_type_t key_type,
                                const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *pt, size_t pt_len,
                                int set_lengths)
{
    uint8_t out[PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, 64)];
    size_t out_len = 0;
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;

    /* CCM cannot stream without the declared lengths. */
    if (is_ccm && !set_lengths) {
        return;
    }

    st = psa_aead_encrypt_setup(&op, key_id, alg);
    if (check_status(st, "late_ad: encrypt_setup") != TEST_OK) return;
    if (set_lengths) {
        st = psa_aead_set_lengths(&op, aad_len, pt_len);
        check_status(st, "late_ad: set_lengths");
        if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    }
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "late_ad: set_nonce");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "late_ad: update_ad");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update(&op, pt, pt_len, out, sizeof(out), &out_len);
    check_status(st, "late_ad: update");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }

    st = psa_aead_update_ad(&op, aad, aad_len);
    check(st == PSA_ERROR_BAD_STATE,
          set_lengths ? "late_ad: update_ad after update rejected"
                      : "late_ad: update_ad after update rejected (no lengths)");
    psa_aead_abort(&op);
}

/* PSA_AEAD_FINISH_OUTPUT_SIZE()/PSA_AEAD_VERIFY_OUTPUT_SIZE() are zero for
 * ChaCha20-Poly1305, so a caller that emitted all payload from update() may
 * pass (NULL, 0) as the final output buffer. */
static void test_null_final_output(psa_key_id_t key_id, psa_algorithm_t alg,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *pt, size_t pt_len,
                                   const uint8_t *ref, size_t ref_len)
{
    uint8_t buf[512];
    uint8_t tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t buf_len = 0;
    size_t tag_len = 0;
    size_t fin_len = 1;
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_status_t st;

    if (ref_len < pt_len) {
        check(0, "null_final: short reference");
        return;
    }

    /* Encrypt: all ciphertext comes from update(), finish() emits only the
     * tag into a (NULL, 0) output buffer. */
    st = psa_aead_encrypt_setup(&op, key_id, alg);
    if (check_status(st, "null_final: encrypt_setup") != TEST_OK) return;
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "null_final: set_nonce");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "null_final: update_ad");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update(&op, pt, pt_len, buf, sizeof(buf), &buf_len);
    check_status(st, "null_final: update");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_finish(&op, NULL, 0, &fin_len, tag, sizeof(tag), &tag_len);
    psa_aead_abort(&op);
    check(st == PSA_SUCCESS, "null_final: finish with (NULL, 0) output");
    if (st != PSA_SUCCESS) {
        return;
    }
    check(fin_len == 0, "null_final: finish emitted no ciphertext");
    check(buf_len == pt_len && memcmp(buf, ref, pt_len) == 0,
          "null_final: ciphertext matches reference");
    check(tag_len == ref_len - pt_len &&
          memcmp(tag, ref + pt_len, tag_len) == 0,
          "null_final: tag matches reference");

    /* Decrypt: same shape through psa_aead_verify(). */
    buf_len = 0;
    fin_len = 1;
    op = psa_aead_operation_init();
    st = psa_aead_decrypt_setup(&op, key_id, alg);
    if (check_status(st, "null_final: decrypt_setup") != TEST_OK) return;
    st = psa_aead_set_nonce(&op, nonce, nonce_len);
    check_status(st, "null_final: decrypt set_nonce");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update_ad(&op, aad, aad_len);
    check_status(st, "null_final: decrypt update_ad");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_update(&op, ref, pt_len, buf, sizeof(buf), &buf_len);
    check_status(st, "null_final: decrypt update");
    if (st != PSA_SUCCESS) { psa_aead_abort(&op); return; }
    st = psa_aead_verify(&op, NULL, 0, &fin_len, ref + pt_len,
                         ref_len - pt_len);
    psa_aead_abort(&op);
    check(st == PSA_SUCCESS, "null_final: verify with (NULL, 0) output");
    if (st != PSA_SUCCESS) {
        return;
    }
    check(fin_len == 0, "null_final: verify emitted no plaintext");
    check(buf_len == pt_len && memcmp(buf, pt, pt_len) == 0,
          "null_final: plaintext matches");
}

static int run_algo(const char *name, psa_algorithm_t alg, int is_ccm,
                    psa_key_type_t key_type, size_t key_len,
                    size_t nonce_len, size_t aad_len,
                    const uint8_t *nonce, const uint8_t *aad,
                    const uint8_t *pt, size_t pt_len,
                    psa_key_usage_t usage)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    uint8_t key[32];
    uint8_t ct[512 + PSA_AEAD_TAG_MAX_SIZE];
    size_t ct_len = 0;
    size_t key_bits = key_len * 8;
    size_t chunks[3] = { 5, 16, 33 };
    int i;
    psa_status_t st;

    printf("%s\n", name);
    memset(key, 0xA5, sizeof(key));
    psa_set_key_type(&attrs, key_type);
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, usage);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_import_key(&attrs, key, key_len, &key_id);
    if (check_status(st, "import key") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt(key_id, alg, nonce, nonce_len, aad, aad_len,
                          pt, pt_len, ct, sizeof(ct), &ct_len);
    if (check_status(st, "oneshot encrypt") != TEST_OK) {
        psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    for (i = 0; i < 3; i++) {
        test_multipart_encrypt(key_id, alg, is_ccm, key_type, key_bits,
                               nonce, nonce_len, aad, aad_len, pt, pt_len,
                               chunks[i]);
        test_multipart_decrypt(key_id, alg, is_ccm, key_type, key_bits,
                               nonce, nonce_len, aad, aad_len, ct, ct_len,
                               chunks[i]);
    }

    test_multipart_decrypt_bad_tag(key_id, alg, is_ccm, key_type, key_bits,
                                   nonce, nonce_len, aad, aad_len, ct, ct_len);

    test_late_update_ad(key_id, alg, is_ccm, key_type, nonce, nonce_len,
                        aad, aad_len, pt, pt_len, 1);
    test_late_update_ad(key_id, alg, is_ccm, key_type, nonce, nonce_len,
                        aad, aad_len, pt, pt_len, 0);

    /* Only for the algorithms whose final output size is zero. */
    if (PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) == 0 &&
        PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg) == 0) {
        test_null_final_output(key_id, alg, nonce, nonce_len,
                               aad, aad_len, pt, pt_len, ct, ct_len);
    }

    if (is_ccm) {
        test_inplace_ccm(key_id, alg, key_type, nonce, nonce_len, aad,
                         aad_len, pt, pt_len);
    }

    psa_destroy_key(key_id);
    return (g_failures == 0) ? TEST_OK : TEST_FAIL;
}

int main(void)
{
    static const uint8_t nonce12[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B
    };
    static const uint8_t nonce13[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C
    };
    static const uint8_t aad[7] = {
        0xC0,0x01,0xC0,0x02,0xC0,0x03,0xC0
    };
    uint8_t pt[48];
    int i;
    int ret = TEST_OK;

    for (i = 0; i < (int)sizeof(pt); i++) {
        pt[i] = (uint8_t)(0x10 + i);
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_crypto_init failed\n");
        return TEST_FAIL;
    }

    g_failures = 0;
    if (run_algo("GCM", PSA_ALG_GCM, 0, PSA_KEY_TYPE_AES, 16,
                 sizeof(nonce12), sizeof(aad),
                 nonce12, aad, pt, sizeof(pt),
                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT) == TEST_FAIL)
        ret = TEST_FAIL;

    g_failures = 0;
    if (run_algo("CCM", PSA_ALG_CCM, 1, PSA_KEY_TYPE_AES, 16,
                 sizeof(nonce13), sizeof(aad),
                 nonce13, aad, pt, sizeof(pt),
                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT) == TEST_FAIL)
        ret = TEST_FAIL;

    /* Second CCM lane with a 12-byte nonce (lenSz = 3): the counter
     * increment must agree with the one-shot reference for nonce lengths
     * other than 13, where the CTR bytes above the length field are zero. */
    g_failures = 0;
    if (run_algo("CCM-12", PSA_ALG_CCM, 1, PSA_KEY_TYPE_AES, 16,
                 sizeof(nonce12), sizeof(aad),
                 nonce12, aad, pt, sizeof(pt),
                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT) == TEST_FAIL)
        ret = TEST_FAIL;

    g_failures = 0;
    if (run_algo("ChaCha20-Poly1305", PSA_ALG_CHACHA20_POLY1305, 0,
                 PSA_KEY_TYPE_CHACHA20, 32,
                 sizeof(nonce12),
                 sizeof(aad), nonce12, aad, pt, sizeof(pt),
                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT) == TEST_FAIL)
        ret = TEST_FAIL;

    printf(ret == TEST_OK ? "PASS: multipart AEAD output-size contract\n"
                          : "FAIL: multipart AEAD output-size contract\n");
    return ret;
}
