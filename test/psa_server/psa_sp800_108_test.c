/* psa_sp800_108_test.c
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
 * Coverage test for wolfPSA SP 800-108r1 counter-mode KDFs (PSA 1.4).
 *
 * Reference-value strategy
 * ------------------------
 * Expected outputs are computed inside the test by independently
 * reconstructing K(1)||K(2)||... at the MAC level using psa_mac_compute
 * with hand-assembled fixed-input buffers.  This validates the KDF
 * plumbing and encoding format independently of the MAC engine (which
 * has its own known-answer tests elsewhere).
 *
 * HMAC construction (PSA 1.4 §10.8):
 *   K(i) = HMAC(secret, [i]_4 || Label || 0x00 || Context || [L]_4)
 *   [L]_4 = total output length in bits, big-endian 4 bytes
 *   L is snapshotted from capacity at the first output_bytes() call
 *   (before capacity is decremented).  set_capacity(N) before any output
 *   call fixes L = N bytes = N*8 bits.
 *
 * CMAC construction (PSA 1.4 §10.8):
 *   K_0 = CMAC(secret, Label || 0x00 || Context || [L]_4)
 *   K(i) = CMAC(secret, [i]_4 || Label || 0x00 || Context || [L]_4 || K_0)
 *
 * Fixed test vectors
 *   HMAC: 32-byte secret = {0x0b, 0x0b, ...}, label = "label", context = "context"
 *   CMAC: 16-byte AES key = {0x0b, 0x0b, ...}, same label/context
 */

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <wolfpsa/psa/crypto.h>

/* -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------*/

static int expect_status(const char *label, psa_status_t status,
                         psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s status=%d expected=%d\n", label, (int)status,
               (int)expected);
        return 1;
    }
    return 0;
}

/* Compute one HMAC block using PSA.
 *
 * Imports the raw secret bytes as a PSA_KEY_TYPE_HMAC key, calls
 * psa_mac_compute over the provided fixed-input buffer, and destroys the
 * temporary key.  out must be at least 32 bytes (SHA-256 digest size). */
static int hmac_sha256(const uint8_t *secret, size_t secret_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t *out, size_t *out_len)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t kid = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, (psa_key_bits_t)(secret_len * 8u));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, secret, secret_len, &kid);
    if (st != PSA_SUCCESS) {
        printf("FAIL hmac_sha256 import status=%d\n", (int)st);
        return 1;
    }

    st = psa_mac_compute(kid, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         data, data_len, out, 32u, out_len);
    psa_destroy_key(kid);
    if (st != PSA_SUCCESS) {
        printf("FAIL hmac_sha256 compute status=%d\n", (int)st);
        return 1;
    }
    return 0;
}

/* Compute one CMAC block using PSA.
 *
 * Imports the raw AES key bytes, calls psa_mac_compute with PSA_ALG_CMAC
 * over the fixed-input buffer.  out must be at least 16 bytes. */
static int aes_cmac(const uint8_t *aes_key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t *out_len)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t kid = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, (psa_key_bits_t)(key_len * 8u));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_CMAC);

    st = psa_import_key(&attrs, aes_key, key_len, &kid);
    if (st != PSA_SUCCESS) {
        printf("FAIL aes_cmac import status=%d\n", (int)st);
        return 1;
    }

    st = psa_mac_compute(kid, PSA_ALG_CMAC,
                         data, data_len, out, 16u, out_len);
    psa_destroy_key(kid);
    if (st != PSA_SUCCESS) {
        printf("FAIL aes_cmac compute status=%d\n", (int)st);
        return 1;
    }
    return 0;
}

/*
 * Assemble the HMAC fixed-input for counter i:
 *   [i]_4 || label_data || 0x00 || context_data || [L]_4
 * L_bits is total output length in bits (32-bit value).
 */
static size_t build_hmac_fixed_input(uint8_t *buf, size_t bufsz,
                                     uint32_t counter,
                                     const uint8_t *label, size_t label_len,
                                     const uint8_t *context, size_t ctx_len,
                                     uint32_t L_bits)
{
    size_t pos = 0;

    (void)bufsz; /* caller ensures sufficient size */

    /* [i]_4 */
    buf[pos++] = (uint8_t)((counter >> 24) & 0xff);
    buf[pos++] = (uint8_t)((counter >> 16) & 0xff);
    buf[pos++] = (uint8_t)((counter >>  8) & 0xff);
    buf[pos++] = (uint8_t)( counter        & 0xff);
    /* Label */
    if (label_len > 0) {
        memcpy(buf + pos, label, label_len);
        pos += label_len;
    }
    /* separator */
    buf[pos++] = 0x00u;
    /* Context */
    if (ctx_len > 0) {
        memcpy(buf + pos, context, ctx_len);
        pos += ctx_len;
    }
    /* [L]_4 */
    buf[pos++] = (uint8_t)((L_bits >> 24) & 0xff);
    buf[pos++] = (uint8_t)((L_bits >> 16) & 0xff);
    buf[pos++] = (uint8_t)((L_bits >>  8) & 0xff);
    buf[pos++] = (uint8_t)( L_bits        & 0xff);

    return pos;
}

/*
 * Reconstruct HMAC-SHA-256 SP800-108 counter-mode output.
 *
 * Produces num_blocks * 32 bytes into out_ref (caller allocates).
 * capacity_bytes is what set_capacity() was called with; this fixes L.
 */
static int reconstruct_hmac(const uint8_t *secret, size_t secret_len,
                             const uint8_t *label, size_t label_len,
                             const uint8_t *context, size_t ctx_len,
                             size_t capacity_bytes,
                             uint8_t *out_ref, size_t out_len)
{
    /*
     * L = capacity_bytes * 8 bits (L is snapshotted from capacity before any
     * decrement, i.e. the value set by set_capacity()).
     */
    uint32_t L_bits = (uint32_t)(capacity_bytes * 8u);
    uint8_t fi[4 + 255 + 1 + 255 + 4]; /* max fixed-input size */
    uint8_t block[32];
    size_t fi_len;
    size_t mac_out_len;
    uint32_t counter;
    size_t offset = 0;

    for (counter = 1u; offset < out_len; counter++) {
        size_t copy_len;

        fi_len = build_hmac_fixed_input(fi, sizeof(fi), counter,
                                        label, label_len,
                                        context, ctx_len,
                                        L_bits);

        if (hmac_sha256(secret, secret_len, fi, fi_len,
                        block, &mac_out_len) != 0) {
            return 1;
        }

        copy_len = 32u;
        if (offset + copy_len > out_len) {
            copy_len = out_len - offset;
        }
        memcpy(out_ref + offset, block, copy_len);
        offset += copy_len;
    }
    return 0;
}

/*
 * Reconstruct CMAC SP800-108 counter-mode output.
 *
 * K_0 = CMAC(secret, Label || 0x00 || Context || [L]_4)
 * K(i) = CMAC(secret, [i]_4 || Label || 0x00 || Context || [L]_4 || K_0)
 */
static int reconstruct_cmac(const uint8_t *aes_key, size_t key_len,
                             const uint8_t *label, size_t label_len,
                             const uint8_t *context, size_t ctx_len,
                             size_t capacity_bytes,
                             uint8_t *out_ref, size_t out_len)
{
    uint32_t L_bits = (uint32_t)(capacity_bytes * 8u);
    /* K_0 fixed-input: Label || 0x00 || Context || [L]_4 */
    uint8_t k0_fi[255 + 1 + 255 + 4];
    size_t k0_fi_len = 0;
    uint8_t K0[16];
    size_t mac_out_len;
    /* K(i) fixed-input: [i]_4 || Label || 0x00 || Context || [L]_4 || K_0 */
    uint8_t ki_fi[4 + 255 + 1 + 255 + 4 + 16];
    size_t ki_fi_len;
    uint8_t block[16];
    uint32_t counter;
    size_t offset = 0;
    uint32_t L_big;

    L_big = L_bits;

    /* Build K_0 fixed-input */
    if (label_len > 0) {
        memcpy(k0_fi + k0_fi_len, label, label_len);
        k0_fi_len += label_len;
    }
    k0_fi[k0_fi_len++] = 0x00u;
    if (ctx_len > 0) {
        memcpy(k0_fi + k0_fi_len, context, ctx_len);
        k0_fi_len += ctx_len;
    }
    k0_fi[k0_fi_len++] = (uint8_t)((L_big >> 24) & 0xff);
    k0_fi[k0_fi_len++] = (uint8_t)((L_big >> 16) & 0xff);
    k0_fi[k0_fi_len++] = (uint8_t)((L_big >>  8) & 0xff);
    k0_fi[k0_fi_len++] = (uint8_t)( L_big        & 0xff);

    /* Compute K_0 */
    if (aes_cmac(aes_key, key_len, k0_fi, k0_fi_len, K0, &mac_out_len) != 0) {
        return 1;
    }

    /* K(i) loop */
    for (counter = 1u; offset < out_len; counter++) {
        size_t copy_len;

        ki_fi_len = 0;
        /* [i]_4 */
        ki_fi[ki_fi_len++] = (uint8_t)((counter >> 24) & 0xff);
        ki_fi[ki_fi_len++] = (uint8_t)((counter >> 16) & 0xff);
        ki_fi[ki_fi_len++] = (uint8_t)((counter >>  8) & 0xff);
        ki_fi[ki_fi_len++] = (uint8_t)( counter        & 0xff);
        if (label_len > 0) {
            memcpy(ki_fi + ki_fi_len, label, label_len);
            ki_fi_len += label_len;
        }
        ki_fi[ki_fi_len++] = 0x00u;
        if (ctx_len > 0) {
            memcpy(ki_fi + ki_fi_len, context, ctx_len);
            ki_fi_len += ctx_len;
        }
        ki_fi[ki_fi_len++] = (uint8_t)((L_big >> 24) & 0xff);
        ki_fi[ki_fi_len++] = (uint8_t)((L_big >> 16) & 0xff);
        ki_fi[ki_fi_len++] = (uint8_t)((L_big >>  8) & 0xff);
        ki_fi[ki_fi_len++] = (uint8_t)( L_big        & 0xff);
        /* K_0 appended */
        memcpy(ki_fi + ki_fi_len, K0, 16u);
        ki_fi_len += 16u;

        if (aes_cmac(aes_key, key_len, ki_fi, ki_fi_len, block, &mac_out_len) != 0) {
            return 1;
        }

        copy_len = 16u;
        if (offset + copy_len > out_len) {
            copy_len = out_len - offset;
        }
        memcpy(out_ref + offset, block, copy_len);
        offset += copy_len;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Test vectors
 * -------------------------------------------------------------------------*/

/* 32-byte HMAC secret: all 0x0b */
static const uint8_t g_hmac_secret[32] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

/* 16-byte AES-128 CMAC secret: all 0x0b */
static const uint8_t g_cmac_secret[16] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t g_label[]   = { 'l', 'a', 'b', 'e', 'l' };
static const uint8_t g_context[] = { 'c', 'o', 'n', 't', 'e', 'x', 't' };

/* -------------------------------------------------------------------------
 * Test case 1: HMAC-SHA-256 two separate output_bytes(32) calls match K(1)||K(2)
 *
 * set_capacity(64) → L = 64 bytes = 512 bits = 0x00000200
 * K(1) = HMAC(secret, 00000001 || "label" || 00 || "context" || 00000200)
 * K(2) = HMAC(secret, 00000002 || "label" || 00 || "context" || 00000200)
 * -------------------------------------------------------------------------*/
static int test_hmac_two_output_calls(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out_a[32], out_b[32];
    uint8_t ref[64];
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc1 setup", st, PSA_SUCCESS) != 0) return 1;

    /* set_capacity BEFORE first output fixes L */
    st = psa_key_derivation_set_capacity(&op, 64u);
    if (expect_status("tc1 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        g_hmac_secret, sizeof(g_hmac_secret));
    if (expect_status("tc1 input SECRET", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        g_label, sizeof(g_label));
    if (expect_status("tc1 input LABEL", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                                        g_context, sizeof(g_context));
    if (expect_status("tc1 input CONTEXT", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_output_bytes(&op, out_a, 32u);
    if (expect_status("tc1 output_bytes[0..31]", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_output_bytes(&op, out_b, 32u);
    if (expect_status("tc1 output_bytes[32..63]", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);

    /* Reconstruct K(1)||K(2) independently at the MAC level.
     * capacity = 64 bytes → L = 512 bits. */
    if (reconstruct_hmac(g_hmac_secret, sizeof(g_hmac_secret),
                         g_label, sizeof(g_label),
                         g_context, sizeof(g_context),
                         64u, ref, 64u) != 0) {
        return 1;
    }

    if (memcmp(out_a, ref,      32u) != 0) {
        printf("FAIL tc1: K(1) mismatch\n");
        return 1;
    }
    if (memcmp(out_b, ref + 32, 32u) != 0) {
        printf("FAIL tc1: K(2) mismatch\n");
        return 1;
    }

    printf("PASS tc1: HMAC two output calls match K(1)||K(2)\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 2: Same derivation but output in one 64-byte call (call-granularity
 * independence).  Must produce identical bytes to tc1.
 * -------------------------------------------------------------------------*/
static int test_hmac_single_64_byte_call(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out[64];
    uint8_t ref[64];
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc2 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_set_capacity(&op, 64u);
    if (expect_status("tc2 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        g_hmac_secret, sizeof(g_hmac_secret));
    if (expect_status("tc2 input SECRET", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        g_label, sizeof(g_label));
    if (expect_status("tc2 input LABEL", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                                        g_context, sizeof(g_context));
    if (expect_status("tc2 input CONTEXT", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_output_bytes(&op, out, 64u);
    if (expect_status("tc2 output_bytes[0..63]", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);

    /* Same reconstruction as tc1; must be byte-identical */
    if (reconstruct_hmac(g_hmac_secret, sizeof(g_hmac_secret),
                         g_label, sizeof(g_label),
                         g_context, sizeof(g_context),
                         64u, ref, 64u) != 0) {
        return 1;
    }

    if (memcmp(out, ref, 64u) != 0) {
        printf("FAIL tc2: single 64-byte output differs from K(1)||K(2)\n");
        return 1;
    }

    printf("PASS tc2: single 64-byte call == two 32-byte calls\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 3: CMAC variant.
 *
 * set_capacity(32) → L = 32 bytes = 256 bits = 0x00000100
 * K_0 = CMAC(secret, "label" || 0x00 || "context" || 00000100)
 * K(1) = CMAC(secret, 00000001 || "label" || 0x00 || "context" || 00000100 || K_0)
 * K(2) = CMAC(secret, 00000002 || "label" || 0x00 || "context" || 00000100 || K_0)
 * Output = K(1) || K(2)  (32 bytes total, 16 bytes per CMAC block)
 * -------------------------------------------------------------------------*/
static int test_cmac_basic(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_CMAC;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out[32];
    uint8_t ref[32];
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP tc3: CMAC not supported in this build\n");
        return 0;
    }
    if (expect_status("tc3 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_set_capacity(&op, 32u);
    if (expect_status("tc3 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        g_cmac_secret, sizeof(g_cmac_secret));
    if (expect_status("tc3 input SECRET", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        g_label, sizeof(g_label));
    if (expect_status("tc3 input LABEL", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                                        g_context, sizeof(g_context));
    if (expect_status("tc3 input CONTEXT", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_output_bytes(&op, out, 32u);
    if (expect_status("tc3 output_bytes(32)", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);

    if (reconstruct_cmac(g_cmac_secret, sizeof(g_cmac_secret),
                         g_label, sizeof(g_label),
                         g_context, sizeof(g_context),
                         32u, ref, 32u) != 0) {
        return 1;
    }

    if (memcmp(out, ref, 32u) != 0) {
        printf("FAIL tc3: CMAC output mismatch\n");
        return 1;
    }

    printf("PASS tc3: CMAC K(1)||K(2) matches reconstruction\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 4: SECRET via psa_key_derivation_input_key with PSA_KEY_TYPE_DERIVE.
 *
 * Import the same HMAC secret bytes as a PSA_KEY_TYPE_DERIVE key with
 * alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256).  Derivation must
 * produce identical output to tc1 (input_bytes with same secret).
 * -------------------------------------------------------------------------*/
static int test_hmac_input_key(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t key_attrs = psa_key_attributes_init();
    psa_key_id_t kid = PSA_KEY_ID_NULL;
    uint8_t out[64];
    uint8_t ref[64];
    psa_status_t st;

    /* Import the secret as a DERIVE key whose permitted algorithm is the KDF
     * algorithm.  input_key() checks key_alg == ctx->alg. */
    psa_set_key_type(&key_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&key_attrs,
                     (psa_key_bits_t)(sizeof(g_hmac_secret) * 8u));
    psa_set_key_usage_flags(&key_attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attrs, alg);

    st = psa_import_key(&key_attrs, g_hmac_secret, sizeof(g_hmac_secret), &kid);
    if (expect_status("tc4 import DERIVE key", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc4 setup", st, PSA_SUCCESS) != 0) {
        psa_destroy_key(kid);
        return 1;
    }

    st = psa_key_derivation_set_capacity(&op, 64u);
    if (expect_status("tc4 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_destroy_key(kid);
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, kid);
    if (expect_status("tc4 input_key SECRET", st, PSA_SUCCESS) != 0) {
        psa_destroy_key(kid);
        psa_key_derivation_abort(&op);
        return 1;
    }
    psa_destroy_key(kid);

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        g_label, sizeof(g_label));
    if (expect_status("tc4 input LABEL", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                                        g_context, sizeof(g_context));
    if (expect_status("tc4 input CONTEXT", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_output_bytes(&op, out, 64u);
    if (expect_status("tc4 output_bytes", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);

    /* Expected: same as tc1/tc2 reconstruction */
    if (reconstruct_hmac(g_hmac_secret, sizeof(g_hmac_secret),
                         g_label, sizeof(g_label),
                         g_context, sizeof(g_context),
                         64u, ref, 64u) != 0) {
        return 1;
    }

    if (memcmp(out, ref, 64u) != 0) {
        printf("FAIL tc4: input_key output differs from input_bytes output\n");
        return 1;
    }

    printf("PASS tc4: input_key produces same output as input_bytes\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 5: Omitting LABEL and CONTEXT entirely.
 *
 * Both are optional; derivation must succeed with empty label/context.
 * Reconstruction uses empty label/context (zero-length):
 *   K(i) = HMAC(secret, [i]_4 || 0x00 || [L]_4)
 * -------------------------------------------------------------------------*/
static int test_hmac_no_label_no_context(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out[64];
    uint8_t ref[64];
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc5 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_set_capacity(&op, 64u);
    if (expect_status("tc5 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    /* SECRET only — no LABEL, no CONTEXT */
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        g_hmac_secret, sizeof(g_hmac_secret));
    if (expect_status("tc5 input SECRET", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_output_bytes(&op, out, 64u);
    if (expect_status("tc5 output_bytes", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);

    /* Reconstruction with empty label and context */
    if (reconstruct_hmac(g_hmac_secret, sizeof(g_hmac_secret),
                         NULL, 0u,
                         NULL, 0u,
                         64u, ref, 64u) != 0) {
        return 1;
    }

    if (memcmp(out, ref, 64u) != 0) {
        printf("FAIL tc5: empty label/context output mismatch\n");
        return 1;
    }

    printf("PASS tc5: empty label+context derivation matches reconstruction\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 6: output_key produces a 128-bit AES key.
 *
 * Verify that psa_key_derivation_output_key works end-to-end (AES key
 * type is unstructured, fits 16 bytes = 128 bits).
 * -------------------------------------------------------------------------*/
static int test_hmac_output_key(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t out_attrs = psa_key_attributes_init();
    psa_key_id_t derived_key = PSA_KEY_ID_NULL;
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc6 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_set_capacity(&op, 16u);
    if (expect_status("tc6 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        g_hmac_secret, sizeof(g_hmac_secret));
    if (expect_status("tc6 input SECRET", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        g_label, sizeof(g_label));
    if (expect_status("tc6 input LABEL", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                                        g_context, sizeof(g_context));
    if (expect_status("tc6 input CONTEXT", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_set_key_type(&out_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&out_attrs, 128u);
    psa_set_key_usage_flags(&out_attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&out_attrs, PSA_ALG_CTR);

    st = psa_key_derivation_output_key(&out_attrs, &op, &derived_key);
    if (expect_status("tc6 output_key(AES-128)", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_destroy_key(derived_key);
    psa_key_derivation_abort(&op);

    printf("PASS tc6: output_key produced AES-128 key\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 7: CMAC variant with a 15-byte secret must fail.
 *
 * AES key size must be 16, 24, or 32 bytes.  A 15-byte secret is invalid.
 * The error must occur at output_bytes() (CMAC validity is checked at
 * derivation time, not at input_bytes() time).
 * -------------------------------------------------------------------------*/
static int test_cmac_invalid_key_len(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_CMAC;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static const uint8_t bad_secret[15] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    uint8_t out[16];
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        printf("SKIP tc7: CMAC not supported in this build\n");
        return 0;
    }
    if (expect_status("tc7 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_set_capacity(&op, 16u);
    if (expect_status("tc7 set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        bad_secret, sizeof(bad_secret));
    if (st != PSA_SUCCESS) {
        /* Library detected the bad length at input time — also acceptable */
        if (st != PSA_ERROR_INVALID_ARGUMENT) {
            printf("FAIL tc7: expected PSA_ERROR_INVALID_ARGUMENT or SUCCESS "
                   "at input_bytes, got %d\n", (int)st);
            psa_key_derivation_abort(&op);
            return 1;
        }
        printf("PASS tc7: CMAC 15-byte secret rejected at input_bytes "
               "(PSA_ERROR_INVALID_ARGUMENT)\n");
        psa_key_derivation_abort(&op);
        return 0;
    }

    /* Library accepted the secret at input time; error must surface at output */
    st = psa_key_derivation_output_bytes(&op, out, 16u);
    if (st == PSA_SUCCESS) {
        printf("FAIL tc7: CMAC with 15-byte secret must not succeed\n");
        psa_key_derivation_abort(&op);
        return 1;
    }
    if (st != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL tc7: expected PSA_ERROR_INVALID_ARGUMENT at output_bytes, "
               "got %d\n", (int)st);
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);
    printf("PASS tc7: CMAC 15-byte secret rejected at output_bytes "
           "(PSA_ERROR_INVALID_ARGUMENT)\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 8: PSA_KEY_DERIVATION_INPUT_SALT must be rejected for SP800-108.
 *
 * Allowed steps are: SECRET, LABEL, CONTEXT only.  SALT must return
 * PSA_ERROR_INVALID_ARGUMENT.
 * -------------------------------------------------------------------------*/
static int test_hmac_salt_rejected(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static const uint8_t salt[] = { 0x01, 0x02, 0x03, 0x04 };
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc8 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, sizeof(salt));
    if (st == PSA_SUCCESS) {
        printf("BUG tc8: library accepted SALT input for SP800-108 — "
               "SALT is not a valid step for this algorithm\n");
        psa_key_derivation_abort(&op);
        return 1;
    }
    if (st != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL tc8: expected PSA_ERROR_INVALID_ARGUMENT for SALT, "
               "got %d\n", (int)st);
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);
    printf("PASS tc8: SALT step correctly rejected with "
           "PSA_ERROR_INVALID_ARGUMENT\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test case 9: SP800-108 steps must not be provided twice.
 * -------------------------------------------------------------------------*/
static int test_hmac_duplicate_step_rejected(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static const uint8_t secret[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static const uint8_t label[] = { 'l', 'a', 'b', 'e', 'l' };
    psa_status_t st;

    st = psa_key_derivation_setup(&op, alg);
    if (expect_status("tc9 setup", st, PSA_SUCCESS) != 0) return 1;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret));
    if (expect_status("tc9 input SECRET", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret));
    if (expect_status("tc9 duplicate SECRET", st,
                      PSA_ERROR_BAD_STATE) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        label, sizeof(label));
    if (expect_status("tc9 input LABEL", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        label, sizeof(label));
    if (expect_status("tc9 duplicate LABEL", st,
                      PSA_ERROR_BAD_STATE) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }

    psa_key_derivation_abort(&op);
    printf("PASS tc9: duplicate SP800-108 steps rejected with "
           "PSA_ERROR_BAD_STATE\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------*/
/* Setup an SP800-108 HMAC-SHA256 operation with the given capacity and the
 * standard secret/label/context inputs. Returns 0 on success, 1 on failure
 * (op aborted). */
static int sp800_hmac_setup(psa_key_derivation_operation_t *op,
                            psa_algorithm_t alg, size_t capacity)
{
    psa_status_t st;

    st = psa_key_derivation_setup(op, alg);
    if (expect_status("large-cap setup", st, PSA_SUCCESS) != 0)
        return 1;
    st = psa_key_derivation_set_capacity(op, capacity);
    if (expect_status("large-cap set_capacity", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(op);
        return 1;
    }
    st = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        g_hmac_secret, sizeof(g_hmac_secret));
    if (expect_status("large-cap secret", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(op);
        return 1;
    }
    st = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_LABEL,
                                        g_label, sizeof(g_label));
    if (expect_status("large-cap label", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(op);
        return 1;
    }
    st = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                                        g_context, sizeof(g_context));
    if (expect_status("large-cap context", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(op);
        return 1;
    }
    return 0;
}

/* Test case: large-capacity lazy path.
 *
 * A capacity above the output-cache bound forces the derivation onto the
 * lazy, non-cached path. Verify prefix-consistency across the offset==0
 * direct-compute branch and the offset>0 recompute-and-slice branch: two
 * consecutive output_bytes() calls, a single output_bytes(64) call on a fresh
 * identical derivation, and the independent K(1)||K(2) reconstruction must all
 * agree. Existing SP800-108 tests only use small capacities that stay on the
 * cached path, so this exercises the otherwise-untested lazy branches. */
static int test_hmac_large_capacity_lazy(void)
{
    psa_algorithm_t alg = PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256);
    size_t cap = 100000u; /* above the 64 KB output-cache bound */
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out_a[32];
    uint8_t out_b[32];
    uint8_t out_single[64];
    uint8_t ref[64];
    psa_status_t st;

    /* Two consecutive 32-byte calls: offset 0 (direct compute) then offset 32
     * (recompute-and-slice). */
    if (sp800_hmac_setup(&op, alg, cap) != 0)
        return 1;
    st = psa_key_derivation_output_bytes(&op, out_a, sizeof(out_a));
    if (expect_status("large-cap out_a", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }
    st = psa_key_derivation_output_bytes(&op, out_b, sizeof(out_b));
    if (expect_status("large-cap out_b", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }
    psa_key_derivation_abort(&op);

    /* Single 64-byte call on a fresh identical derivation. */
    op = psa_key_derivation_operation_init();
    if (sp800_hmac_setup(&op, alg, cap) != 0)
        return 1;
    st = psa_key_derivation_output_bytes(&op, out_single, sizeof(out_single));
    if (expect_status("large-cap single", st, PSA_SUCCESS) != 0) {
        psa_key_derivation_abort(&op);
        return 1;
    }
    psa_key_derivation_abort(&op);

    /* Independent reconstruction (L = capacity in bits). */
    if (reconstruct_hmac(g_hmac_secret, sizeof(g_hmac_secret),
                         g_label, sizeof(g_label),
                         g_context, sizeof(g_context),
                         cap, ref, sizeof(ref)) != 0) {
        printf("FAIL large-cap: reconstruction failed\n");
        return 1;
    }

    if (memcmp(out_a, ref, 32u) != 0) {
        printf("FAIL large-cap: K(1) mismatch (lazy direct-compute)\n");
        return 1;
    }
    if (memcmp(out_b, ref + 32, 32u) != 0) {
        printf("FAIL large-cap: K(2) mismatch (lazy recompute-and-slice)\n");
        return 1;
    }
    if (memcmp(out_single, ref, 64u) != 0) {
        printf("FAIL large-cap: single-call mismatch\n");
        return 1;
    }

    printf("PASS large-cap: SP800-108 lazy path prefix-consistent\n");
    return 0;
}

int main(void)
{
    psa_status_t st;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)st);
        return 1;
    }

    if (test_hmac_two_output_calls()    != 0) return 1;
    if (test_hmac_single_64_byte_call() != 0) return 1;
    if (test_cmac_basic()               != 0) return 1;
    if (test_hmac_input_key()           != 0) return 1;
    if (test_hmac_no_label_no_context() != 0) return 1;
    if (test_hmac_output_key()          != 0) return 1;
    if (test_cmac_invalid_key_len()     != 0) return 1;
    if (test_hmac_salt_rejected()       != 0) return 1;
    if (test_hmac_duplicate_step_rejected() != 0) return 1;
    if (test_hmac_large_capacity_lazy()     != 0) return 1;

    printf("SP800-108 counter-mode KDF test: OK\n");
    return 0;
}
