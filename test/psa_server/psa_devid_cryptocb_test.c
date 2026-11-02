/* psa_devid_cryptocb_test.c
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
 * Checks that every algorithm family reaches a registered crypto callback,
 * both through wolfCrypt's own device selection and through an explicit
 * wolfPSA_SetDefaultDevID().
 *
 * The probe device deliberately sits on a non-zero devId: an algorithm that
 * skipped its wc_*Init() call carries devId 0 from its zeroed context and
 * would go missing from the counts.
 *
 * Unlike the other tests here this one inspects wolfCrypt structures, so it
 * must build against the same user_settings.h as the library itself.
 */

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfpsa/psa/crypto.h>
#include <wolfpsa/psa_engine.h>

#include <stdio.h>
#include <string.h>

/* Arbitrary devId standing in for an offload backend. */
#define TEST_DEVID 0x505341

/* Registered first, so wolfCrypt's own selection picks it when wolfPSA has
 * no explicit devId. Non-zero on purpose, see the note above. */
#define PROBE_DEVID 5

/* When set to a WC_PK_TYPE_* keygen value, the callback claims that key
 * generation succeeded without putting a scalar in the key. That is the
 * backend that keeps the private key on the device, which psa_generate_key()
 * has to refuse rather than export as an all-zero scalar. One value rather
 * than a flag per curve, so a test can only ever mute the one keygen it is
 * checking. */
static int mute_keygen_pk_type = WC_PK_TYPE_NONE;

static int seen[WC_ALGO_TYPE_MAX + 1];
static int seen_total;
static int seen_wrong_devid;
static int expect_devid = INVALID_DEVID;

static const char *algo_name(int algo_type)
{
    switch (algo_type) {
        case WC_ALGO_TYPE_HASH:   return "hash";
        case WC_ALGO_TYPE_CIPHER: return "cipher";
        case WC_ALGO_TYPE_PK:     return "pk";
        case WC_ALGO_TYPE_RNG:    return "rng";
        case WC_ALGO_TYPE_SEED:   return "seed";
        case WC_ALGO_TYPE_HMAC:   return "hmac";
        case WC_ALGO_TYPE_CMAC:   return "cmac";
        default:                  return "other";
    }
}

/* Sink for the borrowed HMAC key, so the read below is not optimised away. */
static volatile byte key_sink;

/* Records the dispatch and declines it, so wolfCrypt falls back to software
 * and the PSA results stay correct.
 *
 * The HMAC arm reads the key the way a real backend would. wc_HmacSetKey()
 * stores the caller's buffer in Hmac.keyRaw rather than copying it, so this
 * is what catches the operation outliving the key material. */
static int count_cb(int devId, wc_CryptoInfo *info, void *ctx)
{
    (void)ctx;

    if (devId != expect_devid) {
        seen_wrong_devid++;
    }
    else if (info != NULL && info->algo_type >= 0 &&
             info->algo_type <= WC_ALGO_TYPE_MAX) {
        seen[info->algo_type]++;
    }
    seen_total++;

    if (info != NULL && info->algo_type == WC_ALGO_TYPE_HMAC &&
        info->hmac.hmac != NULL && info->hmac.hmac->keyRaw != NULL) {
        word16 i;
        for (i = 0; i < info->hmac.hmac->keyLen; i++) {
            key_sink = info->hmac.hmac->keyRaw[i];
        }
    }

    if (mute_keygen_pk_type != WC_PK_TYPE_NONE && info != NULL &&
        info->algo_type == WC_ALGO_TYPE_PK &&
        info->pk.type == mute_keygen_pk_type) {
        /* Success, but the key is left without a private scalar. */
        return 0;
    }

    return CRYPTOCB_UNAVAILABLE;
}

static void reset_counts(int devId)
{
    XMEMSET(seen, 0, sizeof(seen));
    seen_total = 0;
    seen_wrong_devid = 0;
    expect_devid = devId;
}

static int fail(const char *label, psa_status_t status)
{
    printf("FAIL %s status=%d\n", label, (int)status);
    return 1;
}

static int exercise_random(void)
{
    uint8_t out[16];
    psa_status_t st;

    st = psa_generate_random(out, sizeof(out));
    if (st != PSA_SUCCESS)
        return fail("psa_generate_random", st);
    return 0;
}

static int exercise_hash(void)
{
    static const uint8_t msg[] = "wolfPSA devId coverage";
    uint8_t digest[PSA_HASH_MAX_SIZE];
    size_t digest_len = 0;
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          digest, sizeof(digest), &digest_len);
    if (st != PSA_SUCCESS)
        return fail("psa_hash_compute", st);
    return 0;
}

static int exercise_mac(psa_algorithm_t alg, psa_key_type_t type,
                        size_t key_len, const char *label)
{
    static const uint8_t msg[] = "wolfPSA devId coverage";
    uint8_t key_bytes[32];
    uint8_t mac[PSA_MAC_MAX_SIZE];
    size_t mac_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(key_bytes, 0x5a, sizeof(key_bytes));

    psa_set_key_type(&attr, type);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, alg);

    st = psa_import_key(&attr, key_bytes, key_len, &key);
    if (st != PSA_SUCCESS)
        return fail(label, st);

    st = psa_mac_compute(key, alg, msg, sizeof(msg) - 1,
                         mac, sizeof(mac), &mac_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail(label, st);
    return 0;
}

static int exercise_cipher(void)
{
    static const uint8_t plain[32] = { 0 };
    uint8_t key_bytes[16];
    uint8_t out[64];
    size_t out_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(key_bytes, 0x2b, sizeof(key_bytes));

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attr, key_bytes, sizeof(key_bytes), &key);
    if (st != PSA_SUCCESS)
        return fail("aes import", st);

    st = psa_cipher_encrypt(key, PSA_ALG_CBC_NO_PADDING, plain, sizeof(plain),
                            out, sizeof(out), &out_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_cipher_encrypt", st);
    return 0;
}

static int exercise_ecdsa(void)
{
    uint8_t digest[32];
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(digest, 0x11, sizeof(digest));

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("ecc generate", st);

    st = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       digest, sizeof(digest), sig, sizeof(sig), &sig_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_sign_hash ecdsa", st);
    return 0;
}

#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
/* PSA_ALG_DETERMINISTIC_ECDSA promises RFC 6979, and the crypto callback
 * contract carries no deterministic flag, so wolfPSA pins that algorithm to
 * local execution. Two things have to hold: the signature is reproducible,
 * and the sign never reaches the device even though one is selected. The
 * second is the real guard, because the declining callback in this test
 * leaves the software path reproducible either way.
 *
 * Called with a device selected and the counters freshly reset. */
static int check_deterministic_ecdsa_stays_local(void)
{
    uint8_t digest[32];
    uint8_t sig_a[PSA_SIGNATURE_MAX_SIZE];
    uint8_t sig_b[PSA_SIGNATURE_MAX_SIZE];
    size_t len_a = 0;
    size_t len_b = 0;
    psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    XMEMSET(digest, 0x33, sizeof(digest));

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, alg);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("deterministic ecdsa generate", st);

    /* Key generation is allowed to offload; only the signing is measured. */
    reset_counts(expect_devid);

    st = psa_sign_hash(key, alg, digest, sizeof(digest),
                       sig_a, sizeof(sig_a), &len_a);
    if (st != PSA_SUCCESS) {
        ret = fail("deterministic ecdsa sign 1", st);
    }

    if (ret == 0) {
        st = psa_sign_hash(key, alg, digest, sizeof(digest),
                           sig_b, sizeof(sig_b), &len_b);
        if (st != PSA_SUCCESS)
            ret = fail("deterministic ecdsa sign 2", st);
    }

    if (ret == 0 && (len_a != len_b ||
                     XMEMCMP(sig_a, sig_b, len_a) != 0)) {
        printf("FAIL deterministic ECDSA produced two different"
               " signatures\n");
        ret = 1;
    }

    if (ret == 0 && seen[WC_ALGO_TYPE_PK] != 0) {
        printf("FAIL deterministic ECDSA dispatched %d pk operation(s) to a"
               " device\n", seen[WC_ALGO_TYPE_PK]);
        ret = 1;
    }
    else if (ret == 0) {
        printf("deterministic ECDSA: stayed local\n");
    }

    psa_destroy_key(key);
    return ret;
}
#endif /* WOLFSSL_ECDSA_DETERMINISTIC_K */

#ifdef HAVE_ED25519
static int exercise_eddsa(void)
{
    static const uint8_t msg[] = "wolfPSA devId coverage";
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("ed25519 generate", st);

    st = psa_sign_message(key, PSA_ALG_PURE_EDDSA, msg, sizeof(msg) - 1,
                          sig, sizeof(sig), &sig_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_sign_message ed25519", st);
    return 0;
}
#endif /* HAVE_ED25519 */

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
/* RFC 3394 section 4.1 vector, so the software fallback after a declined
 * dispatch is checked against a known answer rather than just a status. */
static const uint8_t kKekRfc3394[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t kPlainRfc3394[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

static const uint8_t kCipherRfc3394[24] = {
    0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
    0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
};

static int exercise_keywrap(void)
{
    uint8_t wrapped[32];
    size_t wrapped_len = 0;
    psa_key_attributes_t kattr = psa_key_attributes_init();
    psa_key_attributes_t tattr = psa_key_attributes_init();
    psa_key_id_t kek = PSA_KEY_ID_NULL;
    psa_key_id_t target = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_WRAP);
    psa_set_key_algorithm(&kattr, PSA_ALG_KW);

    st = psa_import_key(&kattr, kKekRfc3394, sizeof(kKekRfc3394), &kek);
    if (st != PSA_SUCCESS)
        return fail("kek import", st);

    psa_set_key_type(&tattr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&tattr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&tattr, PSA_ALG_KW);

    st = psa_import_key(&tattr, kPlainRfc3394, sizeof(kPlainRfc3394), &target);
    if (st != PSA_SUCCESS) {
        psa_destroy_key(kek);
        return fail("wrap target import", st);
    }

    st = psa_wrap_key(kek, PSA_ALG_KW, target,
                      wrapped, sizeof(wrapped), &wrapped_len);
    if (st != PSA_SUCCESS) {
        ret = fail("psa_wrap_key", st);
    }
    else if (wrapped_len != sizeof(kCipherRfc3394) ||
             XMEMCMP(wrapped, kCipherRfc3394, sizeof(kCipherRfc3394)) != 0) {
        printf("FAIL psa_wrap_key produced the wrong ciphertext\n");
        ret = 1;
    }

    psa_destroy_key(target);
    psa_destroy_key(kek);
    return ret;
}
#endif /* !NO_AES && HAVE_AES_KEYWRAP */

#ifdef HAVE_CURVE448
/* X448 keygen plus agreement, so the curve448 crypto callbacks wolfCrypt
 * gained are actually exercised rather than assumed. */
static int exercise_x448(void)
{
    uint8_t peer[56];
    uint8_t secret[56];
    size_t peer_len = 0;
    size_t secret_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 448);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE |
                                   PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("x448 generate", st);

    st = psa_export_public_key(key, peer, sizeof(peer), &peer_len);
    if (st != PSA_SUCCESS) {
        ret = fail("x448 export public", st);
    }

    if (ret == 0) {
        st = psa_raw_key_agreement(PSA_ALG_ECDH, key, peer, peer_len,
                                   secret, sizeof(secret), &secret_len);
        if (st != PSA_SUCCESS)
            ret = fail("psa_raw_key_agreement x448", st);
    }

    psa_destroy_key(key);
    return ret;
}
#endif /* HAVE_CURVE448 */

#ifndef NO_RSA
static int exercise_rsa(void)
{
    uint8_t digest[32];
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(digest, 0x22, sizeof(digest));

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("rsa generate", st);

    st = psa_sign_hash(key, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                       digest, sizeof(digest), sig, sizeof(sig), &sig_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_sign_hash rsa", st);
    return 0;
}
#endif /* NO_RSA */

#define KDF_MODE_HKDF     0
#define KDF_MODE_EXTRACT  1
#define KDF_MODE_EXPAND   2
#define KDF_MODE_PBKDF2   3
#define KDF_MODE_SP800    4

/* One derivation, driven to output so every input is consumed. Returns 0 on
 * success, 1 on failure, and -1 when the build does not support alg. */
static int run_derivation(psa_algorithm_t alg, int mode, size_t out_len,
                          const char *label)
{
    static const uint8_t secret[]  = "wolfPSA devId kdf secret";
    static const uint8_t salt[]    = "wolfPSA devId kdf salt";
    static const uint8_t info[]    = "wolfPSA devId kdf info";
    static const uint8_t aes_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t prk[32];
    uint8_t out[32];
    psa_status_t st;

    XMEMSET(prk, 0x5a, sizeof(prk));

    st = psa_key_derivation_setup(&op, alg);
    if (st == PSA_ERROR_NOT_SUPPORTED)
        return -1;
    if (st != PSA_SUCCESS)
        return fail(label, st);

    if (mode == KDF_MODE_PBKDF2) {
        st = psa_key_derivation_input_integer(&op,
                 PSA_KEY_DERIVATION_INPUT_COST, 2u);
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof(salt) - 1);
        }
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_PASSWORD,
                     secret, sizeof(secret) - 1);
        }
    }
    else if (mode == KDF_MODE_SP800) {
        /* Counter-mode KDF: the capacity is the L it binds into every block,
         * so it has to be set before any input. */
        st = psa_key_derivation_set_capacity(&op, out_len);
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_SECRET,
                     aes_key, sizeof(aes_key));
        }
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_LABEL, salt, sizeof(salt) - 1);
        }
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_CONTEXT, info, sizeof(info) - 1);
        }
    }
    else {
        st = PSA_SUCCESS;
        if (mode != KDF_MODE_EXPAND) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof(salt) - 1);
        }
        if (st == PSA_SUCCESS && mode == KDF_MODE_EXPAND) {
            /* Expand takes a PRK, so the secret must be exactly one digest. */
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_SECRET, prk, sizeof(prk));
        }
        else if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_SECRET,
                     secret, sizeof(secret) - 1);
        }
        if (st == PSA_SUCCESS && mode != KDF_MODE_EXTRACT) {
            st = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof(info) - 1);
        }
    }

    if (st == PSA_SUCCESS)
        st = psa_key_derivation_output_bytes(&op, out, out_len);

    psa_key_derivation_abort(&op);
    if (st == PSA_ERROR_NOT_SUPPORTED)
        return -1;
    if (st != PSA_SUCCESS)
        return fail(label, st);
    return 0;
}

/* One derivation against a fresh count, so a devId dropped from a single KDF
 * call site shows up. check_families() cannot see it: the hash, HMAC and CMAC
 * counters are already non-zero from the other exercises. */
static int check_one_kdf(psa_algorithm_t alg, int mode, size_t out_len,
                         const char *label, int algo_type)
{
    int ret;

    reset_counts(expect_devid);

    ret = run_derivation(alg, mode, out_len, label);
    if (ret < 0) {
        printf("  %-14s not supported in this build\n", label);
        return 0;
    }
    if (ret != 0)
        return ret;

    if (seen[algo_type] == 0) {
        printf("FAIL %s reached no %s operation on devId %d\n", label,
               algo_name(algo_type), expect_devid);
        return 1;
    }
    if (seen_wrong_devid != 0) {
        printf("FAIL %s carried a devId other than %d\n", label,
               expect_devid);
        return 1;
    }

    printf("  %-14s dispatched %d %s operation(s)\n", label,
           seen[algo_type], algo_name(algo_type));
    return 0;
}

static int check_kdf_dispatch(void)
{
    int saved = expect_devid;
    int ret = 0;

    printf("kdf dispatch:\n");

    ret |= check_one_kdf(PSA_ALG_HKDF(PSA_ALG_SHA_256), KDF_MODE_HKDF,
                         32u, "hkdf", WC_ALGO_TYPE_HMAC);
    ret |= check_one_kdf(PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256),
                         KDF_MODE_EXTRACT, 32u, "hkdf-extract",
                         WC_ALGO_TYPE_HMAC);
    ret |= check_one_kdf(PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256),
                         KDF_MODE_EXPAND, 32u, "hkdf-expand",
                         WC_ALGO_TYPE_HMAC);
    ret |= check_one_kdf(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
                         KDF_MODE_PBKDF2, 32u, "pbkdf2", WC_ALGO_TYPE_HMAC);
#ifdef WOLFSSL_CMAC
    ret |= check_one_kdf(PSA_ALG_SP800_108_COUNTER_CMAC, KDF_MODE_SP800,
                         32u, "sp800-108-cmac", WC_ALGO_TYPE_CMAC);
#endif

    reset_counts(saved);
    return ret;
}

static int exercise_all(void)
{
    int ret = 0;

    ret |= exercise_random();
    ret |= exercise_hash();
    ret |= exercise_mac(PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_KEY_TYPE_HMAC,
                        32, "hmac");
#ifdef WOLFSSL_CMAC
    ret |= exercise_mac(PSA_ALG_CMAC, PSA_KEY_TYPE_AES, 16, "cmac");
#endif
    ret |= exercise_cipher();
#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
    ret |= exercise_keywrap();
#endif
    ret |= exercise_ecdsa();
#ifdef HAVE_ED25519
    ret |= exercise_eddsa();
#endif
#ifdef HAVE_CURVE448
    ret |= exercise_x448();
#endif
#ifndef NO_RSA
    ret |= exercise_rsa();
#endif

    return ret;
}

static int require_seen(int algo_type)
{
    if (seen[algo_type] == 0) {
        printf("FAIL no %s operation reached the callback\n",
               algo_name(algo_type));
        return 1;
    }
    printf("  %-6s dispatched %d time(s)\n", algo_name(algo_type),
           seen[algo_type]);
    return 0;
}

/* A device that generates the key but keeps the scalar leaves the private
 * key at zero. Exporting that would hand the caller an all-zero private key,
 * so psa_generate_key() must fail instead. Exercises the guards in
 * psa_asymmetric_generate_key_ecc(), _ed25519(), _x25519() and _x448().
 *
 * Ed448 has no case here on purpose: wc_ed448_make_key() carries no
 * wc_CryptoCb_* dispatch at all, only sign and verify, so no device can hold
 * an Ed448 scalar and the guard would be unreachable. */
static int check_keygen_silent_device(const char *label, int pk_type,
                                      psa_key_type_t key_type, size_t bits,
                                      psa_key_usage_t usage,
                                      psa_algorithm_t alg)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = 0xdeadbeef;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&attr, key_type);
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);

    mute_keygen_pk_type = pk_type;
    st = psa_generate_key(&attr, &key);
    mute_keygen_pk_type = WC_PK_TYPE_NONE;

    /* HARDWARE_FAILURE specifically: without the guard the export downstream
     * still fails, but with INVALID_ARGUMENT, which is indistinguishable from
     * a caller passing bad attributes. */
    if (st == PSA_SUCCESS) {
        printf("FAIL psa_generate_key reported success for a device that"
               " kept the %s private scalar\n", label);
        psa_destroy_key(key);
        ret = 1;
    }
    else if (st != PSA_ERROR_HARDWARE_FAILURE) {
        printf("FAIL psa_generate_key refused the device-held %s key as %d,"
               " expected PSA_ERROR_HARDWARE_FAILURE\n", label, (int)st);
        ret = 1;
    }
    else {
        printf("silent device: %s keygen refused\n", label);
    }

    return ret;
}

/* Every keygen path that can reach a device, so a guard deleted from any one
 * of them fails the suite. */
static int check_keygen_silent_device_all(void)
{
    int ret = 0;

#ifdef HAVE_ECC
    if (ret == 0) {
        ret = check_keygen_silent_device("ecc", WC_PK_TYPE_EC_KEYGEN,
                  PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                  PSA_KEY_USAGE_SIGN_HASH, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    }
    reset_counts(TEST_DEVID);
#endif
#ifdef HAVE_ED25519
    if (ret == 0) {
        ret = check_keygen_silent_device("ed25519", WC_PK_TYPE_ED25519_KEYGEN,
                  PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS),
                  255, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_PURE_EDDSA);
    }
    reset_counts(TEST_DEVID);
#endif
#ifdef HAVE_CURVE25519
    if (ret == 0) {
        ret = check_keygen_silent_device("x25519",
                  WC_PK_TYPE_CURVE25519_KEYGEN,
                  PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 255,
                  PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH);
    }
    reset_counts(TEST_DEVID);
#endif
#ifdef HAVE_CURVE448
    if (ret == 0) {
        ret = check_keygen_silent_device("x448", WC_PK_TYPE_CURVE448_KEYGEN,
                  PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 448,
                  PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH);
    }
    reset_counts(TEST_DEVID);
#endif

    return ret;
}

static int check_families(void)
{
    int ret = 0;

    ret |= require_seen(WC_ALGO_TYPE_HASH);
    ret |= require_seen(WC_ALGO_TYPE_CIPHER);
    ret |= require_seen(WC_ALGO_TYPE_PK);
    ret |= require_seen(WC_ALGO_TYPE_HMAC);
#ifdef WOLFSSL_CMAC
    ret |= require_seen(WC_ALGO_TYPE_CMAC);
#endif
    if (seen[WC_ALGO_TYPE_RNG] == 0 && seen[WC_ALGO_TYPE_SEED] == 0) {
        printf("FAIL no rng operation reached the callback\n");
        ret = 1;
    }
    else {
        printf("  %-6s dispatched %d time(s)\n", algo_name(WC_ALGO_TYPE_RNG),
               seen[WC_ALGO_TYPE_RNG]);
        printf("  %-6s dispatched %d time(s)\n", algo_name(WC_ALGO_TYPE_SEED),
               seen[WC_ALGO_TYPE_SEED]);
    }
    if (seen_wrong_devid != 0) {
        printf("FAIL %d operation(s) carried a devId other than %d\n",
               seen_wrong_devid, expect_devid);
        ret = 1;
    }
    return ret;
}

int main(void)
{
    int ret = 0;
    psa_status_t st;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS)
        return fail("psa_crypto_init", st);

    /* Phase 1: no device registered and no explicit devId, so every wolfCrypt
     * object must be built with INVALID_DEVID. */
    if (wolfPSA_GetDefaultDevID() != INVALID_DEVID) {
        printf("FAIL default devId is not INVALID_DEVID with no device"
               " registered\n");
        return 1;
    }

    /* Phase 2: a registered device and still no explicit devId. wolfCrypt's
     * own selection picks the only registered device, so every family must
     * reach it. An algorithm that never ran its wc_*Init() carries devId 0
     * instead and goes missing here. */
    /* Through wolfPSA's own wrappers, which is what a shared-library user
     * has to use: a bare wc_CryptoCb_RegisterDevice() binds by link order
     * and can land in libwolfssl's device table instead of this one. */
    if (wolfPSA_RegisterCryptoCb(PROBE_DEVID, count_cb, NULL) != 0) {
        printf("FAIL wolfPSA_RegisterCryptoCb(probe)\n");
        return 1;
    }

    if (wolfPSA_GetDefaultDevID() != PROBE_DEVID) {
        printf("FAIL default devId did not follow wolfCrypt device selection"
               " (got %d, want %d)\n", wolfPSA_GetDefaultDevID(),
               PROBE_DEVID);
        ret = 1;
    }

    if (ret == 0) {
        printf("wolfCrypt device selection (devId %d):\n", PROBE_DEVID);
        reset_counts(PROBE_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

    /* Phase 3: an explicit devId must win over that selection. The probe
     * device stays registered, so a stale read shows up as a dispatch on
     * PROBE_DEVID rather than TEST_DEVID. */
    if (ret == 0 && wolfPSA_RegisterCryptoCb(TEST_DEVID, count_cb,
                                             NULL) != 0) {
        printf("FAIL wolfPSA_RegisterCryptoCb(test)\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_SetDefaultDevID(TEST_DEVID) != 0) {
        printf("FAIL wolfPSA_SetDefaultDevID\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_GetDefaultDevID() != TEST_DEVID) {
        printf("FAIL explicit devId did not override device selection\n");
        ret = 1;
    }

    if (ret == 0) {
        printf("explicit devId %d:\n", TEST_DEVID);
        reset_counts(TEST_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    if (ret == 0) {
        ret = check_deterministic_ecdsa_stays_local();
    }
    reset_counts(TEST_DEVID);
#endif

    if (ret == 0) {
        ret = check_kdf_dispatch();
    }
    reset_counts(TEST_DEVID);

    if (ret == 0) {
        ret = check_keygen_silent_device_all();
    }

    /* Phase 4: an explicit INVALID_DEVID is the opt-out, so nothing may
     * dispatch even though both devices are still registered. */
    if (ret == 0 && wolfPSA_SetDefaultDevID(INVALID_DEVID) != 0) {
        printf("FAIL wolfPSA_SetDefaultDevID(INVALID_DEVID)\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_GetDefaultDevID() != INVALID_DEVID) {
        printf("FAIL INVALID_DEVID did not force local execution\n");
        ret = 1;
    }

    if (ret == 0) {
        reset_counts(INVALID_DEVID);
        ret = exercise_all();
    }

    if (ret == 0 && seen_total != 0) {
        printf("FAIL %d operation(s) dispatched after opting out\n",
               seen_total);
        ret = 1;
    }
    else if (ret == 0) {
        printf("opt-out: no dispatches\n");
    }

    /* Phase 5: WOLFPSA_DEVID_DEFAULT hands the choice back to wolfCrypt, so
     * the opt-out and any explicit devId are both reversible. TEST_DEVID is
     * unregistered first, leaving the probe as wolfCrypt's own selection. */
    wolfPSA_UnRegisterCryptoCb(TEST_DEVID);

    if (ret == 0 && wolfPSA_SetDefaultDevID(WOLFPSA_DEVID_DEFAULT) != 0) {
        printf("FAIL wolfPSA_SetDefaultDevID(WOLFPSA_DEVID_DEFAULT)\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_GetDefaultDevID() != PROBE_DEVID) {
        printf("FAIL default was not handed back to wolfCrypt (got %d,"
               " want %d)\n", wolfPSA_GetDefaultDevID(), PROBE_DEVID);
        ret = 1;
    }

    if (ret == 0) {
        printf("handed back to wolfCrypt (devId %d):\n", PROBE_DEVID);
        reset_counts(PROBE_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

    /* Phase 6: mbedtls_psa_crypto_free() drops the last wolfCrypt reference,
     * which unregisters every device. Nothing may dispatch after re-init
     * until the probe is registered again. */
    if (ret == 0) {
        mbedtls_psa_crypto_free();
        st = psa_crypto_init();
        if (st != PSA_SUCCESS)
            ret = fail("psa_crypto_init after free", st);
    }

    if (ret == 0) {
        reset_counts(PROBE_DEVID);
        ret = exercise_all();
    }

    if (ret == 0 && seen_total != 0) {
        printf("FAIL %d operation(s) dispatched after free and re-init\n",
               seen_total);
        ret = 1;
    }
    else if (ret == 0) {
        printf("free and re-init: no dispatches\n");
    }

    if (ret == 0 && wolfPSA_RegisterCryptoCb(PROBE_DEVID, count_cb,
                                             NULL) != 0) {
        printf("FAIL wolfPSA_RegisterCryptoCb(probe) after re-init\n");
        ret = 1;
    }

    if (ret == 0) {
        printf("registered again after re-init (devId %d):\n", PROBE_DEVID);
        reset_counts(PROBE_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

    wolfPSA_UnRegisterCryptoCb(PROBE_DEVID);

    if (ret != 0)
        return 1;

    printf("PSA devId crypto callback test: OK\n");
    return 0;
}
