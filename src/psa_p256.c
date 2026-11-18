/* psa_p256.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfpsa/psa_p256.h>

#ifdef WOLFPSA_ECC_SP_DIRECT

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sp.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(HAVE_ECC) || !defined(WOLFSSL_HAVE_SP_ECC) || \
    defined(WOLFSSL_SP_NO_256)
    #error "WOLFPSA_ECC_SP_DIRECT needs wolfCrypt's SP P-256 code"
#endif
#ifdef ALT_ECC_SIZE
    #error "WOLFPSA_ECC_SP_DIRECT does not support ALT_ECC_SIZE"
#endif
#ifdef WOLF_CRYPTO_CB
    #error "WOLFPSA_ECC_SP_DIRECT bypasses crypto callbacks for P-256"
#endif
/* The PSA_WANT probe reads wolfCrypt's curves: P-256 must be the only one. */
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC112) || \
    defined(HAVE_ECC128) || defined(HAVE_ECC160) || defined(HAVE_ECC192) || \
    defined(HAVE_ECC224) || defined(HAVE_ECC239) || defined(HAVE_ECC320) || \
    defined(HAVE_ECC384) || defined(HAVE_ECC521) || \
    defined(HAVE_ECC_BRAINPOOL) || defined(HAVE_ECC_KOBLITZ) || \
    defined(WOLFSSL_SM2) || defined(WOLFSSL_ECDSA_DETERMINISTIC_K)
    #error "WOLFPSA_ECC_SP_DIRECT supports randomized P-256 only"
#endif

static const byte p256_prime[WOLFPSA_P256_SCALAR_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const byte p256_order[WOLFPSA_P256_SCALAR_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

/* 1 when the big-endian a is below m, in time independent of a. */
static word32 p256_below(const byte* a, const byte* m)
{
    word32 borrow = 0;
    int i;

    for (i = WOLFPSA_P256_SCALAR_LEN - 1; i >= 0; i--) {
        borrow = (((word32)a[i] - (word32)m[i] - borrow) >> 8) & 1U;
    }
    return borrow;
}

/* 1 when 0 < d < n, in time independent of d. */
static word32 p256_scalar_ok(const byte* d)
{
    word32 nz = 0;
    int i;

    for (i = 0; i < WOLFPSA_P256_SCALAR_LEN; i++) {
        nz |= d[i];
    }
    return p256_below(d, p256_order) & (((0U - nz) >> 31) & 1U);
}

static int p256_point_init(ecc_point* p)
{
    return mp_init_multi(p->x, p->y, p->z, NULL, NULL, NULL);
}

static void p256_point_free(ecc_point* p)
{
    mp_clear(p->x);
    mp_clear(p->y);
    mp_clear(p->z);
}

/* An uncompressed point with x, y < p that is on the curve. P-256 has
 * cofactor 1, so every such point is in the prime-order group. */
static int p256_point_read(ecc_point* p, const byte* pub)
{
    int ret = 0;

    if ((pub[0] != 0x04) ||
            (p256_below(pub + 1, p256_prime) == 0U) ||
            (p256_below(pub + 1 + WOLFPSA_P256_SCALAR_LEN, p256_prime) == 0U)) {
        ret = ECC_OUT_OF_RANGE_E;
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(p->x, pub + 1, WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(p->y, pub + 1 + WOLFPSA_P256_SCALAR_LEN,
                                   WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret == 0) {
        ret = mp_set(p->z, 1);
    }
    if (ret == 0) {
        ret = sp_ecc_is_point_256(p->x, p->y);
    }
    return ret;
}

static int p256_point_write(ecc_point* p, byte* pub)
{
    int ret;

    pub[0] = 0x04;
    ret = mp_to_unsigned_bin_len(p->x, pub + 1, WOLFPSA_P256_SCALAR_LEN);
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(p->y, pub + 1 + WOLFPSA_P256_SCALAR_LEN,
                                     WOLFPSA_P256_SCALAR_LEN);
    }
    return ret;
}

/* Loads the private scalar after checking 0 < d < n. */
static int p256_scalar_read(mp_int* k, const byte* d)
{
    int ret = 0;

    if (p256_scalar_ok(d) == 0U) {
        ret = ECC_PRIV_KEY_E;
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(k, d, WOLFPSA_P256_SCALAR_LEN);
    }
    return ret;
}

int wolfPSA_P256_CheckPrivate(const byte* d)
{
    if (d == NULL) {
        return BAD_FUNC_ARG;
    }
    return (p256_scalar_ok(d) != 0U) ? 0 : ECC_PRIV_KEY_E;
}

int wolfPSA_P256_CheckPublic(const byte* pub)
{
    ecc_point p;
    int ret;

    if (pub == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&p, 0, sizeof(p));
    ret = p256_point_init(&p);
    if (ret == 0) {
        ret = p256_point_read(&p, pub);
    }
    p256_point_free(&p);
    return ret;
}

int wolfPSA_P256_Public(const byte* d, byte* pub)
{
    mp_int k;
    ecc_point p;
    int ret = 0;

    if (d == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&k, 0, sizeof(k));
    XMEMSET(&p, 0, sizeof(p));
    ret = mp_init(&k);
    if (ret == 0) {
        ret = p256_point_init(&p);
    }
    if (ret == 0) {
        ret = p256_scalar_read(&k, d);
    }
    if (ret == 0) {
        ret = sp_ecc_mulmod_base_256(&k, &p, 1, NULL);
    }
    if (ret == 0) {
        ret = p256_point_write(&p, pub);
    }
    mp_forcezero(&k);
    p256_point_free(&p);
    return ret;
}

int wolfPSA_P256_Generate(WC_RNG* rng, byte* d, byte* pub)
{
    mp_int k;
    ecc_point p;
    int ret = 0;

    if (rng == NULL || d == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&k, 0, sizeof(k));
    XMEMSET(&p, 0, sizeof(p));
    ret = mp_init(&k);
    if (ret == 0) {
        ret = p256_point_init(&p);
    }
    if (ret == 0) {
        ret = sp_ecc_make_key_256(rng, &k, &p, NULL);
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(&k, d, WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret == 0) {
        ret = p256_point_write(&p, pub);
    }
    if (ret != 0) {
        wc_ForceZero(d, WOLFPSA_P256_SCALAR_LEN);
    }
    mp_forcezero(&k);
    p256_point_free(&p);
    return ret;
}

int wolfPSA_P256_Sign(const byte* d, const byte* hash, word32 hash_len,
                      WC_RNG* rng, byte* sig)
{
    mp_int k;
    mp_int r;
    mp_int s;
    int ret = 0;

    if (d == NULL || rng == NULL || sig == NULL ||
            (hash == NULL && hash_len != 0U)) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&k, 0, sizeof(k));
    XMEMSET(&r, 0, sizeof(r));
    XMEMSET(&s, 0, sizeof(s));
    ret = mp_init_multi(&k, &r, &s, NULL, NULL, NULL);
    if (ret == 0) {
        ret = p256_scalar_read(&k, d);
    }
    if (ret == 0) {
        ret = sp_ecc_sign_256(hash, hash_len, rng, &k, &r, &s, NULL, NULL);
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(&r, sig, WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(&s, sig + WOLFPSA_P256_SCALAR_LEN,
                                     WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret != 0) {
        wc_ForceZero(sig, WOLFPSA_P256_SIG_LEN);
    }
    mp_forcezero(&k);
    mp_clear(&r);
    mp_clear(&s);
    return ret;
}

int wolfPSA_P256_Verify(const byte* pub, const byte* hash, word32 hash_len,
                        const byte* sig, int* res)
{
    mp_int r;
    mp_int s;
    ecc_point p;
    int ret = 0;

    if (pub == NULL || sig == NULL || res == NULL ||
            (hash == NULL && hash_len != 0U)) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    /* sp_ecc_verify_256 leaves r and s unchecked; r = s = 0 would verify. */
    if ((p256_scalar_ok(sig) == 0U) ||
            (p256_scalar_ok(sig + WOLFPSA_P256_SCALAR_LEN) == 0U)) {
        return 0;
    }
    XMEMSET(&r, 0, sizeof(r));
    XMEMSET(&s, 0, sizeof(s));
    XMEMSET(&p, 0, sizeof(p));
    ret = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
    if (ret == 0) {
        ret = p256_point_init(&p);
    }
    if (ret == 0) {
        ret = p256_point_read(&p, pub);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&r, sig, WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&s, sig + WOLFPSA_P256_SCALAR_LEN,
                                   WOLFPSA_P256_SCALAR_LEN);
    }
    if (ret == 0) {
        ret = sp_ecc_verify_256(hash, hash_len, p.x, p.y, p.z, &r, &s, res,
                                NULL);
    }
    if (ret != 0) {
        *res = 0;
    }
    mp_clear(&r);
    mp_clear(&s);
    p256_point_free(&p);
    return ret;
}

int wolfPSA_P256_Ecdh(const byte* d, const byte* peer, byte* secret)
{
    mp_int k;
    ecc_point p;
    word32 len = WOLFPSA_P256_SCALAR_LEN;
    int ret = 0;

    if (d == NULL || peer == NULL || secret == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&k, 0, sizeof(k));
    XMEMSET(&p, 0, sizeof(p));
    ret = mp_init(&k);
    if (ret == 0) {
        ret = p256_point_init(&p);
    }
    if (ret == 0) {
        ret = p256_point_read(&p, peer);
    }
    if (ret == 0) {
        ret = p256_scalar_read(&k, d);
    }
    if (ret == 0) {
        ret = sp_ecc_secret_gen_256(&k, &p, secret, &len, NULL);
    }
    if (ret == 0 && len != WOLFPSA_P256_SCALAR_LEN) {
        ret = BUFFER_E;
    }
    if (ret != 0) {
        wc_ForceZero(secret, WOLFPSA_P256_SCALAR_LEN);
    }
    mp_forcezero(&k);
    p256_point_free(&p);
    return ret;
}

#endif /* WOLFPSA_ECC_SP_DIRECT */
