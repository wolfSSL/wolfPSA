/* psa_eddsa_mont_export_test.c
 *
 * Regression test: psa_export_public_key() used to guard the
 * whole ECC branch on HAVE_ECC + the ECC key import/export macros, so
 * standalone Ed25519/Ed448/X25519/X448 public-key export returned
 * PSA_ERROR_NOT_SUPPORTED in builds that compile those backends without
 * generic Weierstrass ECC, and even the raw byte copy of a stored public
 * key was blocked.
 *
 * The defect only manifests in a build without HAVE_ECC, so this test is
 * the configuration-independent half of the pair: it asserts that the four
 * standalone families export their public key, and that a stored standalone
 * public key round-trips as a byte copy, whenever the backends are
 * compiled in (always true for the default build, and the assertion that
 * failed before the fix in a HAVE_ECC-off build).
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

static int test_export_pair_public(psa_ecc_family_t family,
                                   psa_key_bits_t bits, size_t pub_len,
                                   const char* label)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_type_t key_type;
    uint8_t pub[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(448)];
    size_t pub_size = sizeof(pub);
    uint8_t pair[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(448)];
    size_t pair_len = 0;
    psa_status_t st;
    int ok = 0;

    key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(family);

    psa_set_key_type(&attrs, key_type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attrs, &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s generate status=%d\n", label, (int)st);
        goto out;
    }

    st = psa_export_public_key(key_id, pub, sizeof(pub), &pub_size);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s export status=%d (want SUCCESS)\n", label,
               (int)st);
        goto destroy;
    }

    if (pub_size != pub_len) {
        printf("FAIL %s export len=%u expected=%u\n", label,
               (unsigned)pub_size, (unsigned)pub_len);
        goto destroy;
    }

    st = psa_export_key(key_id, pair,
                        PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, bits),
                        &pair_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s key pair export into PSA_EXPORT_KEY_OUTPUT_SIZE "
               "status=%d\n", label, (int)st);
        goto destroy;
    }

    ok = 1;

destroy:
    (void)psa_destroy_key(key_id);

out:
    return ok ? 0 : 1;
}

static int test_stored_public_key_copy(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t in[32];
    uint8_t out[64];
    size_t out_size = sizeof(out);
    psa_status_t st;
    int ok = 0;
    int i;

    for (i = 0; i < (int)sizeof(in); i++) {
        in[i] = (uint8_t)(i * 7 + 1);
    }

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 255);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_import_key(&attrs, in, sizeof(in), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL stored-pub import status=%d\n", (int)st);
        goto out;
    }

    st = psa_export_public_key(key_id, out, sizeof(out), &out_size);
    if (st != PSA_SUCCESS) {
        printf("FAIL stored-pub export status=%d (want SUCCESS)\n",
               (int)st);
        goto destroy;
    }

    if (out_size != sizeof(in) ||
        memcmp(out, in, sizeof(in)) != 0) {
        printf("FAIL stored-pub copy len=%u\n", (unsigned)out_size);
        goto destroy;
    }

    ok = 1;

destroy:
    (void)psa_destroy_key(key_id);

out:
    return ok ? 0 : 1;
}

int main(void)
{
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    rc |= test_export_pair_public(PSA_ECC_FAMILY_TWISTED_EDWARDS, 255,
                                  32, "ed25519");
    rc |= test_export_pair_public(PSA_ECC_FAMILY_TWISTED_EDWARDS, 448,
                                  57, "ed448");
    rc |= test_export_pair_public(PSA_ECC_FAMILY_MONTGOMERY, 255, 32,
                                  "x25519");
    rc |= test_export_pair_public(PSA_ECC_FAMILY_MONTGOMERY, 448, 56,
                                  "x448");
    rc |= test_stored_public_key_copy();

    if (rc != 0) {
        printf("PSA eccguard export test: FAIL\n");
        return 1;
    }

    printf("PSA eccguard export test: OK\n");
    return 0;
}
