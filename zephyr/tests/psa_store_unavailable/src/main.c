/* main.c - wolfPSA store-unavailable degradation test
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
 * Built with CONFIG_SECURE_STORAGE deliberately unset, so wolfPSA's Zephyr store
 * backend (src/psa_store_zephyr.c) compiles its degradation stubs: every
 * wolfPSA_Store_* entry point returns "not available". This pins the documented
 * contract of that branch -- volatile keys keep working, and a persistent-key
 * operation fails cleanly (a storage error, no crash) rather than silently
 * succeeding.
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>
#include <string.h>

/* Volatile keys never touch the store, so they must work regardless. */
ZTEST(wolfpsa_store_unavailable, test_volatile_key_still_works)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	const uint8_t key[16] = { 0 };
	const uint8_t pt[16] = "0123456789abcde";
	uint8_t nonce[12] = { 0 };
	uint8_t ct[sizeof(pt) + 16];
	uint8_t out[sizeof(pt)];
	size_t ctlen = 0, outlen = 0;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS, "crypto init");

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_GCM);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, 128);

	zassert_equal(psa_import_key(&a, key, sizeof(key), &k), PSA_SUCCESS,
		      "import volatile key");
	zassert_equal(psa_aead_encrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce),
			NULL, 0, pt, sizeof(pt), ct, sizeof(ct), &ctlen),
		      PSA_SUCCESS, "encrypt");
	zassert_equal(psa_aead_decrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce),
			NULL, 0, ct, ctlen, out, sizeof(out), &outlen),
		      PSA_SUCCESS, "decrypt");
	zassert_equal(outlen, sizeof(pt), "roundtrip length");
	zassert_mem_equal(out, pt, sizeof(pt), "roundtrip data");

	zassert_equal(psa_destroy_key(k), PSA_SUCCESS, "destroy");
}

/* A persistent key needs the store; with none available the import must fail
 * cleanly (some error status, no crash) rather than silently succeed. */
ZTEST(wolfpsa_store_unavailable, test_persistent_key_degrades)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	const uint8_t key[16] = { 0 };
	psa_status_t status;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS, "crypto init");

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_GCM);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, 128);
	psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&a, 0x00000041);

	status = psa_import_key(&a, key, sizeof(key), &k);
	zassert_not_equal(status, PSA_SUCCESS,
			  "persistent import must not succeed with no store");
}

ZTEST_SUITE(wolfpsa_store_unavailable, NULL, NULL, NULL, NULL, NULL);
