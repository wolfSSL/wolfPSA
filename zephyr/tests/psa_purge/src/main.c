/* main.c - wolfPSA psa_purge_key() unit test
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
 * psa_purge_key() confirms a key exists and reports its status; wolfPSA keeps no
 * purgeable in-RAM cache of persistent key material, so there is nothing to
 * evict. These tests pin both outcomes: success for a live key, and
 * PSA_ERROR_INVALID_HANDLE for one that does not exist -- the latter path is
 * otherwise undriven, since every other caller purges a key it just created.
 * psa_purge_key() itself is platform-neutral (src/psa_key_storage.c); this is
 * the Zephyr ztest, mirrored in the standalone tier by a case in
 * test/psa_server/psa_14_misc_test.c.
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

/* Import a volatile AES-128 key; returns its id or PSA_KEY_ID_NULL on failure. */
static psa_key_id_t import_volatile_key(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	const uint8_t key[16] = { 0 };

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_GCM);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, 128);

	if (psa_import_key(&a, key, sizeof(key), &k) != PSA_SUCCESS) {
		return PSA_KEY_ID_NULL;
	}
	return k;
}

/* A live key has no purgeable cached copy, so purge reports success. */
ZTEST(wolfpsa_purge, test_purge_live_key)
{
	psa_key_id_t k;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS, "crypto init");

	k = import_volatile_key();
	zassert_not_equal(k, PSA_KEY_ID_NULL, "import volatile key");

	zassert_equal(psa_purge_key(k), PSA_SUCCESS, "purge of a live key succeeds");

	zassert_equal(psa_destroy_key(k), PSA_SUCCESS, "destroy");
}

/* Purging a key that does not exist must be rejected, not silently succeed. */
ZTEST(wolfpsa_purge, test_purge_absent_key)
{
	psa_key_id_t k;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS, "crypto init");

	k = import_volatile_key();
	zassert_not_equal(k, PSA_KEY_ID_NULL, "import volatile key");
	zassert_equal(psa_destroy_key(k), PSA_SUCCESS, "destroy");

	/* k now refers to no key. */
	zassert_equal(psa_purge_key(k), PSA_ERROR_INVALID_HANDLE,
		      "purge of an absent key is rejected");
}

ZTEST_SUITE(wolfpsa_purge, NULL, NULL, NULL, NULL, NULL);
