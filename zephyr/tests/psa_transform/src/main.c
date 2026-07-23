/* main.c - wolfPSA secure_storage ITS transform unit test
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
 * Unit-tests wolfPSA's wolfCrypt AES-256-GCM custom ITS transform
 * (zephyr/src/psa_its_transform_wolfcrypt.c) directly -- its two functions are
 * global. This is wolfPSA-internal behavior that Zephyr's own suite cannot
 * cover: Zephyr's custom-transform test is a plaintext passthrough that verifies
 * neither confidentiality nor tamper detection. The generic persistent-key and
 * ITS round-trip flows are covered instead by running Zephyr's own
 * samples/psa/{its,persistent_key} and tests/subsys/secure_storage/psa/crypto
 * against wolfPSA (see the sibling psa_its / psa_persistent_key /
 * psa_secure_storage wrappers).
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>
#include <zephyr/secure_storage/its/transform.h>
#include <string.h>

/* Return non-zero if the byte pattern needle occurs anywhere in hay. */
static int contains_bytes(const uint8_t *hay, size_t hay_len,
			  const uint8_t *needle, size_t needle_len)
{
	size_t i;

	if (needle_len == 0 || hay_len < needle_len) {
		return 0;
	}
	for (i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(hay + i, needle, needle_len) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Confidentiality at rest, tamper detection, and UID binding of the AES-GCM
 * transform. */
ZTEST(wolfpsa_transform, test_transform_authenticates)
{
	const secure_storage_its_uid_t uid = {
		.uid = 0x1234, .caller_id = SECURE_STORAGE_ITS_CALLER_PSA_ITS
	};
	const secure_storage_its_uid_t other = {
		.uid = 0x9999, .caller_id = SECURE_STORAGE_ITS_CALLER_PSA_ITS
	};
	const uint8_t secret[] = "top secret persistent key material";
	uint8_t stored[SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE];
	uint8_t tampered[SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE];
	uint8_t out[128];
	size_t stored_len = 0;
	size_t out_len = 0;
	psa_storage_create_flags_t flags = 0;

	zassert_equal(secure_storage_its_transform_to_store(uid, sizeof(secret),
			secret, PSA_STORAGE_FLAG_NONE, stored, &stored_len),
		      PSA_SUCCESS, "encrypt for store");

	/* Confidentiality: the plaintext must not appear in the stored blob. */
	zassert_false(contains_bytes(stored, stored_len, secret, sizeof(secret)),
		      "plaintext leaked into stored data");

	/* Correct round-trip. */
	zassert_equal(secure_storage_its_transform_from_store(uid, stored_len,
			stored, sizeof(out), out, &out_len, &flags),
		      PSA_SUCCESS, "decrypt from store");
	zassert_equal(out_len, sizeof(secret), "recovered length");
	zassert_mem_equal(out, secret, sizeof(secret), "recovered data");

	/* Tamper one byte -> authentication fails. */
	memcpy(tampered, stored, stored_len);
	tampered[stored_len - 1] ^= 0x01;
	zassert_equal(secure_storage_its_transform_from_store(uid, stored_len,
			tampered, sizeof(out), out, &out_len, &flags),
		      PSA_ERROR_INVALID_SIGNATURE, "tamper detected");

	/* A different UID cannot decrypt (UID is salt + AAD). */
	zassert_equal(secure_storage_its_transform_from_store(other, stored_len,
			stored, sizeof(out), out, &out_len, &flags),
		      PSA_ERROR_INVALID_SIGNATURE, "uid binding enforced");
}

/* A stored blob shorter than the minimum framing (flags + nonce + tag = 29
 * bytes) must be rejected as corrupt before any crypto runs. */
ZTEST(wolfpsa_transform, test_from_store_short_input_is_corrupt)
{
	const secure_storage_its_uid_t uid = {
		.uid = 0x1234, .caller_id = SECURE_STORAGE_ITS_CALLER_PSA_ITS
	};
	uint8_t stored[SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE] = {0};
	uint8_t out[128];
	size_t out_len = 0;
	psa_storage_create_flags_t flags = 0;

	/* 10 < 1 (flags) + 12 (nonce) + 16 (tag). */
	zassert_equal(secure_storage_its_transform_from_store(uid, 10,
			stored, sizeof(out), out, &out_len, &flags),
		      PSA_ERROR_DATA_CORRUPT, "short input rejected as corrupt");
}

/* A destination buffer smaller than the recovered plaintext must be rejected
 * with BUFFER_TOO_SMALL, and no bytes written past its end. */
ZTEST(wolfpsa_transform, test_from_store_small_output_buffer)
{
	const secure_storage_its_uid_t uid = {
		.uid = 0x1234, .caller_id = SECURE_STORAGE_ITS_CALLER_PSA_ITS
	};
	const uint8_t secret[] = "top secret persistent key material";
	uint8_t stored[SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE];
	/* out_area is one byte larger than the too-small window we pass in; the
	 * trailing byte is a canary that must survive (no OOB write). */
	uint8_t out_area[sizeof(secret)];
	const size_t small = sizeof(secret) - 1;
	size_t stored_len = 0;
	size_t out_len = 0;
	psa_storage_create_flags_t flags = 0;

	memset(out_area, 0xAA, sizeof(out_area));

	zassert_equal(secure_storage_its_transform_to_store(uid, sizeof(secret),
			secret, PSA_STORAGE_FLAG_NONE, stored, &stored_len),
		      PSA_SUCCESS, "encrypt for store");

	zassert_equal(secure_storage_its_transform_from_store(uid, stored_len,
			stored, small, out_area, &out_len, &flags),
		      PSA_ERROR_BUFFER_TOO_SMALL, "small output buffer rejected");
	zassert_equal(out_area[small], 0xAA, "no write past the output buffer");
}

ZTEST_SUITE(wolfpsa_transform, NULL, NULL, NULL, NULL, NULL);
