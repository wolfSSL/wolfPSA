/* main.c - wolfPSA concurrent key-store stress test
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
 * Hammers the wolfPSA volatile key store from several threads at once. Each
 * worker repeatedly imports/generates its OWN keys, uses them, and destroys
 * them, so the threads race on the shared volatile-key list and the auto-id
 * counter. With CONFIG_WOLFPSA_THREAD_SAFE the global (non-recursive) lock must keep
 * that shared state consistent; without it this reliably corrupts/crashes.
 *
 * Preemptive time-slicing (prj.conf) forces interleaving on the single native
 * CPU, including preemption mid list-traversal.
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>
#include <psa/crypto.h>
#include <string.h>

#define NTHREADS 4
#define NITERS   60

K_THREAD_STACK_ARRAY_DEFINE(worker_stacks, NTHREADS, 24576);
static struct k_thread worker_threads[NTHREADS];

static atomic_t g_ops;
static atomic_t g_fail;

/* One key imported once and used (read-only lookup) by every thread at the same
 * time, so the workers race on a single shared list node while they also churn
 * their own keys — exercising concurrent readers vs. list mutation. */
static psa_key_id_t g_shared_key = PSA_KEY_ID_NULL;

static const uint8_t pt[] = "wolfPSA concurrent key-store stress payload!";

/* One AES-GCM volatile-key round-trip on a fresh key. */
static int do_aes_gcm(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t key[16], nonce[12];
	uint8_t ct[sizeof(pt) + 16];
	uint8_t out[sizeof(pt)];
	size_t ctlen = 0, outlen = 0;
	int rc = -1;

	if (psa_generate_random(key, sizeof(key)) != PSA_SUCCESS ||
	    psa_generate_random(nonce, sizeof(nonce)) != PSA_SUCCESS) {
		return -1;
	}
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_GCM);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, 128);

	if (psa_import_key(&a, key, sizeof(key), &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_aead_encrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce), NULL, 0,
			     pt, sizeof(pt), ct, sizeof(ct), &ctlen) == PSA_SUCCESS &&
	    psa_aead_decrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce), NULL, 0,
			     ct, ctlen, out, sizeof(out), &outlen) == PSA_SUCCESS &&
	    outlen == sizeof(pt) && memcmp(out, pt, sizeof(pt)) == 0) {
		rc = 0;
	}
	(void)psa_destroy_key(k);
	return rc;
}

/* One ECDSA P-256 generate/sign/verify/destroy on a fresh key. */
static int do_ecdsa(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	const psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	uint8_t hash[32], sig[80];
	size_t hlen = 0, siglen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&a, alg);
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&a, 256);

	if (psa_generate_key(&a, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_hash_compute(PSA_ALG_SHA_256, pt, sizeof(pt), hash, sizeof(hash),
			     &hlen) == PSA_SUCCESS &&
	    psa_sign_hash(k, alg, hash, hlen, sig, sizeof(sig), &siglen) == PSA_SUCCESS &&
	    psa_verify_hash(k, alg, hash, hlen, sig, siglen) == PSA_SUCCESS) {
		rc = 0;
	}
	(void)psa_destroy_key(k);
	return rc;
}

/* AES-GCM round-trip using an EXISTING key id (shared across threads). Does not
 * import/destroy — it only looks the key up, so many threads read the same list
 * node concurrently. */
static int do_shared_gcm(psa_key_id_t k)
{
	uint8_t nonce[12];
	uint8_t ct[sizeof(pt) + 16];
	uint8_t out[sizeof(pt)];
	size_t ctlen = 0, outlen = 0;

	if (psa_generate_random(nonce, sizeof(nonce)) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_aead_encrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce), NULL, 0,
			     pt, sizeof(pt), ct, sizeof(ct), &ctlen) != PSA_SUCCESS ||
	    psa_aead_decrypt(k, PSA_ALG_GCM, nonce, sizeof(nonce), NULL, 0,
			     ct, ctlen, out, sizeof(out), &outlen) != PSA_SUCCESS ||
	    outlen != sizeof(pt) || memcmp(out, pt, sizeof(pt)) != 0) {
		return -1;
	}
	return 0;
}

static void worker(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	for (int i = 0; i < NITERS; i++) {
		if (do_aes_gcm() != 0) {
			atomic_inc(&g_fail);
		}
		atomic_inc(&g_ops);

		if (do_ecdsa() != 0) {
			atomic_inc(&g_fail);
		}
		atomic_inc(&g_ops);

		if (do_shared_gcm(g_shared_key) != 0) {
			atomic_inc(&g_fail);
		}
		atomic_inc(&g_ops);
	}
}

ZTEST(wolfpsa_concurrency, test_parallel_keystore)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t key[16];

	zassert_equal(psa_crypto_init(), PSA_SUCCESS);

	/* Import the shared key that every worker will read concurrently. */
	memset(key, 0x5a, sizeof(key));
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_GCM);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, 128);
	zassert_equal(psa_import_key(&a, key, sizeof(key), &g_shared_key), PSA_SUCCESS);

	atomic_set(&g_ops, 0);
	atomic_set(&g_fail, 0);

	for (int i = 0; i < NTHREADS; i++) {
		k_thread_create(&worker_threads[i], worker_stacks[i],
				K_THREAD_STACK_SIZEOF(worker_stacks[i]),
				worker, NULL, NULL, NULL,
				K_PRIO_PREEMPT(5), 0, K_NO_WAIT);
	}
	for (int i = 0; i < NTHREADS; i++) {
		zassert_equal(k_thread_join(&worker_threads[i], K_FOREVER), 0);
	}

	zassert_equal(atomic_get(&g_ops), NTHREADS * NITERS * 3,
		      "unexpected op count");
	zassert_equal(atomic_get(&g_fail), 0,
		      "%d concurrent PSA operations failed", (int)atomic_get(&g_fail));

	(void)psa_destroy_key(g_shared_key);
}

ZTEST_SUITE(wolfpsa_concurrency, NULL, NULL, NULL, NULL, NULL);
