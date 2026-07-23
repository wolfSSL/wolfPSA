/* main.c - wolfPSA broad-surface PSA smoke test
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
 * Runtime verification that the wolfPSA provider (on wolfCrypt from the
 * wolfSSL module) works across the major PSA algorithm families on Zephyr:
 * hashes, HMAC, AES-CTR, AES-CMAC, RSA-2048 PSS, ECDSA P-256, ECDH P-256,
 * ML-KEM-768 and ML-DSA-65. Every check logs PASS/FAIL and the run ends with
 * a summary. Uses volatile keys only (no persistent store dependency).
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <psa/crypto.h>
#include <string.h>

LOG_MODULE_REGISTER(psa_smoke, LOG_LEVEL_INF);

static int g_pass;
static int g_fail;

static void report(const char *name, bool ok)
{
	if (ok) {
		g_pass++;
		LOG_INF("PASS  %s", name);
	} else {
		g_fail++;
		LOG_ERR("FAIL  %s", name);
	}
}

/* Compare helper. */
static bool eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

static const uint8_t msg[] = "The quick brown fox jumps over the lazy dog.";

static void test_hash(void)
{
	uint8_t h[64];
	size_t hlen = 0;
	psa_status_t st;

	st = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
			      h, sizeof(h), &hlen);
	report("SHA-256 compute", st == PSA_SUCCESS && hlen == 32);

	st = psa_hash_compute(PSA_ALG_SHA_384, msg, sizeof(msg) - 1,
			      h, sizeof(h), &hlen);
	report("SHA-384 compute", st == PSA_SUCCESS && hlen == 48);
}

static void test_hmac(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t key[32];
	uint8_t mac[32];
	size_t maclen = 0;
	psa_status_t st;
	const psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);

	memset(key, 0x0b, sizeof(key));
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&a, alg);
	psa_set_key_type(&a, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&a, sizeof(key) * 8);

	st = psa_import_key(&a, key, sizeof(key), &k);
	if (st != PSA_SUCCESS) {
		report("HMAC-SHA256 import", false);
		return;
	}
	st = psa_mac_compute(k, alg, msg, sizeof(msg) - 1, mac, sizeof(mac), &maclen);
	report("HMAC-SHA256 compute", st == PSA_SUCCESS && maclen == 32);

	st = psa_mac_verify(k, alg, msg, sizeof(msg) - 1, mac, maclen);
	report("HMAC-SHA256 verify", st == PSA_SUCCESS);

	psa_destroy_key(k);
}

static void test_aes_ctr(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t key[16];
	uint8_t ct[64];   /* IV(16) + ciphertext */
	uint8_t pt[sizeof(msg) - 1];
	size_t ctlen = 0, ptlen = 0;
	psa_status_t st;

	memset(key, 0x2a, sizeof(key));
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_CTR);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, sizeof(key) * 8);

	st = psa_import_key(&a, key, sizeof(key), &k);
	if (st != PSA_SUCCESS) {
		report("AES-CTR import", false);
		return;
	}
	st = psa_cipher_encrypt(k, PSA_ALG_CTR, msg, sizeof(msg) - 1,
				ct, sizeof(ct), &ctlen);
	if (st != PSA_SUCCESS) {
		report("AES-CTR encrypt", false);
		psa_destroy_key(k);
		return;
	}
	st = psa_cipher_decrypt(k, PSA_ALG_CTR, ct, ctlen, pt, sizeof(pt), &ptlen);
	report("AES-CTR round-trip",
	       st == PSA_SUCCESS && ptlen == sizeof(msg) - 1 &&
	       eq(pt, msg, sizeof(msg) - 1));

	psa_destroy_key(k);
}

static void test_cmac(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t key[16];
	uint8_t mac[16];
	size_t maclen = 0;
	psa_status_t st;

	memset(key, 0x3c, sizeof(key));
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&a, PSA_ALG_CMAC);
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&a, sizeof(key) * 8);

	st = psa_import_key(&a, key, sizeof(key), &k);
	if (st != PSA_SUCCESS) {
		report("AES-CMAC import", false);
		return;
	}
	st = psa_mac_compute(k, PSA_ALG_CMAC, msg, sizeof(msg) - 1,
			     mac, sizeof(mac), &maclen);
	if (st != PSA_SUCCESS || maclen != 16) {
		report("AES-CMAC compute", false);
		psa_destroy_key(k);
		return;
	}
	st = psa_mac_verify(k, PSA_ALG_CMAC, msg, sizeof(msg) - 1, mac, maclen);
	report("AES-CMAC compute+verify", st == PSA_SUCCESS);

	psa_destroy_key(k);
}

static void test_rsa_pss(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t hash[32];
	size_t hlen = 0;
	uint8_t sig[256];
	size_t siglen = 0;
	psa_status_t st;
	const psa_algorithm_t alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&a, alg);
	psa_set_key_type(&a, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&a, 2048);

	LOG_INF("...generating RSA-2048 key (may take a moment)");
	st = psa_generate_key(&a, &k);
	if (st != PSA_SUCCESS) {
		report("RSA-2048 generate", false);
		return;
	}
	report("RSA-2048 generate", true);

	(void)psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
			       hash, sizeof(hash), &hlen);
	st = psa_sign_hash(k, alg, hash, hlen, sig, sizeof(sig), &siglen);
	if (st != PSA_SUCCESS) {
		report("RSA-2048 PSS sign", false);
		psa_destroy_key(k);
		return;
	}
	st = psa_verify_hash(k, alg, hash, hlen, sig, siglen);
	report("RSA-2048 PSS sign+verify", st == PSA_SUCCESS);

	psa_destroy_key(k);
}

static void test_ecdsa(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t hash[32];
	size_t hlen = 0;
	uint8_t sig[80];
	size_t siglen = 0;
	psa_status_t st;
	const psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&a, alg);
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&a, 256);

	st = psa_generate_key(&a, &k);
	if (st != PSA_SUCCESS) {
		report("ECDSA P-256 generate", false);
		return;
	}
	report("ECDSA P-256 generate", true);

	(void)psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
			       hash, sizeof(hash), &hlen);
	st = psa_sign_hash(k, alg, hash, hlen, sig, sizeof(sig), &siglen);
	if (st != PSA_SUCCESS) {
		report("ECDSA P-256 sign", false);
		psa_destroy_key(k);
		return;
	}
	st = psa_verify_hash(k, alg, hash, hlen, sig, siglen);
	report("ECDSA P-256 sign+verify", st == PSA_SUCCESS);

	psa_destroy_key(k);
}

static void test_ecdh(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k1 = PSA_KEY_ID_NULL, k2 = PSA_KEY_ID_NULL;
	uint8_t pub1[133], pub2[133];
	size_t pub1len = 0, pub2len = 0;
	uint8_t ss1[32], ss2[32];
	size_t ss1len = 0, ss2len = 0;
	psa_status_t st;

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&a, PSA_ALG_ECDH);
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&a, 256);

	if (psa_generate_key(&a, &k1) != PSA_SUCCESS ||
	    psa_generate_key(&a, &k2) != PSA_SUCCESS) {
		report("ECDH P-256 generate pair", false);
		goto out;
	}
	if (psa_export_public_key(k1, pub1, sizeof(pub1), &pub1len) != PSA_SUCCESS ||
	    psa_export_public_key(k2, pub2, sizeof(pub2), &pub2len) != PSA_SUCCESS) {
		report("ECDH P-256 export pub", false);
		goto out;
	}

	st = psa_raw_key_agreement(PSA_ALG_ECDH, k1, pub2, pub2len,
				   ss1, sizeof(ss1), &ss1len);
	if (st != PSA_SUCCESS) {
		report("ECDH P-256 agreement A", false);
		goto out;
	}
	st = psa_raw_key_agreement(PSA_ALG_ECDH, k2, pub1, pub1len,
				   ss2, sizeof(ss2), &ss2len);
	if (st != PSA_SUCCESS) {
		report("ECDH P-256 agreement B", false);
		goto out;
	}
	report("ECDH P-256 shared-secret match",
	       ss1len == ss2len && ss1len == 32 && eq(ss1, ss2, ss1len));
out:
	psa_destroy_key(k1);
	psa_destroy_key(k2);
}

static psa_key_attributes_t make_ss_attrs(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&a, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&a, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	psa_set_key_bits(&a, 0);
	return a;
}

static void test_mlkem(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t ss_attrs;
	psa_key_id_t kp = PSA_KEY_ID_NULL;
	psa_key_id_t ss_enc = PSA_KEY_ID_NULL, ss_dec = PSA_KEY_ID_NULL;
	uint8_t ct[1600];
	size_t ctlen = 0;
	uint8_t sse[32], ssd[32];
	size_t sselen = 0, ssdlen = 0;
	psa_status_t st;

	psa_set_key_type(&a, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
	psa_set_key_bits(&a, 768);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&a, PSA_ALG_ML_KEM);

	st = psa_generate_key(&a, &kp);
	if (st != PSA_SUCCESS) {
		report("ML-KEM-768 generate", false);
		return;
	}
	report("ML-KEM-768 generate", true);

	ss_attrs = make_ss_attrs();
	st = psa_encapsulate(kp, PSA_ALG_ML_KEM, &ss_attrs, &ss_enc,
			     ct, sizeof(ct), &ctlen);
	if (st != PSA_SUCCESS) {
		report("ML-KEM-768 encapsulate", false);
		goto out;
	}
	ss_attrs = make_ss_attrs();
	st = psa_decapsulate(kp, PSA_ALG_ML_KEM, ct, ctlen, &ss_attrs, &ss_dec);
	if (st != PSA_SUCCESS) {
		report("ML-KEM-768 decapsulate", false);
		goto out;
	}
	if (psa_export_key(ss_enc, sse, sizeof(sse), &sselen) != PSA_SUCCESS ||
	    psa_export_key(ss_dec, ssd, sizeof(ssd), &ssdlen) != PSA_SUCCESS) {
		report("ML-KEM-768 export secrets", false);
		goto out;
	}
	report("ML-KEM-768 shared-secret match",
	       sselen == ssdlen && sselen > 0 && eq(sse, ssd, sselen));
out:
	psa_destroy_key(ss_enc);
	psa_destroy_key(ss_dec);
	psa_destroy_key(kp);
}

static void test_mldsa(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = PSA_KEY_ID_NULL;
	uint8_t sig[4096];
	size_t siglen = 0;
	psa_status_t st;

	psa_set_key_type(&a, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
	psa_set_key_bits(&a, 192);   /* ML-DSA-65 */
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&a, PSA_ALG_ML_DSA);

	LOG_INF("...generating ML-DSA-65 key");
	st = psa_generate_key(&a, &k);
	if (st != PSA_SUCCESS) {
		report("ML-DSA-65 generate", false);
		return;
	}
	report("ML-DSA-65 generate", true);

	st = psa_sign_message(k, PSA_ALG_ML_DSA, msg, sizeof(msg) - 1,
			      sig, sizeof(sig), &siglen);
	if (st != PSA_SUCCESS) {
		report("ML-DSA-65 sign", false);
		psa_destroy_key(k);
		return;
	}
	st = psa_verify_message(k, PSA_ALG_ML_DSA, msg, sizeof(msg) - 1, sig, siglen);
	report("ML-DSA-65 sign+verify", st == PSA_SUCCESS);

	psa_destroy_key(k);
}

int main(void)
{
	psa_status_t st;

	LOG_INF("=== wolfPSA broad PSA smoke test ===");

	st = psa_crypto_init();
	if (st != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed: %d", (int)st);
		return 0;
	}

	test_hash();
	test_hmac();
	test_aes_ctr();
	test_cmac();
	test_rsa_pss();
	test_ecdsa();
	test_ecdh();
	test_mlkem();
	test_mldsa();

	LOG_INF("=== summary: %d passed, %d failed ===", g_pass, g_fail);
	if (g_fail == 0) {
		LOG_INF("ALL PSA SMOKE TESTS PASSED");
	} else {
		LOG_ERR("SOME PSA SMOKE TESTS FAILED");
	}
	return 0;
}
