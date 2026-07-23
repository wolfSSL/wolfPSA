/* main.c - wolfSSL-TLS + wolfPSA coexistence test
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
 * Proves that the wolfSSL TLS layer and the wolfPSA PSA Crypto provider live in
 * one image on the same wolfCrypt core: the PSA API works, AND the TLS layer is
 * present and functional (methods, contexts, and an in-memory client<->server
 * handshake over a memory transport, no network stack needed).
 */

#include <zephyr/ztest.h>
#include <string.h>

#include <psa/crypto.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#define USE_CERT_BUFFERS_2048   /* expose server_cert_der_2048 etc. */
#include <wolfssl/certs_test.h>

/* --- The wolfPSA PSA provider works ------------------------------------- */
ZTEST(psa_tls_coexist, test_psa_provider_works)
{
	uint8_t buf[32];
	uint8_t hash[32];
	size_t hash_len = 0;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS, "psa_crypto_init");
	zassert_equal(psa_generate_random(buf, sizeof(buf)), PSA_SUCCESS,
		      "psa_generate_random");
	zassert_equal(psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)"wolf", 4,
				       hash, sizeof(hash), &hash_len),
		      PSA_SUCCESS, "psa_hash_compute");
	zassert_equal(hash_len, 32, "SHA-256 output length");
}

/* --- The wolfSSL TLS layer is present ----------------------------------- */
ZTEST(psa_tls_coexist, test_wolfssl_tls_layer_present)
{
	WOLFSSL_CTX *ctx;

	zassert_equal(wolfSSL_Init(), WOLFSSL_SUCCESS, "wolfSSL_Init");

	/* Creating a TLS context requires the full TLS layer to be linked -- it
	 * would be absent under WOLFCRYPT_ONLY. */
	ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
	zassert_not_null(ctx, "TLS context creation failed (TLS layer missing?)");

	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
}

/* --- A real TLS handshake runs in the same image as the PSA provider ----- */

/* In-memory transport: one FIFO per direction, driven by the I/O callbacks. */
struct membuf {
	unsigned char data[16384];
	int len;   /* bytes written */
	int pos;   /* bytes consumed */
};
static struct membuf g_c2s; /* client -> server */
static struct membuf g_s2c; /* server -> client */

static int mem_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	struct membuf *m = (struct membuf *)ctx;
	int avail = m->len - m->pos;

	(void)ssl;
	if (avail <= 0) {
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}
	if (sz > avail) {
		sz = avail;
	}
	memcpy(buf, m->data + m->pos, (size_t)sz);
	m->pos += sz;
	return sz;
}

static int mem_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	struct membuf *m = (struct membuf *)ctx;

	(void)ssl;
	if (m->len + sz > (int)sizeof(m->data)) {
		return WOLFSSL_CBIO_ERR_WANT_WRITE;
	}
	memcpy(m->data + m->len, buf, (size_t)sz);
	m->len += sz;
	return sz;
}

ZTEST(psa_tls_coexist, test_tls_handshake_with_psa)
{
	WOLFSSL_CTX *sctx = NULL, *cctx = NULL;
	WOLFSSL *ssl_s = NULL, *ssl_c = NULL;
	uint8_t rnd[16];
	int cret = -1, sret = -1;
	int i;

	memset(&g_c2s, 0, sizeof(g_c2s));
	memset(&g_s2c, 0, sizeof(g_s2c));

	zassert_equal(wolfSSL_Init(), WOLFSSL_SUCCESS, "wolfSSL_Init");

	/* Server: cert + key from wolfSSL's built-in test material. */
	sctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
	zassert_not_null(sctx, "server CTX");
	zassert_equal(wolfSSL_CTX_use_certificate_buffer(sctx, server_cert_der_2048,
			sizeof_server_cert_der_2048, WOLFSSL_FILETYPE_ASN1),
		      WOLFSSL_SUCCESS, "server cert");
	zassert_equal(wolfSSL_CTX_use_PrivateKey_buffer(sctx, server_key_der_2048,
			sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1),
		      WOLFSSL_SUCCESS, "server key");

	/* Client: skip peer verification to keep the test to the handshake crypto. */
	cctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	zassert_not_null(cctx, "client CTX");
	wolfSSL_CTX_set_verify(cctx, WOLFSSL_VERIFY_NONE, NULL);

	wolfSSL_CTX_SetIORecv(sctx, mem_recv);
	wolfSSL_CTX_SetIOSend(sctx, mem_send);
	wolfSSL_CTX_SetIORecv(cctx, mem_recv);
	wolfSSL_CTX_SetIOSend(cctx, mem_send);

	ssl_s = wolfSSL_new(sctx);
	ssl_c = wolfSSL_new(cctx);
	zassert_not_null(ssl_s, "server SSL");
	zassert_not_null(ssl_c, "client SSL");

	/* Client reads server->client, writes client->server (and vice-versa). */
	wolfSSL_SetIOReadCtx(ssl_c, &g_s2c);
	wolfSSL_SetIOWriteCtx(ssl_c, &g_c2s);
	wolfSSL_SetIOReadCtx(ssl_s, &g_c2s);
	wolfSSL_SetIOWriteCtx(ssl_s, &g_s2c);

	/* Pump both ends until the handshake completes on both sides. */
	for (i = 0; i < 20 && (cret != WOLFSSL_SUCCESS || sret != WOLFSSL_SUCCESS);
	     i++) {
		if (cret != WOLFSSL_SUCCESS) {
			cret = wolfSSL_connect(ssl_c);
		}
		if (sret != WOLFSSL_SUCCESS) {
			sret = wolfSSL_accept(ssl_s);
		}
	}

	zassert_equal(cret, WOLFSSL_SUCCESS, "client handshake (err %d)",
		      wolfSSL_get_error(ssl_c, cret));
	zassert_equal(sret, WOLFSSL_SUCCESS, "server handshake (err %d)",
		      wolfSSL_get_error(ssl_s, sret));

	/* The PSA provider still works right after a TLS handshake in one image. */
	zassert_equal(psa_generate_random(rnd, sizeof(rnd)), PSA_SUCCESS,
		      "PSA after TLS handshake");

	wolfSSL_free(ssl_c);
	wolfSSL_free(ssl_s);
	wolfSSL_CTX_free(cctx);
	wolfSSL_CTX_free(sctx);
	wolfSSL_Cleanup();
}

ZTEST_SUITE(psa_tls_coexist, NULL, NULL, NULL, NULL, NULL);
