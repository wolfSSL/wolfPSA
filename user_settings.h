/* user_settings.h
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

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#if defined(__ZEPHYR__)
/* Zephyr build: the wolfSSL module's user_settings.h is authoritative -- it
 * honors CONFIG_WOLFSSL_SETTINGS_FILE (the user's own config) and applies the
 * wolfPSA structural baseline, and the module's wolfCrypt objects compile
 * against it too, so wolfPSA's own sources must share it (identical struct ABI).
 * Because the wolfpsa/ include dir sits ahead of the module's on the include
 * path, wolfcrypt/settings.h's `#include "user_settings.h"` resolves HERE first;
 * defer to the next user_settings.h on the path (the module's) rather than apply
 * this standalone-Makefile configuration. */
#include_next "user_settings.h"
#else

#ifndef WOLFPSA_MBEDTLS_COMPAT
#define WOLFCRYPT_ONLY
#endif /* WOLFPSA_MBEDTLS_COMPAT */
/* MBEDTLS_THREADING_C: thread safe, see src/psa_lock.h */
#if defined(MBEDTLS_THREADING_C) && !defined(WOLFPSA_THREAD_SAFE)
#define WOLFPSA_THREAD_SAFE
#endif /* MBEDTLS_THREADING_C && !WOLFPSA_THREAD_SAFE */
#ifndef WOLFPSA_THREAD_SAFE
#define SINGLE_THREADED
#endif /* WOLFPSA_THREAD_SAFE */
#define WOLFSSL_PSA_ENGINE
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_1024
#define WOLFSSL_SP_384
#define HAVE_SP_ECC
#define RSA_MIN_SIZE 1024
#define WOLFSSL_KEY_GEN
/* Side-channel hardening: enable constant-time and blinding protection for
 * RSA/ECC private-key operations dispatched through the PSA engine. */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
/* AES backend: PSA compliance or speed. PSA requires constant-time AES;
 * wolfCrypt's fastest software core indexes T-tables with secret-derived
 * bytes, which is a cache-timing channel. Default here is the compliant
 * bitsliced core (requires HAVE_AES_ECB, defined below). Build with
 * AES_FAST=1 (or -DWOLFPSA_AES_FAST) to take the T-table core instead.
 * src/psa_config.h holds the policy and the full list of accepted
 * backends. */
#ifndef WOLFPSA_AES_FAST
#define WC_AES_BITSLICED
#endif
#define WOLFSSL_HAVE_PRF
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WOLFSSL_MD5
#define WOLFSSL_RIPEMD
#define WOLFSSL_SHA224
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#undef NO_MD5
#undef NO_DES3
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_ECDSA_DETERMINISTIC_K
/* PSA places no constraint on the content of the hash passed to
 * psa_sign_hash()/psa_verify_hash(): it is opaque bytes, and an all-zero
 * digest is a legal input (the PSA API test suite signs one for
 * SECP384R1/SHA-384). wolfCrypt rejects an all-zero digest by default as a
 * guard against uninitialized buffers, which would surface as
 * PSA_ERROR_INVALID_ARGUMENT for input the spec requires us to accept. */
#define WC_ALLOW_ECC_ZERO_HASH
#define WC_RSA_PSS
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_RSA_OAEP
#define WOLFSSL_DES3
#define WOLFSSL_DES_ECB
#define HAVE_AESGCM
/* Streaming AES-GCM (wc_AesGcmEncryptUpdate) so the multipart AEAD path can
 * emit the payload from psa_aead_update() instead of buffering it all for
 * finish(). */
#define WOLFSSL_AESGCM_STREAM
/* PSA allows 4 and 8 byte GCM tags; wolfCrypt's default minimum is 12.
 * Applies to all GCM/GMAC callers. PSA key policy must allow short tags. */
#ifndef WOLFSSL_MIN_AUTH_TAG_SZ
#define WOLFSSL_MIN_AUTH_TAG_SZ 4
#endif
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define WOLFSSL_CMAC
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_STREAMING_VERIFY
#define HAVE_CURVE448
#define HAVE_ED448
#define WOLFSSL_ED448_STREAMING_VERIFY
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_LMS_VERIFY_ONLY
#define WOLFSSL_HAVE_XMSS
#define WOLFSSL_XMSS_VERIFY_ONLY
/* Ascon is marked experimental in wolfSSL (5.9.4+) and refuses to build
 * without this opt-in. */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_ASCON
/* AES key wrap requires the direct (single-block) AES API. */
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_KEYWRAP
#define HAVE_XCHACHA
#define HAVE_CMAC_KDF

/* wolfSSL TLS for the Mbed TLS compatibility layer (MBEDTLS_COMPAT=1), with
 * configure's TLS defaults. NO_DH: wolfPSA builds no dh.c. */
#ifdef WOLFPSA_MBEDTLS_COMPAT
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SERVER_RENEGOTIATION_INFO
#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_DH
/* Mbed TLS accepts NULL parameters after an ECDSA signature OID */
#define WOLFSSL_ECC_SIGALG_PARAMS_NULL_ALLOWED
/* For MBEDTLS_X509_BADCERT_MISSING, see src/mbedtls_compat.c */
#define WOLFSSL_ALWAYS_VERIFY_CB
/* mbedtls_ssl_conf_ciphersuites() takes cipher suite IDs */
#define WOLFSSL_SET_CIPHER_BYTES
/* An IP address host name is checked against the certificate's IP SANs */
#define WOLFSSL_IP_ALT_NAME
#endif /* WOLFPSA_MBEDTLS_COMPAT */

#endif /* __ZEPHYR__ */

#endif /* WOLFSSL_USER_SETTINGS_H */
