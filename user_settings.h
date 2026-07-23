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

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
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
#define WC_RSA_PSS
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_RSA_OAEP
#define WOLFSSL_DES3
#define WOLFSSL_DES_ECB
#define HAVE_AESGCM
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
/* Ascon is marked experimental in wolfSSL master and refuses to build
 * without this opt-in. */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_ASCON
/* AES key wrap requires the direct (single-block) AES API. */
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_KEYWRAP
#define HAVE_XCHACHA
#define HAVE_CMAC_KDF

#endif /* __ZEPHYR__ */

#endif /* WOLFSSL_USER_SETTINGS_H */
