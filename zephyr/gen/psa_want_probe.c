/* psa_want_probe.c
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
 * NOT a compiled translation unit. This file is *preprocessed* at build time
 * (gcc -E -P) with the same wolfCrypt configuration as the rest of the build,
 * and gen-crypto-config.py extracts the surviving `__WPSA_EMIT__<symbol>`
 * lines to generate wolfpsa/psa/crypto_config_zephyr.h -- the consumer-visible
 * PSA_WANT_ surface. Each block below maps an enabled wolfCrypt feature to the
 * PSA_WANT_ symbol(s) wolfPSA exposes for it, so the advertised PSA surface is
 * exactly "what wolfCrypt compiled" intersected with "what wolfPSA implements".
 *
 * Excluded on purpose (wolfPSA has no PSA binding): finite-field DH, PAKE,
 * Camellia, ARIA, ECC Brainpool/Koblitz. Keep this in sync with src/ when a
 * feature graduates.
 */

/* Pull in the effective wolfCrypt feature configuration (the module's
 * user_settings.h + wolfPSA baseline). We include user_settings.h directly
 * rather than <wolfssl/wolfcrypt/settings.h> so this probe preprocesses without
 * dragging in the Zephyr kernel headers settings.h pulls under WOLFSSL_ZEPHYR;
 * every feature macro this probe tests is materialized by user_settings.h. */
#include "user_settings.h"

/* ----- Hashes ----- */
#if !defined(NO_SHA)
__WPSA_EMIT__PSA_WANT_ALG_SHA_1
#endif
#if defined(WOLFSSL_SHA224)
__WPSA_EMIT__PSA_WANT_ALG_SHA_224
#endif
#if !defined(NO_SHA256)
__WPSA_EMIT__PSA_WANT_ALG_SHA_256
#endif
#if defined(WOLFSSL_SHA384)
__WPSA_EMIT__PSA_WANT_ALG_SHA_384
#endif
#if defined(WOLFSSL_SHA512)
__WPSA_EMIT__PSA_WANT_ALG_SHA_512
#endif
#if defined(WOLFSSL_SHA3)
__WPSA_EMIT__PSA_WANT_ALG_SHA3_224
__WPSA_EMIT__PSA_WANT_ALG_SHA3_256
__WPSA_EMIT__PSA_WANT_ALG_SHA3_384
__WPSA_EMIT__PSA_WANT_ALG_SHA3_512
#endif
#if defined(WOLFSSL_SHAKE128)
__WPSA_EMIT__PSA_WANT_ALG_SHAKE128
#endif
#if defined(WOLFSSL_SHAKE256)
__WPSA_EMIT__PSA_WANT_ALG_SHAKE256
#endif
#if !defined(NO_MD5)
__WPSA_EMIT__PSA_WANT_ALG_MD5
#endif
#if defined(WOLFSSL_RIPEMD)
__WPSA_EMIT__PSA_WANT_ALG_RIPEMD160
#endif

/* ----- MAC ----- */
#if !defined(NO_HMAC)
__WPSA_EMIT__PSA_WANT_ALG_HMAC
__WPSA_EMIT__PSA_WANT_KEY_TYPE_HMAC
#endif
#if defined(WOLFSSL_CMAC)
__WPSA_EMIT__PSA_WANT_ALG_CMAC
#endif

/* ----- AES + modes ----- */
#if !defined(NO_AES)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_AES
/* AES-CBC is present in wolfCrypt unless explicitly removed. */
#if !defined(NO_AES_CBC)
__WPSA_EMIT__PSA_WANT_ALG_CBC_NO_PADDING
__WPSA_EMIT__PSA_WANT_ALG_CBC_PKCS7
#endif
#if defined(HAVE_AES_ECB)
__WPSA_EMIT__PSA_WANT_ALG_ECB_NO_PADDING
#endif
#if defined(WOLFSSL_AES_COUNTER)
__WPSA_EMIT__PSA_WANT_ALG_CTR
#endif
#if defined(WOLFSSL_AES_CFB)
__WPSA_EMIT__PSA_WANT_ALG_CFB
#endif
#if defined(WOLFSSL_AES_OFB)
__WPSA_EMIT__PSA_WANT_ALG_OFB
#endif
#if defined(HAVE_AESGCM)
__WPSA_EMIT__PSA_WANT_ALG_GCM
#endif
#if defined(HAVE_AESCCM)
__WPSA_EMIT__PSA_WANT_ALG_CCM
__WPSA_EMIT__PSA_WANT_ALG_CCM_STAR_NO_TAG
#endif
#endif /* !NO_AES */

/* ----- ChaCha20 / Poly1305 ----- */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_CHACHA20
__WPSA_EMIT__PSA_WANT_ALG_CHACHA20_POLY1305
__WPSA_EMIT__PSA_WANT_ALG_STREAM_CIPHER
#endif

/* ----- RSA ----- */
#if !defined(NO_RSA)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY
__WPSA_EMIT__PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC
__WPSA_EMIT__PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT
__WPSA_EMIT__PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT
__WPSA_EMIT__PSA_WANT_ALG_RSA_PKCS1V15_SIGN
__WPSA_EMIT__PSA_WANT_ALG_RSA_PKCS1V15_CRYPT
#if defined(WOLFSSL_KEY_GEN)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
#endif
#if defined(WC_RSA_PSS)
__WPSA_EMIT__PSA_WANT_ALG_RSA_PSS
#endif
#if defined(WOLFSSL_RSA_OAEP) || defined(WC_RSA_OAEP)
__WPSA_EMIT__PSA_WANT_ALG_RSA_OAEP
#endif
#endif /* !NO_RSA */

/* ----- ECC (secp r1) ----- */
#if defined(HAVE_ECC)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE
__WPSA_EMIT__PSA_WANT_ALG_ECDSA
__WPSA_EMIT__PSA_WANT_ALG_ECDH
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K)
__WPSA_EMIT__PSA_WANT_ALG_DETERMINISTIC_ECDSA
#endif
#if !defined(NO_ECC256)
__WPSA_EMIT__PSA_WANT_ECC_SECP_R1_256
#endif
#if defined(HAVE_ECC384)
__WPSA_EMIT__PSA_WANT_ECC_SECP_R1_384
#endif
#if defined(HAVE_ECC521)
__WPSA_EMIT__PSA_WANT_ECC_SECP_R1_521
#endif
#endif /* HAVE_ECC */

/* ----- Montgomery curves ----- */
#if defined(HAVE_CURVE25519)
__WPSA_EMIT__PSA_WANT_ECC_MONTGOMERY_255
#endif
#if defined(HAVE_CURVE448)
__WPSA_EMIT__PSA_WANT_ECC_MONTGOMERY_448
#endif

/* ----- KDFs ----- */
#if defined(HAVE_HKDF)
__WPSA_EMIT__PSA_WANT_ALG_HKDF
__WPSA_EMIT__PSA_WANT_ALG_HKDF_EXTRACT
__WPSA_EMIT__PSA_WANT_ALG_HKDF_EXPAND
#endif
#if defined(HAVE_PBKDF2)
__WPSA_EMIT__PSA_WANT_ALG_PBKDF2_HMAC
#endif
#if defined(HAVE_PBKDF2) && defined(WOLFSSL_CMAC)
__WPSA_EMIT__PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
#endif
#if defined(WOLFSSL_HAVE_PRF)
__WPSA_EMIT__PSA_WANT_ALG_TLS12_PRF
__WPSA_EMIT__PSA_WANT_ALG_TLS12_PSK_TO_MS
#endif

/* ----- Key-derivation input key types ----- */
__WPSA_EMIT__PSA_WANT_KEY_TYPE_RAW_DATA
__WPSA_EMIT__PSA_WANT_KEY_TYPE_DERIVE
#if defined(HAVE_PBKDF2)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_PASSWORD
__WPSA_EMIT__PSA_WANT_KEY_TYPE_PASSWORD_HASH
#endif

/* ----- PQC ----- */
#if defined(WOLFSSL_HAVE_MLKEM)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ML_KEM
#endif
#if defined(WOLFSSL_HAVE_MLDSA)
__WPSA_EMIT__PSA_WANT_KEY_TYPE_ML_DSA
#endif
