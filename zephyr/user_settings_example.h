/* user_settings_example.h
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
 * EXAMPLE broad wolfCrypt feature configuration for use with wolfPSA.
 *
 * wolfPSA does NOT apply this file automatically. wolfPSA follows whatever
 * wolfCrypt configuration the wolfSSL module was built with; this header is just
 * a ready-made, broad example you can opt into by pointing
 * CONFIG_WOLFSSL_SETTINGS_FILE at it (the wolfPSA module root is on the include
 * path, so this zephyr/-relative name resolves):
 *
 *     CONFIG_WOLFSSL_SETTINGS_FILE="zephyr/user_settings_example.h"
 *
 * The wolfPSA samples/tests use it so their PSA surface stays broad. For a real
 * application, point CONFIG_WOLFSSL_SETTINGS_FILE at your own user_settings.h
 * (or configure wolfCrypt via the module's Kconfig) and wolfPSA will expose
 * exactly what you enabled.
 *
 * This is FEATURE config only: the structural profile wolfPSA needs (the
 * Hash-DRBG + seed callback, and single-threaded on a no-threads kernel) is
 * applied via generic wolfSSL Kconfig knobs that the wolfPSA Kconfig selects,
 * and WOLFSSL_PSA_ENGINE is defined only for wolfPSA's own translation units --
 * none of that lives here. WOLFCRYPT_ONLY is NOT part of that profile: wolfPSA
 * coexists with the wolfSSL TLS layer, so building crypto-only is an optional
 * lean-image choice (WOLFSSL_CRYPTO_ONLY), never a wolfPSA requirement.
 */

#ifndef USER_SETTINGS_WOLFPSA_EXAMPLE_H
#define USER_SETTINGS_WOLFPSA_EXAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform / build model                                                    */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4 /* 32-bit alignment on uint32_t */
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_FILESYSTEM               /* wolfPSA uses the pluggable store, not files */
#define NO_WRITEV

/* Structural profile. wolfPSA no longer injects these via Kconfig, so a
 * settings file must set them itself; this makes the example a self-contained
 * crypto-only config. (For TLS + wolfPSA coexistence, use the module-default
 * Kconfig config instead of this file.) */
#define WOLFCRYPT_ONLY
#define HAVE_HASHDRBG               /* wolfPSA requires the Hash-DRBG; the wolfSSL
                                     * module's wc_GenerateSeed() seeds it from the
                                     * HW entropy driver when one is present */
#ifndef CONFIG_MULTITHREADING
    #define SINGLE_THREADED         /* no threading layer available */
#endif

/* ------------------------------------------------------------------------- */
/* Math (Single Precision, all sizes)                                        */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_1024
#define WOLFSSL_SP_384
#define HAVE_SP_ECC

/* ------------------------------------------------------------------------- */
/* RSA                                                                       */
/* ------------------------------------------------------------------------- */
#define RSA_MIN_SIZE 1024
#define WOLFSSL_KEY_GEN
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_RSA_OAEP

/* Side-channel hardening for private-key ops. */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

/* ------------------------------------------------------------------------- */
/* Hashes                                                                    */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_MD5
#define WOLFSSL_RIPEMD
#define WOLFSSL_SHA224
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#undef  NO_MD5
#undef  NO_DES3

/* ------------------------------------------------------------------------- */
/* ECC / EdDSA / Montgomery                                                  */
/* ------------------------------------------------------------------------- */
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_ECDSA_DETERMINISTIC_K
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_STREAMING_VERIFY
#define HAVE_CURVE448
#define HAVE_ED448
#define WOLFSSL_ED448_STREAMING_VERIFY

/* ------------------------------------------------------------------------- */
/* Symmetric / AEAD / MAC                                                    */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_DES3
#define WOLFSSL_DES_ECB
#define HAVE_AESGCM
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define WOLFSSL_AES_DIRECT          /* required by AES key wrap */
#define HAVE_AES_KEYWRAP
#define WOLFSSL_CMAC
#define HAVE_CHACHA
#define HAVE_XCHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

/* ------------------------------------------------------------------------- */
/* KDFs                                                                      */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_HAVE_PRF
#define HAVE_HKDF
#define HAVE_PBKDF2
#define HAVE_CMAC_KDF

/* ------------------------------------------------------------------------- */
/* PQC / stateful-hash                                                       */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_LMS_VERIFY_ONLY
#define WOLFSSL_HAVE_XMSS
#define WOLFSSL_XMSS_VERIFY_ONLY

/* ------------------------------------------------------------------------- */
/* Experimental (Ascon requires the opt-in)                                  */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_ASCON

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_WOLFPSA_EXAMPLE_H */
