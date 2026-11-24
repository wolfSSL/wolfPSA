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

/* A small Secure-image set: no ASN.1, no RSA, P-256 ECC, AES-GCM/CCM/CTR,
 * SHA-256 and HKDF, with every other key family compiled out. Multipart GCM
 * streams its AAD. */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_PSA_ENGINE
#define WOLFSSL_SP_MATH_ALL
#define ECC_TIMING_RESISTANT
#define HAVE_ECC
#define HAVE_ECC_DHE
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_ECDSA_DETERMINISTIC_K
#define HAVE_HKDF
#define WOLFSSL_SHA256
#define HAVE_AESGCM
#define HAVE_AESCCM
/* Multipart CCM runs on the direct AES block calls */
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_TOUCH_LINES
#define WC_ALLOW_ECC_ZERO_HASH
#define NO_ASN
#define NO_ASN_TIME
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_PBKDF2
#define WOLFPSA_AEAD_BORROW
#define WOLFSSL_AESGCM_STREAM
#define WOLFPSA_GCM_ONESHOT_STREAM
#define WOLFPSA_AEAD_STREAM_AAD

#endif /* WOLFSSL_USER_SETTINGS_H */
