/* psa_p256.h
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

#ifndef WOLFPSA_P256_H
#define WOLFPSA_P256_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef WOLFPSA_ECC_SP_DIRECT

#define WOLFPSA_P256_SCALAR_LEN 32
#define WOLFPSA_P256_POINT_LEN  65
#define WOLFPSA_P256_SIG_LEN    64

/* P-256 straight on wolfCrypt's SP code, with ecc.c's key and signature
 * checks. Keys are a 32-byte scalar or a 65-byte uncompressed point, and
 * signatures are r||s. */
WOLFSSL_LOCAL int wolfPSA_P256_CheckPrivate(const byte* d);
WOLFSSL_LOCAL int wolfPSA_P256_Public(const byte* d, byte* pub);
WOLFSSL_LOCAL int wolfPSA_P256_CheckPublic(const byte* pub);
WOLFSSL_LOCAL int wolfPSA_P256_Generate(WC_RNG* rng, byte* d, byte* pub);
WOLFSSL_LOCAL int wolfPSA_P256_Sign(const byte* d, const byte* hash,
                                    word32 hash_len, WC_RNG* rng, byte* sig);
WOLFSSL_LOCAL int wolfPSA_P256_Verify(const byte* pub, const byte* hash,
                                      word32 hash_len, const byte* sig,
                                      int* res);
WOLFSSL_LOCAL int wolfPSA_P256_Ecdh(const byte* d, const byte* peer,
                                    byte* secret);

#endif /* WOLFPSA_ECC_SP_DIRECT */

#endif /* WOLFPSA_P256_H */
