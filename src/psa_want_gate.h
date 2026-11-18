/* psa_want_gate.h
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

#ifndef WOLFPSA_WANT_GATE_H
#define WOLFPSA_WANT_GATE_H

#include <wolfssl/wolfcrypt/settings.h>

/* Under WOLFPSA_WANT_GATED (gen-crypto-config.py --without) these algorithms also
 * need their PSA_WANT_ALG_*, so wolfCrypt keeps a primitive PSA does not expose. */
#include <psa/crypto_config.h>

#if defined(HAVE_AESGCM) && \
    (!defined(WOLFPSA_WANT_GATED) || defined(PSA_WANT_ALG_GCM))
    #define WOLFPSA_GCM
#endif
#if defined(HAVE_AESCCM) && \
    (!defined(WOLFPSA_WANT_GATED) || defined(PSA_WANT_ALG_CCM))
    #define WOLFPSA_CCM
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
    (!defined(WOLFPSA_WANT_GATED) || defined(PSA_WANT_ALG_CHACHA20_POLY1305))
    #define WOLFPSA_CHACHAPOLY
#endif
#if !defined(NO_HMAC) && \
    (!defined(WOLFPSA_WANT_GATED) || \
     defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC))
    #define WOLFPSA_SP800_108_HMAC
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && \
    (!defined(WOLFPSA_WANT_GATED) || \
     defined(PSA_WANT_ALG_SP800_108_COUNTER_CMAC))
    #define WOLFPSA_SP800_108_CMAC
#endif

#endif /* WOLFPSA_WANT_GATE_H */
