/* psa_engine.h
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

/**
 * Platform Security Architecture (PSA) Engine header
 *
 * If WOLFSSL_PSA_ENGINE is defined, wolfSSL provides an implementation of the
 * PSA Crypto API that calls wolfCrypt APIs.
 *
 */

#ifndef WOLFSSL_PSA_ENGINE_H
#define WOLFSSL_PSA_ENGINE_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/visibility.h>

#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pass this to wolfPSA_SetDefaultDevID() to hand the choice back to
 * wolfCrypt, which is where wolfPSA starts. Reserved by convention:
 * wc_CryptoCb_RegisterDevice() rejects only INVALID_DEVID, so a device
 * registered at INT_MIN is accepted by wolfCrypt but unreachable here.
 * Distinct from INVALID_DEVID, which forces local execution. */
#define WOLFPSA_DEVID_DEFAULT INT_MIN

/* wolfCrypt error code to PSA status code conversion */
WOLFSSL_LOCAL psa_status_t wc_error_to_psa_status(int ret);

/* Undoes psa_crypto_init(), for mbedtls_psa_crypto_free() */
WOLFSSL_LOCAL void wolfPSA_CryptoCleanup(void);

/* Default wolfCrypt devId threaded through wolfPSA's internal wc_*Init()
 * calls. Set it to a registered devId to route every wolfPSA-issued
 * wolfCrypt call through that callback, the integration hook for offload
 * backends such as wolfHSM. Safe to call before psa_crypto_init().
 *
 * Unset, wolfCrypt's own selection applies (wc_CryptoCb_DefaultDevID()).
 * An explicit devId wins over it, INVALID_DEVID included: that one forces
 * local execution. Restore with WOLFPSA_DEVID_DEFAULT, never with a value
 * read back from wolfPSA_GetDefaultDevID(), which resolves the deferred
 * state rather than reporting it and would turn "let wolfCrypt choose"
 * into a hard pin.
 *
 * Covers every algorithm whose wolfCrypt initializer accepts a devId: AES,
 * 3DES, RSA, ECC, Ed25519, Ed448, X25519, X448, ML-DSA, ML-KEM, LMS, XMSS,
 * SHA-1, the SHA-2 and SHA-3 families, SHAKE, HMAC, CMAC, HKDF, PBKDF2 and
 * the RNG. RIPEMD-160, MD5, Ascon and ChaCha20-Poly1305 always run
 * locally, because wolfCrypt exposes no devId for them or ignores the one
 * it accepts. AES key wrap does too for now: wc_AesKeyWrap_ex() falls back
 * to software when the device has no keywrap handler, and a device that
 * took the KEK through WOLF_CRYPTO_CB_AES_SETKEY leaves no key schedule
 * for that fallback to run on.
 *
 * A backend that keeps per-operation state in devCtx must be built with
 * WOLF_CRYPTO_CB_COPY and WOLF_CRYPTO_CB_FREE, or psa_hash_clone()
 * duplicates the handle and psa_hash_abort() never releases it.
 *
 * PSA_ALG_DETERMINISTIC_ECDSA never offloads: the callback contract has no
 * deterministic flag, so wolfPSA pins that one algorithm to software. On a
 * WOLF_CRYPTO_CB_ONLY_ECC build there is no software to pin to and it
 * reports PSA_ERROR_NOT_SUPPORTED.
 *
 * Two escapes outside wolfPSA's control: deriving an X25519 public key
 * goes through the keyless wc_CryptoCb_Curve25519MakePub() and so reaches
 * whichever device registered first (keygen, agreement and all of
 * Curve448 are unaffected), and a WOLF_CRYPTO_CB_FIND build consults its
 * find callback regardless of devId.
 *
 * Threading: one atomic, so setting it under concurrent PSA traffic is
 * defined behaviour wherever wolfSSL_Atomic_Int is real; SINGLE_THREADED
 * and WOLFSSL_NO_ATOMICS builds get a plain int and must serialize the
 * setter themselves. Not a barrier: the value is read once per wolfCrypt
 * object, so an operation spanning the change can use one devId for part
 * of its work and another for the rest. It covers this setting only, not
 * wolfCrypt's unsynchronized gCryptoDev[] table, so register and
 * unregister during single-threaded init or teardown.
 *
 * Returns 0, or NOT_COMPILED_IN for a real devId in a library built
 * without WOLF_CRYPTO_CB. Speaks wolfCrypt, not PSA: int devId and
 * error-crypt.h codes, not psa_status_t. */
WOLFSSL_API int wolfPSA_SetDefaultDevID(int devId);

/* Returns the devId wolfPSA passes to wolfCrypt: the value given to
 * wolfPSA_SetDefaultDevID(), or wolfCrypt's own selection while the
 * setting is WOLFPSA_DEVID_DEFAULT. It is therefore not a test for whether
 * a devId was configured, and it can name a device nobody asked wolfPSA to
 * use. It never returns WOLFPSA_DEVID_DEFAULT itself. */
WOLFSSL_API int wolfPSA_GetDefaultDevID(void);

/* wolfCrypt's CryptoDevCallbackFunc sits inside cryptocb.h's WOLF_CRYPTO_CB
 * guard, while the two entry points below stay in the ABI for every
 * configuration. Alias it where it exists so the two cannot drift apart. */
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
    typedef CryptoDevCallbackFunc wolfPSA_CryptoCbFunc;
#else
    struct wc_CryptoInfo;
    typedef int (*wolfPSA_CryptoCbFunc)(int devId, struct wc_CryptoInfo *info,
                                        void *ctx);
#endif

/* Register or unregister a crypto callback against the device table
 * wolfPSA dispatches through. Use these rather than
 * wc_CryptoCb_RegisterDevice() directly: libwolfpsa links its own copy of
 * wolfCrypt, so an application that also links libwolfssl has two tables
 * and a bare call binds by link order. Returns 0, or NOT_COMPILED_IN
 * without WOLF_CRYPTO_CB. Call during single-threaded init or teardown,
 * per the threading note above. */
WOLFSSL_API int wolfPSA_RegisterCryptoCb(int devId, wolfPSA_CryptoCbFunc cb,
                                         void *ctx);
WOLFSSL_API int wolfPSA_UnRegisterCryptoCb(int devId);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_PSA_ENGINE */
#endif /* WOLFSSL_PSA_ENGINE_H */
