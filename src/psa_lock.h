/* psa_lock.h
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
 * Optional serialization of wolfPSA's shared mutable state.
 *
 * wolfPSA keeps its volatile-key list and the auto-id counter in file-scope
 * globals in psa_key_storage.c. When independent threads may call the PSA API
 * concurrently, those shared-state accesses must be serialized.
 *
 * WOLFPSA_LOCK()/WOLFPSA_UNLOCK() wrap every access to that shared state. They
 * map to a single global mutex when WOLFPSA_THREAD_SAFE is defined, and to
 * no-ops otherwise (a single-threaded build). The mutex uses wolfCrypt's
 * portable mutex API (wc_InitMutex / wc_LockMutex / wc_UnLockMutex), so it works
 * on any platform wolfCrypt runs on -- there is nothing platform-specific here.
 * WOLFPSA_THREAD_SAFE must be paired with a multi-threaded wolfCrypt build.
 *
 * The mutex is created once via WOLFPSA_LOCK_INIT() (idempotent) and is never
 * taken recursively: no guarded entry point calls another while holding it, so
 * a plain non-recursive mutex is sufficient.
 *
 * Scope: this lock guards wolfPSA's in-memory key-store structures (the
 * volatile-key list and the id counter) and serializes the persistent import
 * path's existence-check-then-write, so two concurrent imports of the same
 * persistent id resolve to a single ALREADY_EXISTS rather than both succeeding.
 * Per-operation crypto uses stack-local wolfCrypt contexts and per-call local
 * WC_RNGs, and wolfpsa_get_key_data() returns an owned COPY of the key material,
 * so no live list node escapes the locked region. Individual persistent-store
 * calls are atomic on their own (the file backend commits with an atomic
 * temp-file rename and reads through a held file handle; a platform store such
 * as Zephyr secure_storage owns its own consistency); the lock adds the
 * cross-thread atomicity the multi-call check-then-write import needs.
 */

#ifndef WOLFPSA_PSA_LOCK_H
#define WOLFPSA_PSA_LOCK_H

/* WOLFPSA_THREAD_SAFE is the portable switch. A Kconfig-based build (e.g.
 * Zephyr's CONFIG_WOLFPSA_THREAD_SAFE) maps its option onto it here; any other
 * build defines WOLFPSA_THREAD_SAFE directly. */
#if defined(CONFIG_WOLFPSA_THREAD_SAFE) && !defined(WOLFPSA_THREAD_SAFE)
    #define WOLFPSA_THREAD_SAFE
#endif

#if defined(WOLFPSA_THREAD_SAFE)

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>

/* The single global mutex is defined once (via WOLFPSA_DEFINE_LOCK) in
 * psa_key_storage.c, alongside wolfpsa_lock_ensure_init(). */
extern wolfSSL_Mutex wolfpsa_global_mutex;

#define WOLFPSA_DEFINE_LOCK() wolfSSL_Mutex wolfpsa_global_mutex

/* One-time, idempotent mutex creation (defined in psa_key_storage.c). It must
 * run before any WOLFPSA_LOCK() can; psa_crypto_init() calls it, and the PSA
 * contract requires psa_crypto_init() before any other PSA call -- so this is a
 * platform-neutral bootstrap (no Zephyr init hook needed). Returns the
 * wc_InitMutex return code so a caller can surface a mutex-init failure instead
 * of reporting a dead lock as success. */
int wolfpsa_lock_ensure_init(void);
#define WOLFPSA_LOCK_INIT()   wolfpsa_lock_ensure_init()

/* LOCK/UNLOCK discard their return codes, matching wolfCrypt's own
 * (void)wc_LockMutex convention: a correctly-initialized, non-recursive mutex
 * only fails on a programming error (a bad handle or a self-deadlock), which
 * this code designs out -- not a runtime condition worth branching on. The one
 * failure that CAN happen at runtime, creating the mutex, is surfaced by
 * WOLFPSA_LOCK_INIT() above. */
#define WOLFPSA_LOCK()        (void)wc_LockMutex(&wolfpsa_global_mutex)
#define WOLFPSA_UNLOCK()      (void)wc_UnLockMutex(&wolfpsa_global_mutex)

#else /* single-threaded / standalone build: no-ops */

/* Expands to a forward struct declaration so the `;` at the single use site is
 * consumed -- no stray file-scope semicolon under -Wpedantic. */
#define WOLFPSA_DEFINE_LOCK() struct wolfpsa_lock_placeholder
#define WOLFPSA_LOCK_INIT()   0
#define WOLFPSA_LOCK()        ((void)0)
#define WOLFPSA_UNLOCK()      ((void)0)

#endif

#endif /* WOLFPSA_PSA_LOCK_H */
