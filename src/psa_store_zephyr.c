/* psa_store_zephyr.c
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
 * Zephyr PSA store backend.
 *
 * This is the wolfPSA persistent-store backend for Zephyr, selected by defining
 * WOLFPSA_CUSTOM_STORE (which compiles out the default POSIX backend in
 * psa_store_posix.c). It implements the six wolfPSA_Store_* entry points from
 * <psa_store.h>.
 *
 * When CONFIG_SECURE_STORAGE is enabled the six entry points map onto the
 * Zephyr PSA Internal Trusted Storage (ITS) API (psa_its_set/get/get_info/
 * remove). ITS is a whole-object store, so:
 *   - writes accumulate into a heap buffer and are committed with psa_its_set()
 *     inside wolfPSA_Store_Write(), where the ITS status propagates through the
 *     return value that psa_key_storage.c checks (Close has no commit step to
 *     report, so it returns WOLFPSA_STORE_OK); psa_its_set() is atomic, so a failed
 *     commit leaves any prior value intact, mirroring the POSIX backend's
 *     atomic-rename-on-close semantics;
 *   - reads take a whole-object snapshot with psa_its_get() when the handle is
 *     opened and serve the sequential partial reads (header then body) that
 *     psa_key_storage.c does from that snapshot. ITS has no read handle, so
 *     re-fetching per read would let a concurrent psa_its_set() at the same UID
 *     swap the record between the authorization check and the key-data read;
 *     the snapshot gives the immutable view the POSIX backend gets from its
 *     open file handle.
 * The UID is the key id directly (mirrors tf-psa-crypto's non-owner
 * psa_its_identifier_of_slot(); the PSA user key-id range is 30-bit, matching
 * Zephyr's default ITS UID width).
 *
 * When CONFIG_SECURE_STORAGE is not enabled the entry points fall back to a
 * "not available" stub: only volatile keys work (they never touch the store),
 * and persistent-key APIs degrade cleanly to a storage error.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "psa_config.h"

#if defined(WOLFPSA_CUSTOM_STORE)

#include <psa_store.h>

/* WOLFPSA_STORE_NOT_AVAILABLE / WOLFPSA_STORE_IO_ERROR come from psa_store.h. */

#if defined(CONFIG_SECURE_STORAGE)

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* wolfPSA is the PSA Crypto provider, so its key records belong in the
 * provider's ITS caller namespace, apart from application psa_its_*() and
 * psa_ps_*() data at the same UID, where Mbed TLS keeps its keys. Zephyr 4.5
 * selects it with BUILDING_PSA_CRYPTO, 4.3/4.4 with BUILDING_MBEDTLS_CRYPTO. */
#ifndef BUILDING_PSA_CRYPTO
#define BUILDING_PSA_CRYPTO
#endif
#ifndef BUILDING_MBEDTLS_CRYPTO
#define BUILDING_MBEDTLS_CRYPTO
#endif
#include <psa/internal_trusted_storage.h>

/* Per-open context. For writes, buf accumulates the object until it is
 * committed; for reads, buf is the snapshot taken at open, off the sequential
 * cursor into it and len its total size. */
typedef struct WolfpsaZephyrStore {
    psa_storage_uid_t uid;
    unsigned char*    buf;
    size_t len;
    size_t off;
    int write;
} WolfpsaZephyrStore;

/* Map a wolfPSA store record identity to an ITS UID. Only WOLFPSA_STORE_KEY
 * records exist today and id2 is always 0; the UID is the key id itself. */
static psa_storage_uid_t wolfpsa_store_uid(int type, unsigned long id1,
                                           unsigned long id2)
{
    (void)type;
    (void)id2;
    return (psa_storage_uid_t)id1;
}

int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2, int
                         read,
                         int variableSz, void** store)
{
    int ret = WOLFPSA_STORE_OK;
    psa_storage_uid_t uid;
    WolfpsaZephyrStore* ctx = NULL;
    struct psa_storage_info_t info;
    psa_status_t st;

    /* variableSz is only a hint and understates the total written, so the
     * write buffer grows on demand in wolfPSA_Store_Write() instead. */
    (void)variableSz;

    if (store == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    *store = NULL;

    uid = wolfpsa_store_uid(type, id1, id2);
    if (uid == 0) {
        /* ITS requires a nonzero UID; PSA_KEY_ID_NULL is never persisted. */
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (read) {
        st = psa_its_get_info(uid, &info);
        if (st == PSA_ERROR_DOES_NOT_EXIST) {
            return WOLFPSA_STORE_NOT_AVAILABLE;
        }
        if (st != PSA_SUCCESS) {
            return WOLFPSA_STORE_IO_ERROR;
        }
    }

    ctx = (WolfpsaZephyrStore*)XMALLOC(sizeof(*ctx), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        /* Runtime memory exhaustion, not a storage failure: report it as such
         * so the caller can map it to PSA_ERROR_INSUFFICIENT_MEMORY, as the
         * POSIX backend does for its own context allocation. */
        return MEMORY_E;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->uid = uid;
    ctx->write = (read == 0);
    if (read && info.size > 0) {
        /* Snapshot the whole record now: every read of this handle must see
         * the same object, even if another thread replaces the UID. */
        size_t got = 0;

        ctx->buf = (unsigned char*)XMALLOC((size_t)info.size, NULL,
                                           DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx->buf == NULL) {
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
        st = psa_its_get(uid, 0, (size_t)info.size, ctx->buf, &got);
        if (st != PSA_SUCCESS || got != (size_t)info.size) {
            wc_ForceZero(ctx->buf, (size_t)info.size);
            XFREE(ctx->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFPSA_STORE_IO_ERROR;
        }
        ctx->len = got;
    }

    *store = ctx;
    return ret;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
                       void** store)
{
    return wolfPSA_Store_OpenSz(type, id1, id2, read, 0, store);
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    psa_storage_uid_t uid;
    psa_status_t st;

    uid = wolfpsa_store_uid(type, id1, id2);
    if (uid == 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    st = psa_its_remove(uid);
    if (st == PSA_ERROR_DOES_NOT_EXIST) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }
    if (st != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    return WOLFPSA_STORE_OK;
}

int wolfPSA_Store_Close(void* store)
{
    WolfpsaZephyrStore* ctx = (WolfpsaZephyrStore*)store;

    if (ctx != NULL) {
        if (ctx->buf != NULL) {
            /* Both the write buffer and the read snapshot hold serialized key
             * material. */
            wc_ForceZero(ctx->buf, ctx->len);
            XFREE(ctx->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XMEMSET(ctx, 0, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return WOLFPSA_STORE_OK;
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    WolfpsaZephyrStore* ctx = (WolfpsaZephyrStore*)store;
    size_t got;

    if (ctx == NULL || ctx->write || buffer == NULL || len < 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (len == 0 || ctx->buf == NULL || ctx->off >= ctx->len) {
        return 0;
    }

    /* Serve from the snapshot taken at open, not from ITS: the record behind
     * this UID may have been replaced since. */
    got = ctx->len - ctx->off;
    if (got > (size_t)len) {
        got = (size_t)len;
    }
    XMEMCPY(buffer, ctx->buf + ctx->off, got);
    ctx->off += got;
    return (int)got;
}

int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    WolfpsaZephyrStore* ctx = (WolfpsaZephyrStore*)store;
    unsigned char* grown;
    psa_status_t st;

    if (ctx == NULL || ctx->write == 0 || buffer == NULL || len < 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (len > 0) {
        /* Grow the accumulation buffer manually (not XREALLOC) so the old
         * buffer, which holds key material, is zeroed before being freed. */
        grown = (unsigned char*)XMALLOC(ctx->len + (size_t)len, NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
        if (grown == NULL) {
            return MEMORY_E;
        }
        if (ctx->buf != NULL) {
            XMEMCPY(grown, ctx->buf, ctx->len);
            wc_ForceZero(ctx->buf, ctx->len);
            XFREE(ctx->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XMEMCPY(grown + ctx->len, buffer, (size_t)len);
        ctx->buf = grown;
        ctx->len += (size_t)len;
    }

    if (ctx->len == 0) {
        return len;
    }

    /* Commit the whole accumulated object now (atomic) so a storage failure is
     * reported through this return value: psa_its_set is the only commit step
     * this backend has, and Close has nothing of its own to report.
     * Re-committing on each Write is harmless for the single-Write usage in
     * psa_key_storage.c and leaves the final object correct if streamed. */
    st = psa_its_set(ctx->uid, ctx->len, ctx->buf, 0);
    if (st != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    return len;
}

#else /* !CONFIG_SECURE_STORAGE */

/*
 * No persistent backend available: report "not available" so that reads of a
 * persistent key miss cleanly and writes are treated as unsupported. Volatile
 * keys never reach the store, so all volatile-key PSA flows still work.
 */

int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2, int
                         read,
                         int variableSz, void** store)
{
    (void)type;
    (void)id1;
    (void)id2;
    (void)read;
    (void)variableSz;

    if (store != NULL) {
        *store = NULL;
    }

    return WOLFPSA_STORE_NOT_AVAILABLE;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
                       void** store)
{
    return wolfPSA_Store_OpenSz(type, id1, id2, read, 0, store);
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    (void)type;
    (void)id1;
    (void)id2;

    return WOLFPSA_STORE_NOT_AVAILABLE;
}

int wolfPSA_Store_Close(void* store)
{
    (void)store;

    return WOLFPSA_STORE_OK;
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    (void)store;
    (void)buffer;
    (void)len;

    return WOLFPSA_STORE_IO_ERROR;
}

int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    (void)store;
    (void)buffer;
    (void)len;

    return WOLFPSA_STORE_IO_ERROR;
}

#endif /* CONFIG_SECURE_STORAGE */

#endif /* WOLFPSA_CUSTOM_STORE */
