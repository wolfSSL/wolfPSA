/* psa_xof.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include "psa_trace.h"
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
#include <wolfssl/wolfcrypt/sha3.h>
#endif

/*
 * Absorb strategy: wc_Shake128_Absorb / wc_Shake256_Absorb call Sha3Final()
 * internally on every invocation, which applies SHAKE padding and finalises the
 * sponge state in one shot.  Calling Absorb more than once would produce
 * incorrect output.  Therefore all input fed via psa_xof_update() is
 * accumulated in a dynamically allocated byte buffer (ibuf / ibuf_len /
 * ibuf_cap), and the single Absorb() is deferred to the first call of
 * psa_xof_output() just before the first SqueezeBlocks().
 *
 * Output is served from a one-block staging buffer (buf / buf_off) so that
 * callers asking for less than one block still get correct output.  For output
 * requests >= block_size that are block-aligned the blocks are squeezed
 * directly into the caller's buffer.
 */

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)

/* SHAKE128 rate = 1600 - 256 = 1344 bits = 168 bytes */
#define SHAKE128_BLOCK_SIZE  168u
/* SHAKE256 rate = 1600 - 512 = 1088 bits = 136 bytes */
#define SHAKE256_BLOCK_SIZE  136u

typedef struct psa_xof_operation_ctx {
    psa_algorithm_t alg;

    /* wc_Shake is typedef'd to wc_Sha3 */
    wc_Shake        shake;

    /* 0 = still absorbing input; 1 = squeeze phase started */
    int             squeezing;

    /* rate (block) size in bytes */
    word32          block_size;

    /* one-block staging buffer for squeeze tail */
    uint8_t         buf[SHAKE128_BLOCK_SIZE]; /* sized to the larger rate */
    word32          buf_off; /* next unread byte in buf */
    word32          buf_len; /* valid bytes in buf (== block_size once filled) */

    /* accumulated input buffer (absorb-once strategy); the backend
     * Absorb() takes word32 lengths, so ibuf_len stays <= UINT32_MAX
     * and size_t keeps the grow arithmetic overflow-free */
    uint8_t        *ibuf;
    size_t          ibuf_len;  /* bytes written */
    size_t          ibuf_cap;  /* bytes allocated */
} psa_xof_operation_ctx_t;

/* ------------------------------------------------------------------ helpers */

static psa_xof_operation_ctx_t *psa_xof_get_ctx(psa_xof_operation_t *op)
{
    if (op == NULL)
        return NULL;
    return (psa_xof_operation_ctx_t *)(uintptr_t)op->opaque;
}

static void psa_xof_free_ctx(psa_xof_operation_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    /* free wolfCrypt shake state */
    switch (ctx->alg) {
#ifdef WOLFSSL_SHAKE128
        case PSA_ALG_SHAKE128:
            wc_Shake128_Free(&ctx->shake);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256:
            wc_Shake256_Free(&ctx->shake);
            break;
#endif
        default:
            break;
    }

    /* free input accumulation buffer */
    if (ctx->ibuf != NULL) {
        wc_ForceZero(ctx->ibuf, ctx->ibuf_cap);
        XFREE(ctx->ibuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx->ibuf = NULL;
    }
}

/*
 * Grow the input accumulation buffer to hold at least need_cap bytes total.
 * Returns 0 on success, -1 on allocation failure.
 */
static int psa_xof_ibuf_grow(psa_xof_operation_ctx_t *ctx, size_t need_cap)
{
    uint8_t *newbuf;
    size_t   new_cap;

    if (need_cap <= ctx->ibuf_cap)
        return 0;

    /* double-or-fit growth; stop doubling once past half of UINT32_MAX
     * so the multiply cannot wrap (need_cap is <= UINT32_MAX) */
    new_cap = ctx->ibuf_cap ? ctx->ibuf_cap : 256u;
    while (new_cap < need_cap) {
        if (new_cap > ((size_t)UINT32_MAX) / 2u) {
            new_cap = (size_t)UINT32_MAX;
            break;
        }
        new_cap *= 2u;
    }

    newbuf = (uint8_t *)XMALLOC(new_cap, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (newbuf == NULL)
        return -1;

    if (ctx->ibuf != NULL && ctx->ibuf_len > 0)
        XMEMCPY(newbuf, ctx->ibuf, ctx->ibuf_len);

    if (ctx->ibuf != NULL) {
        wc_ForceZero(ctx->ibuf, ctx->ibuf_cap);
        XFREE(ctx->ibuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    ctx->ibuf     = newbuf;
    ctx->ibuf_cap = new_cap;
    return 0;
}

psa_status_t psa_xof_abort(psa_xof_operation_t *operation);

static psa_status_t wolfpsa_xof_fail(psa_xof_operation_t *op,
                                     psa_status_t status)
{
    (void)psa_xof_abort(op);
    return status;
}

/* ============================================================ psa_xof_setup */

psa_status_t psa_xof_setup(psa_xof_operation_t *operation,
                            psa_algorithm_t      alg)
{
    psa_xof_operation_ctx_t *ctx;
    int ret;

    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    wolfpsa_trace("psa_xof_setup(alg=0x%08x)", (unsigned)alg);

    if (!wolfPSA_CryptoReady())
        return PSA_ERROR_BAD_STATE;

    /* reject non-XOF algorithms */
    if (!PSA_ALG_IS_XOF(alg))
        return PSA_ERROR_INVALID_ARGUMENT;

    /* Ascon XOF: not supported by wolfCrypt */
    if (alg == PSA_ALG_ASCON_XOF128 || alg == PSA_ALG_ASCON_CXOF128)
        return PSA_ERROR_NOT_SUPPORTED;

    /* only SHAKE128 / SHAKE256 are supported */
    if (alg != PSA_ALG_SHAKE128 && alg != PSA_ALG_SHAKE256)
        return PSA_ERROR_NOT_SUPPORTED;

    /* operation must be inactive */
    if (operation->opaque != (uintptr_t)NULL)
        return PSA_ERROR_BAD_STATE;

    ctx = (psa_xof_operation_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                              DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL)
        return PSA_ERROR_INSUFFICIENT_MEMORY;

    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;

    switch (alg) {
#ifdef WOLFSSL_SHAKE128
        case PSA_ALG_SHAKE128:
            ctx->block_size = SHAKE128_BLOCK_SIZE;
            ret = wc_InitShake128(&ctx->shake, NULL, wolfPSA_GetDefaultDevID());
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case PSA_ALG_SHAKE256:
            ctx->block_size = SHAKE256_BLOCK_SIZE;
            ret = wc_InitShake256(&ctx->shake, NULL, wolfPSA_GetDefaultDevID());
            break;
#endif
        default:
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ret != 0) {
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return wc_error_to_psa_status(ret);
    }

    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

/* ======================================================= psa_xof_set_context */

psa_status_t psa_xof_set_context(psa_xof_operation_t *operation,
                                  const uint8_t       *context,
                                  size_t               context_length)
{
    psa_xof_operation_ctx_t *ctx = psa_xof_get_ctx(operation);

    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    wolfpsa_trace("psa_xof_set_context(context_length=%zu)", context_length);

    if (ctx == NULL)
        return wolfpsa_xof_fail(operation, PSA_ERROR_BAD_STATE);

    /*
     * PSA 1.4: set_context is only valid for algorithms where
     * PSA_ALG_XOF_HAS_CONTEXT is true.  Neither SHAKE128 nor SHAKE256
     * has a context field, so always return INVALID_ARGUMENT here.
     * A rejected context aborts the operation like any other error.
     */
    if (!PSA_ALG_XOF_HAS_CONTEXT(ctx->alg))
        return wolfpsa_xof_fail(operation, PSA_ERROR_INVALID_ARGUMENT);

    /* Unreachable for SHAKE (kept for future context-supporting algs) */
    if (ctx->squeezing || ctx->ibuf_len > 0)
        return wolfpsa_xof_fail(operation, PSA_ERROR_BAD_STATE);

    (void)context;
    (void)context_length;
    return wolfpsa_xof_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
}

/* ========================================================= psa_xof_update */

psa_status_t psa_xof_update(psa_xof_operation_t *operation,
                             const uint8_t       *input,
                             size_t               input_length)
{
    psa_xof_operation_ctx_t *ctx = psa_xof_get_ctx(operation);
    size_t need;

    if (operation == NULL || (input == NULL && input_length > 0))
        return wolfpsa_xof_fail(operation, PSA_ERROR_INVALID_ARGUMENT);

    if (ctx == NULL)
        return wolfpsa_xof_fail(operation, PSA_ERROR_BAD_STATE);

    /* cannot update after squeezing has started */
    if (ctx->squeezing)
        return wolfpsa_xof_fail(operation, PSA_ERROR_BAD_STATE);

    /* zero-length update is a no-op */
    if (input_length == 0)
        return PSA_SUCCESS;

    if (wolfpsa_check_word32_length(input_length) != PSA_SUCCESS)
        return wolfpsa_xof_fail(operation, PSA_ERROR_INVALID_ARGUMENT);

    /* accumulate input for the deferred single Absorb() call; keep the
     * total within the word32 range the backend Absorb() takes. The
     * subtraction form is what holds where size_t is 32 bits, where
     * need > UINT32_MAX can never be true after the sum wraps
     * (ibuf_len stays <= UINT32_MAX, so the RHS cannot underflow). */
    if (input_length > (size_t)UINT32_MAX - ctx->ibuf_len)
        return wolfpsa_xof_fail(operation, PSA_ERROR_INVALID_ARGUMENT);
    need = ctx->ibuf_len + input_length;

    if (psa_xof_ibuf_grow(ctx, need) != 0)
        return wolfpsa_xof_fail(operation, PSA_ERROR_INSUFFICIENT_MEMORY);

    XMEMCPY(ctx->ibuf + ctx->ibuf_len, input, input_length);
    ctx->ibuf_len += input_length;

    return PSA_SUCCESS;
}

/* ========================================================= psa_xof_output */

/*
 * Absorb all buffered input (exactly once), then serve output_length bytes
 * from the squeezed keystream.
 *
 * Block-aligned chunks that fill the caller buffer directly are squeezed
 * straight into the output pointer.  A one-block staging buffer handles tails.
 */
psa_status_t psa_xof_output(psa_xof_operation_t *operation,
                             uint8_t             *output,
                             size_t               output_length)
{
    psa_xof_operation_ctx_t *ctx = psa_xof_get_ctx(operation);
    int ret;

    if (operation == NULL || (output == NULL && output_length > 0))
        return wolfpsa_xof_fail(operation, PSA_ERROR_INVALID_ARGUMENT);

    if (ctx == NULL)
        return wolfpsa_xof_fail(operation, PSA_ERROR_BAD_STATE);

    /* zero-length output is fine */
    if (output_length == 0)
        return PSA_SUCCESS;

    /* Transition to squeezing: call Absorb exactly once. */
    if (!ctx->squeezing) {
        const uint8_t *absorb_data = (ctx->ibuf != NULL) ? ctx->ibuf
                                                          : (const uint8_t *)"";
        /* ibuf_len is kept <= UINT32_MAX by psa_xof_update */
        word32 absorb_len = (word32)ctx->ibuf_len;

        switch (ctx->alg) {
#ifdef WOLFSSL_SHAKE128
            case PSA_ALG_SHAKE128:
                ret = wc_Shake128_Absorb(&ctx->shake, absorb_data, absorb_len);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case PSA_ALG_SHAKE256:
                ret = wc_Shake256_Absorb(&ctx->shake, absorb_data, absorb_len);
                break;
#endif
            default:
                return wolfpsa_xof_fail(operation, PSA_ERROR_NOT_SUPPORTED);
        }

        if (ret != 0)
            return wolfpsa_xof_fail(operation, wc_error_to_psa_status(ret));

        /* release the input accumulation buffer now that we've absorbed */
        if (ctx->ibuf != NULL) {
            wc_ForceZero(ctx->ibuf, ctx->ibuf_cap);
            XFREE(ctx->ibuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ctx->ibuf = NULL;
        }
        ctx->ibuf_len = 0;
        ctx->ibuf_cap = 0;

        ctx->squeezing = 1;
        ctx->buf_off   = 0;
        ctx->buf_len   = 0;
    }

    /* Serve bytes from the staging buffer and/or direct squeeze. */
    while (output_length > 0) {
        /* 1. Drain the staging buffer first. */
        if (ctx->buf_off < ctx->buf_len) {
            word32 avail = ctx->buf_len - ctx->buf_off;
            word32 take  = (output_length < (size_t)avail)
                               ? (word32)output_length
                               : avail;
            XMEMCPY(output, ctx->buf + ctx->buf_off, take);
            output        += take;
            output_length -= take;
            ctx->buf_off  += take;
            continue;
        }

        /* Staging buffer is empty; reset it. */
        ctx->buf_off = 0;
        ctx->buf_len = 0;

        /* 2. If caller wants >= one full block, squeeze directly.
         * The backend takes a word32 block count and the byte product
         * must not wrap either, so squeeze in chunks for requests
         * whose block count exceeds that range. */
        if (output_length >= (size_t)ctx->block_size) {
            size_t max_blocks = ((size_t)UINT32_MAX) / ctx->block_size;

            while (output_length >= (size_t)ctx->block_size) {
                size_t n_blocks = output_length / ctx->block_size;
                size_t produced;

                if (n_blocks > max_blocks)
                    n_blocks = max_blocks;

                switch (ctx->alg) {
#ifdef WOLFSSL_SHAKE128
                    case PSA_ALG_SHAKE128:
                        ret = wc_Shake128_SqueezeBlocks(&ctx->shake, output,
                                                        (word32)n_blocks);
                        break;
#endif
#ifdef WOLFSSL_SHAKE256
                    case PSA_ALG_SHAKE256:
                        ret = wc_Shake256_SqueezeBlocks(&ctx->shake, output,
                                                        (word32)n_blocks);
                        break;
#endif
                    default:
                        return wolfpsa_xof_fail(operation,
                                                PSA_ERROR_NOT_SUPPORTED);
                }

                if (ret != 0)
                    return wolfpsa_xof_fail(operation,
                                            wc_error_to_psa_status(ret));

                produced = n_blocks * (size_t)ctx->block_size;
                output        += produced;
                output_length -= produced;
            }
            if (output_length == 0)
                break;
        }

        /* 3. Tail: squeeze one block into the staging buffer. */
        switch (ctx->alg) {
#ifdef WOLFSSL_SHAKE128
            case PSA_ALG_SHAKE128:
                ret = wc_Shake128_SqueezeBlocks(&ctx->shake, ctx->buf, 1);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case PSA_ALG_SHAKE256:
                ret = wc_Shake256_SqueezeBlocks(&ctx->shake, ctx->buf, 1);
                break;
#endif
            default:
                return wolfpsa_xof_fail(operation, PSA_ERROR_NOT_SUPPORTED);
        }

        if (ret != 0)
            return wolfpsa_xof_fail(operation, wc_error_to_psa_status(ret));

        ctx->buf_len = ctx->block_size;
        ctx->buf_off = 0;
        /* loop back to drain */
    }

    return PSA_SUCCESS;
}

/* ========================================================= psa_xof_abort */

psa_status_t psa_xof_abort(psa_xof_operation_t *operation)
{
    psa_xof_operation_ctx_t *ctx;

    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    ctx = psa_xof_get_ctx(operation);
    if (ctx == NULL)
        return PSA_SUCCESS; /* already inactive: PSA_SUCCESS per spec */

    psa_xof_free_ctx(ctx);
    wc_ForceZero(ctx, sizeof(*ctx));
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    operation->opaque = (uintptr_t)NULL;

    return PSA_SUCCESS;
}

#else /* !WOLFSSL_SHAKE128 && !WOLFSSL_SHAKE256 */

/*
 * No SHAKE backend in this build.  The XOF API is declared in
 * crypto.h and exported in wolfpsa.map, so the symbols must exist in
 * every configuration: report PSA_ERROR_NOT_SUPPORTED at run time
 * instead of failing at link time.
 */

psa_status_t psa_xof_setup(psa_xof_operation_t *operation,
                           psa_algorithm_t alg)
{
    (void)alg;
    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_xof_set_context(psa_xof_operation_t *operation,
                                 const uint8_t *context,
                                 size_t context_length)
{
    (void)context;
    (void)context_length;
    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;
    /* No backend: no operation can ever be active. */
    return PSA_ERROR_BAD_STATE;
}

psa_status_t psa_xof_update(psa_xof_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length)
{
    (void)input;
    (void)input_length;
    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;
    return PSA_ERROR_BAD_STATE;
}

psa_status_t psa_xof_output(psa_xof_operation_t *operation,
                            uint8_t *output,
                            size_t output_length)
{
    (void)output;
    (void)output_length;
    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;
    return PSA_ERROR_BAD_STATE;
}

psa_status_t psa_xof_abort(psa_xof_operation_t *operation)
{
    if (operation == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;
    /* No backend: no active operation can exist, nothing to release. */
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_SHAKE128 || WOLFSSL_SHAKE256 */

#endif /* WOLFSSL_PSA_ENGINE */
