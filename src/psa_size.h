/* psa_size.h
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

#ifndef WOLFPSA_SIZE_H
#define WOLFPSA_SIZE_H

#include <stdint.h>

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/hash.h>

/* PSA_HASH_MAX_SIZE is derived from the PSA_WANT_ALG_SHA* set, which can be
 * smaller than the largest digest this hash engine accepts when XOFs are
 * enabled (a SHAKE256-only build exposes 64-byte SHAKE256-512 output while
 * PSA_HASH_MAX_SIZE stays 32). Internal scratch buffers that must fit any
 * accepted hash use this bound instead. */
#define WOLFPSA_HASH_MAX_SIZE \
    (PSA_HASH_MAX_SIZE >= WC_MAX_DIGEST_SIZE ? PSA_HASH_MAX_SIZE \
                                             : WC_MAX_DIGEST_SIZE)

static inline psa_status_t wolfpsa_check_word32_length(size_t length)
{
    if (length > UINT32_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFPSA_SIZE_H */
