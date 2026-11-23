/* psa_ccm.h
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

#ifndef WOLFPSA_CCM_H
#define WOLFPSA_CCM_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_PSA_ENGINE) && defined(HAVE_AESCCM) && \
    defined(WOLFSSL_AES_DIRECT)

/* One-shot AES-CCM on wolfPSA's streaming CCM, for code built into the same
 * image that would otherwise link wolfCrypt's one-shot CCM too. They run in
 * software, touch no wolfPSA state, and return 0, BAD_FUNC_ARG,
 * AES_CCM_AUTH_E for a tag mismatch (the output is then zeroed),
 * NOT_COMPILED_IN when PSA_WANT_WITHOUT drops CCM, or a wolfCrypt error. */
WOLFSSL_LOCAL int wolfPSA_AesCcmEncrypt(const byte* key, word32 keySz,
    const byte* nonce, word32 nonceSz, const byte* aad, word32 aadSz,
    const byte* in, word32 inSz, byte* out, byte* tag, word32 tagSz);
WOLFSSL_LOCAL WARN_UNUSED_RESULT int wolfPSA_AesCcmDecrypt(const byte* key, word32 keySz,
    const byte* nonce, word32 nonceSz, const byte* aad, word32 aadSz,
    const byte* in, word32 inSz, const byte* tag, word32 tagSz, byte* out);

#endif /* WOLFSSL_PSA_ENGINE && HAVE_AESCCM && WOLFSSL_AES_DIRECT */

#endif /* WOLFPSA_CCM_H */
