/* psa_tf_psa.c
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

/* TF-PSA-Crypto functions outside the PSA Crypto API. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <mbedtls/platform_util.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfpsa/psa_engine.h>

void mbedtls_psa_crypto_free(void)
{
    wolfPSA_CryptoCleanup();
}

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    if (buf != NULL && len > 0) {
        wc_ForceZero(buf, len);
    }
}

#endif /* WOLFSSL_PSA_ENGINE */
