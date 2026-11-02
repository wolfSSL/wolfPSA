/* crypto_extra.h
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

/* TF-PSA-Crypto extensions to the PSA Crypto API. */

#ifndef PSA_CRYPTO_EXTRA_H
#define PSA_CRYPTO_EXTRA_H

#include "psa/crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Key IDs never encode an owner (no MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER),
 * so a service key ID is a plain PSA key ID. */
typedef psa_key_id_t mbedtls_svc_key_id_t;

#define MBEDTLS_SVC_KEY_ID_INIT ((mbedtls_svc_key_id_t)0)
#define MBEDTLS_SVC_KEY_ID_GET_KEY_ID(id) (id)
#define MBEDTLS_SVC_KEY_ID_GET_OWNER_ID(id) 0

static inline mbedtls_svc_key_id_t mbedtls_svc_key_id_make(
    unsigned int owner_id, psa_key_id_t key_id)
{
    (void)owner_id;
    return key_id;
}

static inline int mbedtls_svc_key_id_equal(mbedtls_svc_key_id_t id1,
                                           mbedtls_svc_key_id_t id2)
{
    return id1 == id2;
}

static inline int mbedtls_svc_key_id_is_null(mbedtls_svc_key_id_t key)
{
    return key == 0;
}

/* Destroy all volatile keys and return to the state before psa_crypto_init().
 * Not thread safe: call when no other PSA call is in progress. Also
 * unregisters crypto callbacks; register them again after psa_crypto_init(). */
void mbedtls_psa_crypto_free(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PSA_CRYPTO_EXTRA_H */
