/* ecp.h
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

/* The Mbed TLS 3.6 EC key of mbedtls_pk_ec(), with WOLFPSA_MBEDTLS_3 */

#ifndef MBEDTLS_ECP_H
#define MBEDTLS_ECP_H

#include "mbedtls/build_info.h"
#include "psa/crypto.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_ERR_ECP_BAD_INPUT_DATA      PSA_ERROR_INVALID_ARGUMENT
#define MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE PSA_ERROR_NOT_SUPPORTED
#define MBEDTLS_ERR_ECP_ALLOC_FAILED        PSA_ERROR_INSUFFICIENT_MEMORY
#define MBEDTLS_ERR_ECP_RANDOM_FAILED       PSA_ERROR_INSUFFICIENT_ENTROPY

typedef enum {
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1,
    MBEDTLS_ECP_DP_SECP224R1,
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_SECP384R1,
    MBEDTLS_ECP_DP_SECP521R1,
    MBEDTLS_ECP_DP_BP256R1,
    MBEDTLS_ECP_DP_BP384R1,
    MBEDTLS_ECP_DP_BP512R1,
    MBEDTLS_ECP_DP_CURVE25519,
    MBEDTLS_ECP_DP_SECP192K1,
    MBEDTLS_ECP_DP_SECP224K1,
    MBEDTLS_ECP_DP_SECP256K1,
    MBEDTLS_ECP_DP_CURVE448
} mbedtls_ecp_group_id;

/* Opaque: only mbedtls_pk_ec() returns one */
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;

int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair* key,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_ECP_H */
