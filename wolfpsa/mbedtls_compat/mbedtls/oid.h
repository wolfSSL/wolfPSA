/* oid.h
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

/* The function only, without the MBEDTLS_OID_* values */

#ifndef MBEDTLS_OID_H
#define MBEDTLS_OID_H

#include "mbedtls/build_info.h"
#include "mbedtls/asn1.h"

#include <stddef.h>

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

int mbedtls_oid_get_numeric_string(char* buf, size_t size,
    const mbedtls_asn1_buf* oid);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* MBEDTLS_OID_H */
