/* x509.h
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

#ifndef MBEDTLS_X509_H
#define MBEDTLS_X509_H

#include "mbedtls/build_info.h"
#include "mbedtls/asn1.h"
#include "mbedtls/pk.h"

typedef mbedtls_asn1_buf mbedtls_x509_buf;

#define MBEDTLS_X509_BADCERT_EXPIRED       0x01
#define MBEDTLS_X509_BADCERT_REVOKED       0x02
#define MBEDTLS_X509_BADCERT_CN_MISMATCH   0x04
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED   0x08
#define MBEDTLS_X509_BADCRL_NOT_TRUSTED    0x10
#define MBEDTLS_X509_BADCRL_EXPIRED        0x20
#define MBEDTLS_X509_BADCERT_MISSING       0x40
#define MBEDTLS_X509_BADCERT_SKIP_VERIFY   0x80
#define MBEDTLS_X509_BADCERT_OTHER         0x0100
#define MBEDTLS_X509_BADCERT_FUTURE        0x0200
#define MBEDTLS_X509_BADCRL_FUTURE         0x0400
#define MBEDTLS_X509_BADCERT_KEY_USAGE     0x0800
#define MBEDTLS_X509_BADCERT_EXT_KEY_USAGE 0x1000
#define MBEDTLS_X509_BADCERT_NS_CERT_TYPE  0x2000
#define MBEDTLS_X509_BADCERT_BAD_MD        0x4000
#define MBEDTLS_X509_BADCERT_BAD_PK        0x8000
#define MBEDTLS_X509_BADCERT_BAD_KEY       0x010000
#define MBEDTLS_X509_BADCRL_BAD_MD         0x020000
#define MBEDTLS_X509_BADCRL_BAD_PK         0x040000
#define MBEDTLS_X509_BADCRL_BAD_KEY        0x080000

/* Mbed TLS defines -141 as PSA_ERROR_INSUFFICIENT_MEMORY */
#define MBEDTLS_ERR_X509_INVALID_FORMAT      -0x2180
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED  -0x2700
#define MBEDTLS_ERR_X509_BAD_INPUT_DATA      -0x2800
#define MBEDTLS_ERR_X509_FILE_IO_ERROR       -0x2900
#define MBEDTLS_ERR_X509_ALLOC_FAILED        -141

#endif /* MBEDTLS_X509_H */
