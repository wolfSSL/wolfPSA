/* asn1.h
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

#ifndef MBEDTLS_ASN1_H
#define MBEDTLS_ASN1_H

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>

#define MBEDTLS_ERR_ASN1_OUT_OF_DATA       -0x0060
#define MBEDTLS_ERR_ASN1_UNEXPECTED_TAG    -0x0062
#define MBEDTLS_ERR_ASN1_INVALID_LENGTH    -0x0064
#define MBEDTLS_ERR_ASN1_LENGTH_MISMATCH   -0x0066
#define MBEDTLS_ERR_ASN1_INVALID_DATA      -0x0068

#define MBEDTLS_ASN1_BOOLEAN               0x01
#define MBEDTLS_ASN1_INTEGER               0x02
#define MBEDTLS_ASN1_BIT_STRING            0x03
#define MBEDTLS_ASN1_OCTET_STRING          0x04
#define MBEDTLS_ASN1_NULL                  0x05
#define MBEDTLS_ASN1_OID                   0x06
#define MBEDTLS_ASN1_ENUMERATED            0x0A
#define MBEDTLS_ASN1_UTF8_STRING           0x0C
#define MBEDTLS_ASN1_SEQUENCE              0x10
#define MBEDTLS_ASN1_SET                   0x11
#define MBEDTLS_ASN1_PRINTABLE_STRING      0x13
#define MBEDTLS_ASN1_T61_STRING            0x14
#define MBEDTLS_ASN1_IA5_STRING            0x16
#define MBEDTLS_ASN1_UTC_TIME              0x17
#define MBEDTLS_ASN1_GENERALIZED_TIME      0x18
#define MBEDTLS_ASN1_UNIVERSAL_STRING      0x1C
#define MBEDTLS_ASN1_BMP_STRING            0x1E
#define MBEDTLS_ASN1_PRIMITIVE             0x00
#define MBEDTLS_ASN1_CONSTRUCTED           0x20
#define MBEDTLS_ASN1_CONTEXT_SPECIFIC      0x80

#define MBEDTLS_ASN1_TAG_CLASS_MASK        0xC0
#define MBEDTLS_ASN1_TAG_PC_MASK           0x20
#define MBEDTLS_ASN1_TAG_VALUE_MASK        0x1F

typedef struct mbedtls_asn1_buf {
    int tag;
    size_t len;
    unsigned char* p;
} mbedtls_asn1_buf;

typedef struct mbedtls_asn1_sequence {
    mbedtls_asn1_buf buf;
    struct mbedtls_asn1_sequence* next;
} mbedtls_asn1_sequence;

/* next_merged is set when next is in the same multi-valued RDN */
typedef struct mbedtls_asn1_named_data {
    mbedtls_asn1_buf oid;
    mbedtls_asn1_buf val;
    struct mbedtls_asn1_named_data* next;
    unsigned char next_merged;
} mbedtls_asn1_named_data;

#endif /* MBEDTLS_ASN1_H */
