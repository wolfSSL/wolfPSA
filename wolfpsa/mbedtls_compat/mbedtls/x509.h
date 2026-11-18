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

#define MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE -0x2080
#define MBEDTLS_ERR_X509_UNKNOWN_OID         -0x2100
#define MBEDTLS_ERR_X509_INVALID_FORMAT      -0x2180
#define MBEDTLS_ERR_X509_INVALID_VERSION     -0x2200
#define MBEDTLS_ERR_X509_INVALID_SERIAL      -0x2280
#define MBEDTLS_ERR_X509_INVALID_ALG         -0x2300
#define MBEDTLS_ERR_X509_INVALID_NAME        -0x2380
#define MBEDTLS_ERR_X509_INVALID_DATE        -0x2400
#define MBEDTLS_ERR_X509_INVALID_SIGNATURE   -0x2480
#define MBEDTLS_ERR_X509_INVALID_EXTENSIONS  -0x2500
#define MBEDTLS_ERR_X509_UNKNOWN_VERSION     -0x2580
#define MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG     -0x2600
#define MBEDTLS_ERR_X509_SIG_MISMATCH        -0x2680
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED  -0x2700
#define MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT -0x2780
#define MBEDTLS_ERR_X509_BAD_INPUT_DATA      -0x2800
#define MBEDTLS_ERR_X509_FILE_IO_ERROR       -0x2900
#define MBEDTLS_ERR_X509_FATAL_ERROR         -0x3000
#define MBEDTLS_ERR_X509_ALLOC_FAILED        PSA_ERROR_INSUFFICIENT_MEMORY
#define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL    PSA_ERROR_BUFFER_TOO_SMALL

#define MBEDTLS_X509_KU_DIGITAL_SIGNATURE  0x80
#define MBEDTLS_X509_KU_NON_REPUDIATION    0x40
#define MBEDTLS_X509_KU_KEY_ENCIPHERMENT   0x20
#define MBEDTLS_X509_KU_DATA_ENCIPHERMENT  0x10
#define MBEDTLS_X509_KU_KEY_AGREEMENT      0x08
#define MBEDTLS_X509_KU_KEY_CERT_SIGN      0x04
#define MBEDTLS_X509_KU_CRL_SIGN           0x02
#define MBEDTLS_X509_KU_ENCIPHER_ONLY      0x01
#define MBEDTLS_X509_KU_DECIPHER_ONLY      0x8000

#define MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT         0x80
#define MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER         0x40
#define MBEDTLS_X509_NS_CERT_TYPE_EMAIL              0x20
#define MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING     0x10
#define MBEDTLS_X509_NS_CERT_TYPE_RESERVED           0x08
#define MBEDTLS_X509_NS_CERT_TYPE_SSL_CA             0x04
#define MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA           0x02
#define MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA  0x01

#define MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER  (1 << 0)
#define MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER    (1 << 1)
#define MBEDTLS_X509_EXT_KEY_USAGE                 (1 << 2)
#define MBEDTLS_X509_EXT_CERTIFICATE_POLICIES      (1 << 3)
#define MBEDTLS_X509_EXT_POLICY_MAPPINGS           (1 << 4)
#define MBEDTLS_X509_EXT_SUBJECT_ALT_NAME          (1 << 5)
#define MBEDTLS_X509_EXT_ISSUER_ALT_NAME           (1 << 6)
#define MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS   (1 << 7)
#define MBEDTLS_X509_EXT_BASIC_CONSTRAINTS         (1 << 8)
#define MBEDTLS_X509_EXT_NAME_CONSTRAINTS          (1 << 9)
#define MBEDTLS_X509_EXT_POLICY_CONSTRAINTS        (1 << 10)
#define MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE        (1 << 11)
#define MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS   (1 << 12)
#define MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY        (1 << 13)
#define MBEDTLS_X509_EXT_FRESHEST_CRL              (1 << 14)
#define MBEDTLS_X509_EXT_NS_CERT_TYPE              (1 << 16)

#define MBEDTLS_X509_MAX_DN_NAME_SIZE 256

typedef mbedtls_asn1_named_data mbedtls_x509_name;
typedef mbedtls_asn1_sequence mbedtls_x509_sequence;

typedef struct mbedtls_x509_authority {
    mbedtls_x509_buf keyIdentifier;
    mbedtls_x509_sequence authorityCertIssuer;
    mbedtls_x509_buf authorityCertSerialNumber;
    mbedtls_x509_buf raw;
} mbedtls_x509_authority;

typedef struct mbedtls_x509_time {
    int year, mon, day;
    int hour, min, sec;
} mbedtls_x509_time;

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
int mbedtls_x509_dn_gets(char* buf, size_t size, const mbedtls_x509_name* dn);
int mbedtls_x509_serial_gets(char* buf, size_t size,
    const mbedtls_x509_buf* serial);
int mbedtls_x509_time_is_past(const mbedtls_x509_time* to);
int mbedtls_x509_time_is_future(const mbedtls_x509_time* from);
#endif /* MBEDTLS_X509_CRT_PARSE_C */

/* The first entry of the next RDN, or NULL */
static inline mbedtls_x509_name* mbedtls_x509_dn_get_next(
    mbedtls_x509_name* dn)
{
    while (dn->MBEDTLS_PRIVATE(next_merged) && dn->next != NULL) {
        dn = dn->next;
    }
    return dn->next;
}

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_X509_H */
