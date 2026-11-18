/* x509.c
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

/* Mbed TLS 4.x X.509 API on wolfCrypt (MBEDTLS_COMPAT=1). */

/* Plain names for the fields Mbed TLS makes private */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfpsa/psa_engine.h>
#include <mbedtls/x509_crt.h>
#include "psa_tf_psa_internal.h"
#include "mbedtls_compat_internal.h"

/* The generated config has MBEDTLS_X509_CRT_PARSE_C when wolfCrypt parses
 * certificates */
#if defined(MBEDTLS_X509_CRT_PARSE_C) == \
        (defined(NO_ASN) || defined(NO_CERTS))
    #error "MBEDTLS_X509_CRT_PARSE_C does not match NO_ASN and NO_CERTS"
#endif /* MBEDTLS_X509_CRT_PARSE_C == (NO_ASN || NO_CERTS) */

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#if defined(MBEDTLS_FS_IO) && !defined(NO_WOLFSSL_DIR) && !defined(_WIN32)
    #define WOLFPSA_X509_DIR
    #include <dirent.h>
    #include <errno.h>
    #include <sys/stat.h>
#endif /* MBEDTLS_FS_IO && !NO_WOLFSSL_DIR && !_WIN32 */

int MbedCertDecode(DecodedCert* cert, const byte* der, word32 len)
{
    wc_InitDecodedCert(cert, der, len, NULL);
    return wc_ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL);
}

/* Sets *len to the certificate's length, dropping trailing data */
static int MbedCertLen(const unsigned char* buf, size_t* len)
{
    word32 idx = 0;
    int seqLen;

    if (GetSequence(buf, &idx, &seqLen, (word32)*len) < 0) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    *len = idx + (word32)seqLen;
    return 0;
}

/* Reads the header at *idx into buf and moves *idx to the content */
static int MbedDerItem(unsigned char* der, word32* idx, word32 end,
    mbedtls_x509_buf* buf)
{
    byte tag;
    int len;

    XMEMSET(buf, 0, sizeof(*buf));
    if (GetASNTag(der, idx, &tag, end) < 0 ||
            GetLength(der, idx, &len, end) < 0) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    buf->tag = tag;
    buf->len = (size_t)len;
    buf->p = der + *idx;
    return 0;
}

/* As MbedDerItem, but raw spans the whole item and *idx moves past it */
static int MbedDerRaw(unsigned char* der, word32* idx, word32 end,
    mbedtls_x509_buf* raw)
{
    word32 start = *idx;
    int ret;

    ret = MbedDerItem(der, idx, end, raw);
    if (ret == 0) {
        *idx += (word32)raw->len;
        raw->p = der + start;
        raw->len = *idx - start;
    }
    return ret;
}

static void* MbedEntryNew(size_t size)
{
    void* entry = XMALLOC(size, NULL, DYNAMIC_TYPE_X509);

    if (entry != NULL) {
        XMEMSET(entry, 0, size);
    }
    return entry;
}

/* Whether c is one of the n bytes at set */
static int MbedByteIn(byte c, const byte* set, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (set[i] == c) {
            return 1;
        }
    }
    return 0;
}

/* Frees the entries after the first, which is part of the certificate */
static void MbedNameFree(mbedtls_x509_name* name)
{
    mbedtls_x509_name* cur = name->next;
    mbedtls_x509_name* next;

    while (cur != NULL) {
        next = cur->next;
        XFREE(cur, NULL, DYNAMIC_TYPE_X509);
        cur = next;
    }
}

static void MbedSeqFree(mbedtls_x509_sequence* seq)
{
    mbedtls_x509_sequence* cur = seq->next;
    mbedtls_x509_sequence* next;

    while (cur != NULL) {
        next = cur->next;
        XFREE(cur, NULL, DYNAMIC_TYPE_X509);
        cur = next;
    }
}

/* Frees what crt owns, but not crt */
static void MbedCertFreeFields(mbedtls_x509_crt* crt)
{
    XFREE(crt->raw.p, NULL, DYNAMIC_TYPE_CERT);
    MbedNameFree(&crt->issuer);
    MbedNameFree(&crt->subject);
    MbedSeqFree(&crt->subject_alt_names);
    MbedSeqFree(&crt->authority_key_id.authorityCertIssuer);
    MbedSeqFree(&crt->certificate_policies);
    MbedSeqFree(&crt->ext_key_usage);
}

/* The value types Mbed TLS accepts in a name */
static const byte mbedNameTags[] = {
    MBEDTLS_ASN1_BMP_STRING, MBEDTLS_ASN1_UTF8_STRING, MBEDTLS_ASN1_T61_STRING,
    MBEDTLS_ASN1_PRINTABLE_STRING, MBEDTLS_ASN1_IA5_STRING,
    MBEDTLS_ASN1_UNIVERSAL_STRING, MBEDTLS_ASN1_BIT_STRING
};

/* Name at *idx, one entry per attribute in name */
static int MbedNameParse(unsigned char* der, word32* idx, word32 end,
    mbedtls_x509_buf* raw, mbedtls_x509_name* name)
{
    mbedtls_x509_name* cur = NULL;
    mbedtls_x509_buf item;
    word32 i = *idx;
    word32 nameEnd = 0;
    word32 setStart = 0;
    word32 setEnd = 0;
    word32 attrEnd = 0;
    int ret;

    ret = MbedDerRaw(der, idx, end, raw);
    if (ret == 0) {
        ret = MbedDerItem(der, &i, end, &item);
        nameEnd = *idx;
    }
    while (ret == 0 && i < nameEnd) {
        if (i >= setEnd) {
            ret = MbedDerItem(der, &i, nameEnd, &item);
            setStart = i;
            setEnd = i + (word32)item.len;
        }
        if (ret == 0 && cur == NULL) {
            cur = name;
        }
        else if (ret == 0) {
            cur->next_merged = (i != setStart);
            cur->next = (mbedtls_x509_name*)MbedEntryNew(sizeof(*cur));
            cur = cur->next;
            if (cur == NULL) {
                ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            }
        }
        if (ret == 0) {
            ret = MbedDerItem(der, &i, setEnd, &item);
            attrEnd = i + (word32)item.len;
        }
        if (ret == 0) {
            ret = MbedDerItem(der, &i, attrEnd, &cur->oid);
            i += (word32)cur->oid.len;
        }
        if (ret == 0) {
            ret = MbedDerItem(der, &i, attrEnd, &cur->val);
            i = attrEnd;
        }
        if (ret == 0 && !MbedByteIn((byte)cur->val.tag, mbedNameTags,
                sizeof(mbedNameTags))) {
            ret = MBEDTLS_ERR_X509_INVALID_NAME;
        }
    }
    return ret;
}

/* MbedSeqParse() flags */
#define MBED_SEQ_INNER     0x01 /* The first item inside each */
#define MBED_SEQ_NOT_EMPTY 0x02

/* Items of the SEQUENCE OF at idx, with the MBED_SEQ_* flags */
static int MbedSeqParse(unsigned char* der, word32 idx, word32 end,
    mbedtls_x509_sequence* seq, int flags)
{
    mbedtls_x509_sequence* cur = NULL;
    mbedtls_x509_buf item;
    word32 next;
    int ret;

    ret = MbedDerItem(der, &idx, end, &item);
    end = idx + (word32)item.len;
    while (ret == 0 && idx < end) {
        ret = MbedDerItem(der, &idx, end, &item);
        next = idx + (word32)item.len;
        if (ret == 0 && (flags & MBED_SEQ_INNER) != 0) {
            ret = MbedDerItem(der, &idx, next, &item);
        }
        if (ret == 0 && cur == NULL) {
            cur = seq;
        }
        else if (ret == 0) {
            cur->next = (mbedtls_x509_sequence*)MbedEntryNew(sizeof(*cur));
            cur = cur->next;
            if (cur == NULL) {
                ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            }
        }
        if (ret == 0) {
            cur->buf = item;
            idx = next;
        }
    }
    if (ret == 0 && cur == NULL && (flags & MBED_SEQ_NOT_EMPTY) != 0) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    return ret;
}

/* AuthorityKeyIdentifier at idx: the key ID, issuer and serial, each at most
 * once and in that order */
static int MbedAuthKeyIdParse(unsigned char* der, word32 idx, word32 end,
    mbedtls_x509_authority* akid)
{
    mbedtls_x509_buf item;
    word32 start;
    int last = -1;
    int ret;

    ret = MbedDerItem(der, &idx, end, &item);
    end = idx + (word32)item.len;
    while (ret == 0 && idx < end) {
        start = idx;
        ret = MbedDerItem(der, &idx, end, &item);
        if (ret == 0 && (item.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) <= last) {
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        else if (ret == 0 && item.tag == ASN_CONTEXT_SPECIFIC) {
            akid->keyIdentifier = item;
            akid->keyIdentifier.tag = MBEDTLS_ASN1_OCTET_STRING;
        }
        else if (ret == 0 &&
                item.tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
            /* GeneralNames, implicit tag */
            ret = MbedSeqParse(der, start, end, &akid->authorityCertIssuer,
                0);
        }
        else if (ret == 0 && item.tag == (ASN_CONTEXT_SPECIFIC | 2)) {
            akid->authorityCertSerialNumber = item;
            akid->authorityCertSerialNumber.tag = MBEDTLS_ASN1_INTEGER;
        }
        last = item.tag & MBEDTLS_ASN1_TAG_VALUE_MASK;
        idx += (word32)item.len;
    }
    return ret;
}

#define MBED_OID(s) (const byte*)(s), (word32)(sizeof(s) - 1)

/* The extensions Mbed TLS reports in ext_types */
static const struct {
    const byte* oid;
    word32 len;
    int type;
} mbedExts[] = {
    { MBED_OID("\x55\x1D\x13"), MBEDTLS_X509_EXT_BASIC_CONSTRAINTS },
    { MBED_OID("\x55\x1D\x0F"), MBEDTLS_X509_EXT_KEY_USAGE },
    { MBED_OID("\x55\x1D\x25"), MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE },
    { MBED_OID("\x55\x1D\x11"), MBEDTLS_X509_EXT_SUBJECT_ALT_NAME },
    { MBED_OID("\x60\x86\x48\x01\x86\xF8\x42\x01\x01"),
        MBEDTLS_X509_EXT_NS_CERT_TYPE },
    { MBED_OID("\x55\x1D\x20"), MBEDTLS_X509_EXT_CERTIFICATE_POLICIES },
    { MBED_OID("\x55\x1D\x0E"), MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER },
    { MBED_OID("\x55\x1D\x23"), MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER }
};

static int MbedOidIs(const mbedtls_x509_buf* oid, const byte* want,
    word32 len)
{
    return oid->len == len && XMEMCMP(oid->p, want, len) == 0;
}

/* Extensions at idx. Scalar values come from wolfCrypt's decode. */
static int MbedExtParse(mbedtls_x509_crt* crt, unsigned char* der,
    word32 idx, word32 end)
{
    mbedtls_x509_buf item;
    mbedtls_x509_buf oid;
    word32 extEnd;
    size_t i;
    int type;
    int ret;

    ret = MbedDerItem(der, &idx, end, &item);
    end = idx + (word32)item.len;
    while (ret == 0 && idx < end) {
        ret = MbedDerItem(der, &idx, end, &item);
        extEnd = idx + (word32)item.len;
        if (ret == 0) {
            ret = MbedDerItem(der, &idx, extEnd, &oid);
            idx += (word32)oid.len;
        }
        if (ret == 0 && idx < extEnd && der[idx] == ASN_BOOLEAN) {
            ret = MbedDerItem(der, &idx, extEnd, &item);
            idx += (word32)item.len;
        }
        if (ret == 0) {
            ret = MbedDerItem(der, &idx, extEnd, &item);
        }
        type = 0;
        for (i = 0; ret == 0 && i < sizeof(mbedExts) / sizeof(mbedExts[0]);
                i++) {
            if (MbedOidIs(&oid, mbedExts[i].oid, mbedExts[i].len)) {
                type = mbedExts[i].type;
            }
        }
        if ((crt->ext_types & type) != 0) {
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        else if (type == MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
            ret = MbedSeqParse(der, idx, extEnd, &crt->subject_alt_names, 0);
        }
        else if (type == MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) {
            ret = MbedSeqParse(der, idx, extEnd, &crt->ext_key_usage,
                MBED_SEQ_NOT_EMPTY);
        }
        else if (type == MBEDTLS_X509_EXT_CERTIFICATE_POLICIES) {
            ret = MbedSeqParse(der, idx, extEnd, &crt->certificate_policies,
                MBED_SEQ_INNER | MBED_SEQ_NOT_EMPTY);
        }
        else if (type == MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER) {
            ret = MbedDerItem(der, &idx, extEnd, &crt->subject_key_id);
        }
        else if (type == MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER) {
            ret = MbedAuthKeyIdParse(der, idx, extEnd,
                &crt->authority_key_id);
        }
        crt->ext_types |= type;
        idx = extEnd;
    }
    return ret;
}

/* The n digits at *p as a number, or -1. *p moves past them. */
static int MbedDigits(const unsigned char** p, size_t n)
{
    int value = 0;

    for (; n > 0; n--, (*p)++) {
        if (**p < '0' || **p > '9') {
            return -1;
        }
        value = value * 10 + (**p - '0');
    }
    return value;
}

/* Whether a time with no negative fields is in range, as Mbed TLS checks */
static int MbedTimeInRange(const mbedtls_x509_time* t)
{
    static const byte days[] = {
        31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    int leap = (t->year % 4 == 0 && t->year % 100 != 0) ||
        t->year % 400 == 0;

    return t->mon >= 1 && t->mon <= 12 && t->day >= 1 &&
        t->day <= days[t->mon - 1] - (t->mon == 2 && !leap) &&
        t->hour <= 23 && t->min <= 59 && t->sec <= 59;
}

/* UTCTime or GeneralizedTime in seconds, as Mbed TLS reads them */
static int MbedTimeParse(const mbedtls_x509_buf* in, mbedtls_x509_time* t)
{
    const unsigned char* p = in->p;
    size_t yearLen = (in->tag == ASN_UTC_TIME) ? 2 : 4;

    /* As Mbed TLS: Z is optional */
    if ((in->tag != ASN_UTC_TIME && in->tag != ASN_GENERALIZED_TIME) ||
            (in->len != yearLen + 10 &&
            (in->len != yearLen + 11 || in->p[in->len - 1] != 'Z'))) {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }
    t->year = MbedDigits(&p, yearLen);
    t->mon = MbedDigits(&p, 2);
    t->day = MbedDigits(&p, 2);
    t->hour = MbedDigits(&p, 2);
    t->min = MbedDigits(&p, 2);
    t->sec = MbedDigits(&p, 2);
    if (t->year < 0 || t->mon < 0 || t->day < 0 || t->hour < 0 ||
            t->min < 0 || t->sec < 0) {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }
    if (yearLen == 2) {
        t->year += (t->year < 50) ? 2000 : 1900;
    }
    return MbedTimeInRange(t) ? 0 : MBEDTLS_ERR_X509_INVALID_DATE;
}

/* Validity at *idx */
static int MbedValidityParse(unsigned char* der, word32* idx, word32 end,
    mbedtls_x509_crt* crt)
{
    mbedtls_x509_buf item;
    word32 i = *idx;
    int ret;

    ret = MbedDerRaw(der, idx, end, &item);
    if (ret == 0) {
        ret = MbedDerItem(der, &i, end, &item);
    }
    if (ret == 0) {
        ret = MbedDerItem(der, &i, *idx, &item);
    }
    if (ret == 0) {
        ret = MbedTimeParse(&item, &crt->valid_from);
        i += (word32)item.len;
    }
    if (ret == 0) {
        ret = MbedDerItem(der, &i, *idx, &item);
    }
    if (ret == 0) {
        ret = MbedTimeParse(&item, &crt->valid_to);
    }
    return ret;
}

/* Sets the fields of crt from crt->raw, which cert decoded */
static int MbedCertFields(mbedtls_x509_crt* crt, const DecodedCert* cert)
{
    unsigned char* der = crt->raw.p;
    mbedtls_x509_buf item;
    word32 idx = 0;
    word32 end = (word32)crt->raw.len;
    word32 next;
    int ret;

    crt->version = cert->version + 1;
    crt->ca_istrue = cert->isCA;
    crt->max_pathlen = cert->pathLengthSet ? cert->pathLength + 1 : 0;
    crt->key_usage = cert->extKeyUsage;
#ifndef IGNORE_NETSCAPE_CERT_TYPE
    crt->ns_cert_type = cert->nsCertType;
#endif /* !IGNORE_NETSCAPE_CERT_TYPE */

    ret = MbedDerItem(der, &idx, end, &item);
    if (ret == 0) {
        next = idx;
        ret = MbedDerRaw(der, &next, end, &crt->tbs);
        end = next;
    }
    if (ret == 0) {
        ret = MbedDerItem(der, &idx, end, &item);
    }
    if (ret == 0 && idx < end &&
            der[idx] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        ret = MbedDerRaw(der, &idx, end, &item);
    }
    if (ret == 0) {
        ret = MbedDerItem(der, &idx, end, &crt->serial);
        idx += (word32)crt->serial.len;
    }
    if (ret == 0) {
        ret = MbedDerItem(der, &idx, end, &item);
        next = idx + (word32)item.len;
    }
    if (ret == 0) {
        ret = MbedDerItem(der, &idx, next, &crt->sig_oid);
        idx = next;
    }
    if (ret == 0) {
        ret = MbedNameParse(der, &idx, end, &crt->issuer_raw, &crt->issuer);
    }
    if (ret == 0) {
        ret = MbedValidityParse(der, &idx, end, crt);
    }
    if (ret == 0) {
        ret = MbedNameParse(der, &idx, end, &crt->subject_raw,
            &crt->subject);
    }
    if (ret == 0) {
        ret = MbedDerRaw(der, &idx, end, &crt->pk_raw);
    }
    while (ret == 0 && idx < end) {
        ret = MbedDerItem(der, &idx, end, &item);
        next = idx + (word32)item.len;
        if (ret == 0 && item.tag == (ASN_CONTEXT_SPECIFIC | 1)) {
            crt->issuer_id = item;
        }
        else if (ret == 0 && item.tag == (ASN_CONTEXT_SPECIFIC | 2)) {
            crt->subject_id = item;
        }
        else if (ret == 0 &&
                item.tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3)) {
            crt->v3_ext = item;
            ret = MbedExtParse(crt, der, idx, next);
        }
        idx = next;
    }
    return ret;
}

/* Copies buf to crt and sets its fields, freeing them on failure */
static int MbedCertLoad(mbedtls_x509_crt* crt, const unsigned char* buf,
    size_t len)
{
    DecodedCert* cert;
    int ret;

    XMEMSET(crt, 0, sizeof(*crt));
    crt->raw.p = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_CERT);
    cert = (DecodedCert*)XMALLOC(sizeof(*cert), NULL, DYNAMIC_TYPE_DCERT);
    if (crt->raw.p == NULL || cert == NULL) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    else {
        XMEMCPY(crt->raw.p, buf, len);
        crt->raw.len = len;
        crt->raw.tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
        ret = MbedCertDecode(cert, crt->raw.p, (word32)len);
        ret = wolfPSA_MbedRet(ret, MBEDTLS_ERR_X509_INVALID_FORMAT);
        if (ret == 0) {
            ret = MbedCertFields(crt, cert);
        }
        wc_FreeDecodedCert(cert);
    }
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
    if (ret != 0) {
        MbedCertFreeFields(crt);
        XMEMSET(crt, 0, sizeof(*crt));
    }
    return ret;
}

/* The checks common to the parse functions, before any allocation */
static int MbedParseCheck(const mbedtls_x509_crt* chain, const void* in)
{
    if (chain == NULL || in == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    return wolfPSA_CryptoReady() ? 0 : PSA_ERROR_BAD_STATE;
}

void mbedtls_x509_crt_init(mbedtls_x509_crt* crt)
{
    WOLFSSL_ENTER("mbedtls_x509_crt_init");

    if (crt != NULL) {
        XMEMSET(crt, 0, sizeof(*crt));
    }
}

void mbedtls_x509_crt_free(mbedtls_x509_crt* crt)
{
    mbedtls_x509_crt* cur = crt;
    mbedtls_x509_crt* next;

    WOLFSSL_ENTER("mbedtls_x509_crt_free");

    while (cur != NULL) {
        next = cur->next;
        MbedCertFreeFields(cur);
        if (cur != crt) {
            XFREE(cur, NULL, DYNAMIC_TYPE_X509);
        }
        cur = next;
    }
    if (crt != NULL) {
        XMEMSET(crt, 0, sizeof(*crt));
    }
}

/* Returns 0 if all certificates parse, the number that failed if some parse,
 * else an error. buf is DER when pem is 0 or it has no PEM header. */
static int MbedCertParse(mbedtls_x509_crt* chain, const unsigned char* buf,
    size_t len, int pem)
{
    int parsed = 0;
    int failed = 0;
    int ret;
#ifdef WOLFSSL_PEM_TO_DER
    const unsigned char* cur = buf;
    size_t left = len;
    EncryptedInfo info;
    DerBuffer* der;

    while (pem && left > 0) {
        der = NULL;
        XMEMSET(&info, 0, sizeof(info));
        ret = wc_PemToDer(cur, (long)left, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
            break;
        }
        if (ret == 0) {
            ret = mbedtls_x509_crt_parse_der(chain, der->buffer,
                der->length);
        }
        else {
            ret = wolfPSA_MbedRet(ret, MBEDTLS_ERR_X509_INVALID_FORMAT);
        }
        wc_FreeDer(&der);
        if (ret == MBEDTLS_ERR_X509_ALLOC_FAILED) {
            return ret;
        }
        if (ret == 0) {
            parsed++;
        }
        else {
            failed++;
        }
        /* Set once the footer is found, also when the block does not decode */
        if (info.consumed <= 0 || (size_t)info.consumed > left) {
            break;
        }
        cur += info.consumed;
        left -= (size_t)info.consumed;
    }
#else
    (void)pem;
#endif /* WOLFSSL_PEM_TO_DER */

    if (parsed > 0) {
        ret = failed;
    }
    else if (failed > 0) {
        ret = MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    else {
        ret = mbedtls_x509_crt_parse_der(chain, buf, len);
    }
    return ret;
}

int mbedtls_x509_crt_parse(mbedtls_x509_crt* chain,
    const unsigned char* buf, size_t buflen)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse");

    ret = MbedParseCheck(chain, buf);
    if (ret == 0) {
        /* As in Mbed TLS, only NUL terminated data can be PEM */
        ret = MbedCertParse(chain, buf, buflen,
            buflen > 0 && buf[buflen - 1] == '\0');
    }
    return ret;
}

int mbedtls_x509_crt_parse_der(mbedtls_x509_crt* chain,
    const unsigned char* buf, size_t buflen)
{
    mbedtls_x509_crt* crt = chain;
    mbedtls_x509_crt loaded;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_der");

    ret = MbedParseCheck(chain, buf);
    if (ret == 0 && (word32)buflen != buflen) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if (ret == 0) {
        ret = MbedCertLen(buf, &buflen);
    }
    if (ret == 0) {
        ret = MbedCertLoad(&loaded, buf, buflen);
    }
    if (ret != 0) {
        return ret;
    }

    while (crt->next != NULL) {
        crt = crt->next;
    }

    if (crt->raw.p != NULL) {
        crt->next = (mbedtls_x509_crt*)XMALLOC(sizeof(*crt), NULL,
            DYNAMIC_TYPE_X509);
        if (crt->next == NULL) {
            MbedCertFreeFields(&loaded);
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
        crt = crt->next;
    }

    /* The lists start in the struct and point only forward, so it copies */
    *crt = loaded;
    return 0;
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_x509_crt_parse_file(mbedtls_x509_crt* chain, const char* path)
{
    unsigned char* buf = NULL;
    size_t len = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_file");

    ret = MbedParseCheck(chain, path);
    if (ret == 0) {
        ret = wolfPSA_MbedLoadFile(path, &buf, &len);
    }
    if (ret == 0) {
        /* Mbed TLS NUL terminates a file with a PEM header */
        ret = MbedCertParse(chain, buf, len, 1);
    }
    wolfPSA_MbedFreeFile(buf, len);
    return ret;
}

#ifdef WOLFPSA_X509_DIR
/* As in Mbed TLS, a file that does not parse counts as one failure, and an
 * entry that stat() does not find, such as a dangling symlink, is skipped */
static int MbedParseDir(mbedtls_x509_crt* chain, const char* path)
{
    char name[MBEDTLS_X509_MAX_FILE_PATH_LEN];
    struct dirent* entry;
    struct stat st;
    DIR* dir;
    int failed = 0;
    int fileRet;
    int ret = 0;

    dir = opendir(path);
    if (dir == NULL) {
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }

    while (ret == 0) {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL) {
            /* NULL at the end, and on an error with errno set */
            if (errno != 0) {
                ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            }
            break;
        }
        fileRet = XSNPRINTF(name, sizeof(name), "%s/%s", path, entry->d_name);
        if (fileRet < 0 || (size_t)fileRet >= sizeof(name)) {
            ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        else if (stat(name, &st) != 0) {
            if (errno != ENOENT) {
                ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            }
        }
        else if (S_ISREG(st.st_mode)) {
            fileRet = mbedtls_x509_crt_parse_file(chain, name);
            failed += (fileRet < 0) ? 1 : fileRet;
        }
    }
    (void)closedir(dir);

    return (ret == 0) ? failed : ret;
}
#endif /* WOLFPSA_X509_DIR */

int mbedtls_x509_crt_parse_path(mbedtls_x509_crt* chain, const char* path)
{
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_path");

    ret = MbedParseCheck(chain, path);
    if (ret == 0) {
#ifdef WOLFPSA_X509_DIR
        ret = MbedParseDir(chain, path);
#else
        ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
#endif /* WOLFPSA_X509_DIR */
    }
    return ret;
}
#endif /* MBEDTLS_FS_IO */

/* Moves p and n past what XSNPRINTF wrote, as MBEDTLS_X509_SAFE_SNPRINTF */
static int MbedAdvance(int ret, char** p, size_t* n)
{
    if (ret < 0 || (size_t)ret >= *n) {
        return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
    }
    *p += ret;
    *n -= (size_t)ret;
    return 0;
}

/* The attributes Mbed TLS prints by short name */
static const struct {
    const byte* oid;
    word32 len;
    const char* name;
} mbedAttrs[] = {
    { MBED_OID("\x55\x04\x03"), "CN" },
    { MBED_OID("\x55\x04\x06"), "C" },
    { MBED_OID("\x55\x04\x07"), "L" },
    { MBED_OID("\x55\x04\x08"), "ST" },
    { MBED_OID("\x55\x04\x0A"), "O" },
    { MBED_OID("\x55\x04\x0B"), "OU" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01"), "emailAddress" },
    { MBED_OID("\x55\x04\x05"), "serialNumber" },
    { MBED_OID("\x55\x04\x10"), "postalAddress" },
    { MBED_OID("\x55\x04\x11"), "postalCode" },
    { MBED_OID("\x55\x04\x04"), "SN" },
    { MBED_OID("\x55\x04\x2A"), "GN" },
    { MBED_OID("\x55\x04\x2B"), "initials" },
    { MBED_OID("\x55\x04\x2C"), "generationQualifier" },
    { MBED_OID("\x55\x04\x0C"), "title" },
    { MBED_OID("\x55\x04\x2E"), "dnQualifier" },
    { MBED_OID("\x55\x04\x41"), "pseudonym" },
    { MBED_OID("\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01"), "uid" },
    { MBED_OID("\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19"), "DC" },
    { MBED_OID("\x55\x04\x2D"), "uniqueIdentifier" }
};

static const char* MbedAttrName(const mbedtls_x509_buf* oid)
{
    size_t i;

    for (i = 0; i < sizeof(mbedAttrs) / sizeof(mbedAttrs[0]); i++) {
        if (MbedOidIs(oid, mbedAttrs[i].oid, mbedAttrs[i].len)) {
            return mbedAttrs[i].name;
        }
    }
    return NULL;
}

/* Appends oid in dotted decimal form. Nothing is appended on error. */
static int MbedOidPrint(char** p, size_t* n, const mbedtls_x509_buf* oid)
{
    char* q = *p;
    size_t m = *n;
    word32 value = 0;
    word32 arc;
    size_t i;
    int first = 1;
    int ret = 0;

    if (oid->len == 0 || (oid->p[oid->len - 1] & 0x80) != 0) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    for (i = 0; ret == 0 && i < oid->len; i++) {
        if ((value == 0 && oid->p[i] == 0x80) || value > (0xFFFFFFFFU >> 7)) {
            return MBEDTLS_ERR_ASN1_INVALID_DATA;
        }
        value = (value << 7) | (oid->p[i] & 0x7F);
        if ((oid->p[i] & 0x80) != 0) {
            continue;
        }
        if (first) {
            arc = (value < 80) ? value / 40 : 2;
            ret = MbedAdvance(XSNPRINTF(q, m, "%u.%u", arc, value - arc * 40),
                &q, &m);
            first = 0;
        }
        else {
            ret = MbedAdvance(XSNPRINTF(q, m, ".%u", value), &q, &m);
        }
        value = 0;
    }
    if (ret == 0) {
        *p = q;
        *n = m;
    }
    return ret;
}

/* Whether RFC 4514 escapes c anywhere in a value */
static int MbedDnSpecial(byte c)
{
    static const char special[] = ",=+<>;\"\\";

    return MbedByteIn(c, (const byte*)special, sizeof(special) - 1);
}

/* Room for extra characters after j and a NUL, as Mbed TLS checks */
#define MBED_DN_ROOM(j, extra, size) ((j) + (extra) + 1 < (size))

/* "#" and the hex of the DER, or the text escaped as in RFC 4514 */
static int MbedDnValue(char* s, size_t size, const mbedtls_x509_name* name,
    int hex)
{
    static const char hexDigits[] = "0123456789ABCDEF";
    byte hdr[1 + MAX_LENGTH_SZ];
    word32 hdrSz;
    size_t j = 0;
    size_t i;
    byte c;

    if (hex) {
        /* Two characters a byte, so a longer value cannot fit */
        if (name->val.len >= size / 2) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        hdr[0] = (byte)name->val.tag;
        hdrSz = 1 + SetLength((word32)name->val.len, hdr + 1);
        s[j++] = '#';
        for (i = 0; i < hdrSz + name->val.len; i++) {
            if (!MBED_DN_ROOM(j, 1, size)) {
                return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            }
            c = (i < hdrSz) ? hdr[i] : name->val.p[i - hdrSz];
            s[j++] = hexDigits[c >> 4];
            s[j++] = hexDigits[c & 0x0F];
        }
    }
    for (i = 0; !hex && i < name->val.len; i++) {
        c = name->val.p[i];
        if (!MBED_DN_ROOM(j, 0, size)) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        if (c == '\0') {
            return MBEDTLS_ERR_X509_INVALID_NAME;
        }
        if (MbedDnSpecial(c) || (i == 0 && (c == '#' || c == ' ')) ||
                (i == name->val.len - 1 && c == ' ')) {
            if (!MBED_DN_ROOM(j, 1, size)) {
                return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            }
            s[j++] = '\\';
            s[j++] = (char)c;
        }
        else if (c < 32 || c >= 127) {
            if (!MBED_DN_ROOM(j, 3, size)) {
                return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            }
            s[j++] = '\\';
            s[j++] = hexDigits[c >> 4];
            s[j++] = hexDigits[c & 0x0F];
        }
        else {
            s[j++] = (char)c;
        }
    }
    s[j] = '\0';
    return 0;
}

int mbedtls_x509_dn_gets(char* buf, size_t size, const mbedtls_x509_name* dn)
{
    char s[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    const mbedtls_x509_name* name;
    const char* shortName;
    char* p = buf;
    size_t n = size;
    int merge = 0;
    int hex;
    int ret = 0;

    if (size > 0) {
        buf[0] = '\0';
    }
    for (name = dn; ret == 0 && name != NULL; name = name->next) {
        if (name->oid.p == NULL) {
            continue;
        }
        if (name != dn) {
            ret = MbedAdvance(XSNPRINTF(p, n, merge ? " + " : ", "), &p, &n);
        }
        hex = name->val.tag != MBEDTLS_ASN1_UTF8_STRING &&
            name->val.tag != MBEDTLS_ASN1_PRINTABLE_STRING &&
            name->val.tag != MBEDTLS_ASN1_IA5_STRING;
        shortName = MbedAttrName(&name->oid);
        if (ret == 0 && shortName != NULL) {
            ret = MbedAdvance(XSNPRINTF(p, n, "%s=", shortName), &p, &n);
        }
        else if (ret == 0) {
            ret = MbedOidPrint(&p, &n, &name->oid);
            if (ret == 0) {
                ret = MbedAdvance(XSNPRINTF(p, n, "="), &p, &n);
                hex = 1;
            }
            else if (ret != MBEDTLS_ERR_X509_BUFFER_TOO_SMALL) {
                ret = MbedAdvance(XSNPRINTF(p, n, "\?\?="), &p, &n);
            }
        }
        if (ret == 0) {
            ret = MbedDnValue(s, sizeof(s), name, hex);
        }
        if (ret == 0) {
            ret = MbedAdvance(XSNPRINTF(p, n, "%s", s), &p, &n);
        }
        merge = name->next_merged;
    }
    return (ret == 0) ? (int)(size - n) : ret;
}

int mbedtls_x509_serial_gets(char* buf, size_t size,
    const mbedtls_x509_buf* serial)
{
    /* As Mbed TLS: up to 32 bytes, else the first 28 and "...." */
    size_t shown = (serial->len <= 32) ? serial->len : 28;
    char* p = buf;
    size_t n = size;
    size_t i;
    int ret = 0;

    if (size > 0) {
        buf[0] = '\0';
    }
    for (i = 0; ret == 0 && i < shown; i++) {
        if (i == 0 && shown > 1 && serial->p[0] == 0) {
            continue;
        }
        ret = MbedAdvance(XSNPRINTF(p, n, "%02X%s", serial->p[i],
            (i < shown - 1) ? ":" : ""), &p, &n);
    }
    if (ret == 0 && shown != serial->len) {
        ret = MbedAdvance(XSNPRINTF(p, n, "...."), &p, &n);
    }
    return (ret == 0) ? (int)(size - n) : ret;
}

#ifndef NO_ASN_TIME
/* Negative, 0 or positive as a is before, equal to or after b */
static int MbedTimeCmp(const mbedtls_x509_time* a, const mbedtls_x509_time* b)
{
    int diff = (a->year - b->year) * 10000 + (a->mon - b->mon) * 100 +
        (a->day - b->day);

    if (diff == 0) {
        diff = (a->hour - b->hour) * 10000 + (a->min - b->min) * 100 +
            (a->sec - b->sec);
    }
    return diff;
}

static int MbedTimeNow(mbedtls_x509_time* now)
{
    time_t t = wc_Time(NULL);
    struct tm* tm;
    struct tm* tmpTime = NULL;
#if defined(NEED_TMP_TIME)
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#endif /* NEED_TMP_TIME */
    (void)tmpTime;

    tm = (t == (time_t)-1) ? NULL : XGMTIME(&t, tmpTime);
    if (tm == NULL) {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    now->year = tm->tm_year + 1900;
    now->mon = tm->tm_mon + 1;
    now->day = tm->tm_mday;
    now->hour = tm->tm_hour;
    now->min = tm->tm_min;
    now->sec = tm->tm_sec;
    return 0;
}
#endif /* !NO_ASN_TIME */

/* Without a clock, as Mbed TLS without MBEDTLS_HAVE_TIME_DATE: neither */
int mbedtls_x509_time_is_past(const mbedtls_x509_time* to)
{
#ifndef NO_ASN_TIME
    mbedtls_x509_time now;

    return MbedTimeNow(&now) != 0 || MbedTimeCmp(to, &now) < 0;
#else
    (void)to;
    return 0;
#endif /* !NO_ASN_TIME */
}

int mbedtls_x509_time_is_future(const mbedtls_x509_time* from)
{
#ifndef NO_ASN_TIME
    mbedtls_x509_time now;

    return MbedTimeNow(&now) != 0 || MbedTimeCmp(from, &now) > 0;
#else
    (void)from;
    return 0;
#endif /* !NO_ASN_TIME */
}

int mbedtls_x509_crt_get_ca_istrue(const mbedtls_x509_crt* crt)
{
    if ((crt->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) == 0) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    return crt->ca_istrue;
}

/* encipherOnly and decipherOnly may be set only if asked for */
int mbedtls_x509_crt_check_key_usage(const mbedtls_x509_crt* crt,
    unsigned int usage)
{
    const unsigned int may = MBEDTLS_X509_KU_ENCIPHER_ONLY |
        MBEDTLS_X509_KU_DECIPHER_ONLY;

    if ((crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) == 0) {
        return 0;
    }
    if ((crt->key_usage & usage & ~may) != (usage & ~may) ||
            (crt->key_usage & may & ~usage) != 0) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    return 0;
}

int mbedtls_x509_crt_check_extended_key_usage(const mbedtls_x509_crt* crt,
    const char* usage_oid, size_t usage_len)
{
    const mbedtls_x509_sequence* cur;

    if ((crt->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) == 0) {
        return 0;
    }
    for (cur = &crt->ext_key_usage; cur != NULL; cur = cur->next) {
        if (MbedOidIs(&cur->buf, (const byte*)usage_oid, (word32)usage_len) ||
                MbedOidIs(&cur->buf, MBED_OID("\x55\x1D\x25\x00"))) {
            return 0;
        }
    }
    return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
}

/* Opaque, so applications cannot define their own. C needs a member. */
struct mbedtls_x509_crt_profile {
    char unused;
};

const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default = { 0 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next = { 0 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb = { 0 };

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
