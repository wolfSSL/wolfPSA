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

/* As MbedDerItem, for the tag tag, ending at end if last, else err */
static int MbedDerTag(unsigned char* der, word32* idx, word32 end, byte tag,
    int last, int err, mbedtls_x509_buf* buf)
{
    if (MbedDerItem(der, idx, end, buf) != 0 || buf->tag != tag ||
            (last && *idx + buf->len != end)) {
        return err;
    }
    return 0;
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
    mbedtls_pk_free(&crt->pk);
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
    const int err = MBEDTLS_ERR_X509_INVALID_NAME;
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
            ret = MbedDerTag(der, &i, nameEnd, ASN_SET | ASN_CONSTRUCTED, 0,
                err, &item);
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
            ret = MbedDerTag(der, &i, setEnd, ASN_SEQUENCE | ASN_CONSTRUCTED, 0,
                err, &item);
            attrEnd = i + (word32)item.len;
        }
        if (ret == 0) {
            ret = MbedDerTag(der, &i, attrEnd, ASN_OBJECT_ID, 0, err,
                &cur->oid);
            i += (word32)cur->oid.len;
        }
        if (ret == 0 && (MbedDerItem(der, &i, attrEnd, &cur->val) != 0 ||
                i + (word32)cur->val.len != attrEnd ||
                !MbedByteIn((byte)cur->val.tag, mbedNameTags,
                sizeof(mbedNameTags)))) {
            ret = err;
        }
        i = attrEnd;
    }
    return ret;
}

/* PolicyInformation from idx to end: the OID into oid, then qualifiers */
static int MbedPolicyParse(unsigned char* der, word32 idx, word32 end,
    mbedtls_x509_buf* oid)
{
    const int err = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    mbedtls_x509_buf item;
    int ret;

    ret = MbedDerTag(der, &idx, end, ASN_OBJECT_ID, 0, err, oid);
    idx += (word32)oid->len;
    if (ret == 0 && idx < end) {
        ret = MbedDerTag(der, &idx, end, ASN_SEQUENCE | ASN_CONSTRUCTED, 1,
            err, &item);
    }
    return ret;
}

/* MbedSeqParse() flags */
#define MBED_SEQ_POLICY    0x01 /* PolicyInformation, keep the OID of each */
#define MBED_SEQ_NOT_EMPTY 0x02

/* Items from idx to end, with the MBED_SEQ_* flags */
static int MbedSeqParse(unsigned char* der, word32 idx, word32 end,
    mbedtls_x509_sequence* seq, int flags)
{
    mbedtls_x509_sequence* cur = NULL;
    mbedtls_x509_buf item;
    word32 next;
    int ret = 0;

    while (ret == 0 && idx < end) {
        ret = MbedDerItem(der, &idx, end, &item);
        next = idx + (word32)item.len;
        if (ret == 0 && (flags & MBED_SEQ_POLICY) != 0) {
            ret = item.tag == (ASN_SEQUENCE | ASN_CONSTRUCTED) ?
                MbedPolicyParse(der, idx, next, &item) :
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
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

#define MBED_OID(s) (const byte*)(s), (word32)(sizeof(s) - 1)

typedef struct {
    const byte* oid;
    word32 len;
    const char* name;
} MbedOidName;

/* The extensions Mbed TLS reports in ext_types, and the tag of each value */
static const struct {
    const byte* oid;
    word32 len;
    byte tag;
    int type;
} mbedExts[] = {
    { MBED_OID("\x55\x1D\x13"), ASN_SEQUENCE | ASN_CONSTRUCTED,
        MBEDTLS_X509_EXT_BASIC_CONSTRAINTS },
    { MBED_OID("\x55\x1D\x0F"), ASN_BIT_STRING, MBEDTLS_X509_EXT_KEY_USAGE },
    { MBED_OID("\x55\x1D\x25"), ASN_SEQUENCE | ASN_CONSTRUCTED,
        MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE },
    { MBED_OID("\x55\x1D\x11"), ASN_SEQUENCE | ASN_CONSTRUCTED,
        MBEDTLS_X509_EXT_SUBJECT_ALT_NAME },
    { MBED_OID("\x60\x86\x48\x01\x86\xF8\x42\x01\x01"), ASN_BIT_STRING,
        MBEDTLS_X509_EXT_NS_CERT_TYPE },
    { MBED_OID("\x55\x1D\x20"), ASN_SEQUENCE | ASN_CONSTRUCTED,
        MBEDTLS_X509_EXT_CERTIFICATE_POLICIES },
    { MBED_OID("\x55\x1D\x0E"), ASN_OCTET_STRING,
        MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER },
    { MBED_OID("\x55\x1D\x23"), ASN_SEQUENCE | ASN_CONSTRUCTED,
        MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER }
};

static int MbedOidIs(const mbedtls_x509_buf* oid, const byte* want,
    word32 len)
{
    return oid->len == len && XMEMCMP(oid->p, want, len) == 0;
}

/* The name of oid in the n entries at names, or NULL */
static const char* MbedOidFind(const MbedOidName* names, size_t n,
    const mbedtls_x509_buf* oid)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (MbedOidIs(oid, names[i].oid, names[i].len)) {
            return names[i].name;
        }
    }
    return NULL;
}

#define MBED_OID_FIND(names, oid) MbedOidFind(names, XELEM_CNT(names), oid)

/* A HardwareModuleName otherName, the only one Mbed TLS reads */
static int MbedHwModuleName(const mbedtls_x509_buf* san,
    mbedtls_x509_buf* hwType, mbedtls_x509_buf* hwSerial)
{
    const int err = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    unsigned char* der = san->p;
    mbedtls_x509_buf item;
    word32 idx = 0;
    word32 end = (word32)san->len;
    int ret;

    ret = MbedDerTag(der, &idx, end, ASN_OBJECT_ID, 0, err, &item);
    if (ret == 0 && !MbedOidIs(&item,
            MBED_OID("\x2B\x06\x01\x05\x05\x07\x08\x04"))) {
        ret = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
    }
    if (ret == 0) {
        idx += (word32)item.len;
        ret = MbedDerTag(der, &idx, end, ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED,
            1, err, &item);
    }
    if (ret == 0) {
        ret = MbedDerTag(der, &idx, end, ASN_SEQUENCE | ASN_CONSTRUCTED, 1,
            err, &item);
    }
    if (ret == 0) {
        ret = MbedDerTag(der, &idx, end, ASN_OBJECT_ID, 0, err, hwType);
    }
    if (ret == 0) {
        idx += (word32)hwType->len;
        ret = MbedDerTag(der, &idx, end, ASN_OCTET_STRING, 1, err, hwSerial);
    }
    return ret;
}

/* The Name in a directoryName. Free name with MbedNameFree(). */
static int MbedSanName(const mbedtls_x509_buf* san, mbedtls_x509_name* name)
{
    mbedtls_x509_buf raw;
    word32 idx = 0;
    int ret = MBEDTLS_ERR_X509_INVALID_NAME;

    if (san->len > 0 && san->p[0] == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        ret = MbedNameParse(san->p, &idx, (word32)san->len, &raw, name);
    }
    if ((ret == 0 && name->oid.p == NULL) ||
            (ret != 0 && ret != MBEDTLS_ERR_X509_ALLOC_FAILED)) {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
    }
    return ret;
}

/* The GeneralName tag number, or -1 if not context specific */
static int MbedSanType(const mbedtls_x509_buf* san)
{
    if ((san->tag & MBEDTLS_ASN1_TAG_CLASS_MASK) !=
            MBEDTLS_ASN1_CONTEXT_SPECIFIC) {
        return -1;
    }
    return san->tag & MBEDTLS_ASN1_TAG_VALUE_MASK;
}

/* Reads a SAN as Mbed TLS does, FEATURE_UNAVAILABLE for types it skips */
static int MbedSanParse(const mbedtls_x509_buf* san, mbedtls_x509_buf* hwType,
    mbedtls_x509_buf* hwSerial, mbedtls_x509_name* name)
{
    int ret = 0;

    XMEMSET(hwType, 0, sizeof(*hwType));
    XMEMSET(hwSerial, 0, sizeof(*hwSerial));
    XMEMSET(name, 0, sizeof(*name));
    switch (MbedSanType(san)) {
        case MBEDTLS_X509_SAN_OTHER_NAME:
            ret = MbedHwModuleName(san, hwType, hwSerial);
            break;
        case MBEDTLS_X509_SAN_IP_ADDRESS:
            if (san->len != 4 && san->len != 16) {
                ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
            }
            break;
        case MBEDTLS_X509_SAN_DIRECTORY_NAME:
            ret = MbedSanName(san, name);
            break;
        case MBEDTLS_X509_SAN_RFC822_NAME:
        case MBEDTLS_X509_SAN_DNS_NAME:
        case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            break;
        default:
            ret = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
            break;
    }
    return ret;
}

/* GeneralNames from idx to end, checked as Mbed TLS checks them */
static int MbedSanSeqParse(unsigned char* der, word32 idx, word32 end,
    mbedtls_x509_sequence* seq)
{
    const mbedtls_x509_sequence* cur;
    mbedtls_x509_buf hwType;
    mbedtls_x509_buf hwSerial;
    mbedtls_x509_name name;
    int ret;

    ret = MbedSeqParse(der, idx, end, seq, 0);
    for (cur = seq; ret == 0 && cur != NULL && cur->buf.p != NULL;
            cur = cur->next) {
        if (MbedSanType(&cur->buf) < 0) {
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        else {
            ret = MbedSanParse(&cur->buf, &hwType, &hwSerial, &name);
            MbedNameFree(&name);
        }
        if (ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) {
            ret = 0;
        }
    }
    return ret;
}

/* AuthorityKeyIdentifier from idx to end: key ID, then issuer and serial */
static int MbedAuthKeyIdParse(unsigned char* der, word32 idx, word32 end,
    mbedtls_x509_authority* akid)
{
    const int err = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    mbedtls_x509_buf item;
    int ret = 0;

    if (idx < end && der[idx] == ASN_CONTEXT_SPECIFIC) {
        ret = MbedDerTag(der, &idx, end, ASN_CONTEXT_SPECIFIC, 0, err,
            &akid->keyIdentifier);
        akid->keyIdentifier.tag = MBEDTLS_ASN1_OCTET_STRING;
        idx += (word32)akid->keyIdentifier.len;
    }
    /* The issuer and serial number are both present or both absent */
    if (ret == 0 && idx < end) {
        ret = MbedDerTag(der, &idx, end,
            ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1, 0, err, &item);
        if (ret == 0) {
            /* GeneralNames, implicit tag */
            ret = MbedSanSeqParse(der, idx, idx + (word32)item.len,
                &akid->authorityCertIssuer);
            idx += (word32)item.len;
        }
        if (ret == 0) {
            ret = MbedDerTag(der, &idx, end, ASN_CONTEXT_SPECIFIC | 2, 1, err,
                &akid->authorityCertSerialNumber);
            akid->authorityCertSerialNumber.tag = MBEDTLS_ASN1_INTEGER;
        }
    }
    return ret;
}

/* Extensions at idx. Scalar values come from wolfCrypt's decode. */
static int MbedExtParse(mbedtls_x509_crt* crt, unsigned char* der,
    word32 idx, word32 end)
{
    mbedtls_x509_buf item;
    mbedtls_x509_buf oid;
    word32 extEnd;
    size_t i;
    byte tag = 0;
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
            ret = MbedDerTag(der, &idx, extEnd, ASN_OCTET_STRING, 1,
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS, &item);
        }
        type = 0;
        for (i = 0; ret == 0 && i < sizeof(mbedExts) / sizeof(mbedExts[0]);
                i++) {
            if (MbedOidIs(&oid, mbedExts[i].oid, mbedExts[i].len)) {
                type = mbedExts[i].type;
                tag = mbedExts[i].tag;
            }
        }
        /* Each once, with one value that fills the OCTET STRING */
        if ((crt->ext_types & type) != 0 || (type != 0 &&
                MbedDerTag(der, &idx, extEnd, tag, 1,
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS, &item) != 0)) {
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        else if (type == MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
            ret = MbedSanSeqParse(der, idx, extEnd, &crt->subject_alt_names);
        }
        else if (type == MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) {
            ret = MbedSeqParse(der, idx, extEnd, &crt->ext_key_usage,
                MBED_SEQ_NOT_EMPTY);
        }
        else if (type == MBEDTLS_X509_EXT_CERTIFICATE_POLICIES) {
            ret = MbedSeqParse(der, idx, extEnd, &crt->certificate_policies,
                MBED_SEQ_POLICY | MBED_SEQ_NOT_EMPTY);
        }
        else if (type == MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER) {
            crt->subject_key_id = item;
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
    if (ret == 0) {
        ret = mbedtls_pk_parse_public_key(&crt->pk, crt->pk_raw.p,
            crt->pk_raw.len);
        /* A key pk cannot hold, such as Ed25519, leaves pk empty */
        if (ret == MBEDTLS_ERR_PK_KEY_INVALID_FORMAT ||
                ret == MBEDTLS_ERR_PK_UNKNOWN_PK_ALG ||
                ret == MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE) {
            ret = 0;
        }
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
static const MbedOidName mbedAttrs[] = {
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
        shortName = MBED_OID_FIND(mbedAttrs, &name->oid);
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

#if !defined(MBEDTLS_X509_REMOVE_INFO)
/* The signature algorithms Mbed TLS names */
static const MbedOidName mbedSigAlgs[] = {
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04"), "RSA with MD5" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05"), "RSA with SHA1" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0E"), "RSA with SHA-224" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B"), "RSA with SHA-256" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0C"), "RSA with SHA-384" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0D"), "RSA with SHA-512" },
    { MBED_OID("\x2B\x0E\x03\x02\x1D"), "RSA with SHA1" },
    { MBED_OID("\x2A\x86\x48\xCE\x3D\x04\x01"), "ECDSA with SHA1" },
    { MBED_OID("\x2A\x86\x48\xCE\x3D\x04\x03\x01"), "ECDSA with SHA224" },
    { MBED_OID("\x2A\x86\x48\xCE\x3D\x04\x03\x02"), "ECDSA with SHA256" },
    { MBED_OID("\x2A\x86\x48\xCE\x3D\x04\x03\x03"), "ECDSA with SHA384" },
    { MBED_OID("\x2A\x86\x48\xCE\x3D\x04\x03\x04"), "ECDSA with SHA512" },
    { MBED_OID("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0A"), "RSASSA-PSS" }
};

static const MbedOidName mbedExtKeyUsages[] = {
    { MBED_OID("\x2B\x06\x01\x05\x05\x07\x03\x01"),
        "TLS Web Server Authentication" },
    { MBED_OID("\x2B\x06\x01\x05\x05\x07\x03\x02"),
        "TLS Web Client Authentication" },
    { MBED_OID("\x2B\x06\x01\x05\x05\x07\x03\x03"), "Code Signing" },
    { MBED_OID("\x2B\x06\x01\x05\x05\x07\x03\x04"), "E-mail Protection" },
    { MBED_OID("\x2B\x06\x01\x05\x05\x07\x03\x08"), "Time Stamping" },
    { MBED_OID("\x2B\x06\x01\x05\x05\x07\x03\x09"), "OCSP Signing" },
    { MBED_OID("\x2B\x06\x01\x04\x01\x82\xE4\x25\x01"),
        "Wi-SUN Alliance Field Area Network (FAN)" }
};

static const MbedOidName mbedPolicies[] = {
    { MBED_OID("\x55\x1D\x20\x00"), "Any Policy" }
};

typedef struct {
    word32 flag;
    const char* name;
} MbedFlagName;

static const MbedFlagName mbedCertTypes[] = {
    { MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT, "SSL Client" },
    { MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER, "SSL Server" },
    { MBEDTLS_X509_NS_CERT_TYPE_EMAIL, "Email" },
    { MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING, "Object Signing" },
    { MBEDTLS_X509_NS_CERT_TYPE_RESERVED, "Reserved" },
    { MBEDTLS_X509_NS_CERT_TYPE_SSL_CA, "SSL CA" },
    { MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA, "Email CA" },
    { MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA, "Object Signing CA" }
};

static const MbedFlagName mbedKeyUsages[] = {
    { MBEDTLS_X509_KU_DIGITAL_SIGNATURE, "Digital Signature" },
    { MBEDTLS_X509_KU_NON_REPUDIATION, "Non Repudiation" },
    { MBEDTLS_X509_KU_KEY_ENCIPHERMENT, "Key Encipherment" },
    { MBEDTLS_X509_KU_DATA_ENCIPHERMENT, "Data Encipherment" },
    { MBEDTLS_X509_KU_KEY_AGREEMENT, "Key Agreement" },
    { MBEDTLS_X509_KU_KEY_CERT_SIGN, "Key Cert Sign" },
    { MBEDTLS_X509_KU_CRL_SIGN, "CRL Sign" },
    { MBEDTLS_X509_KU_ENCIPHER_ONLY, "Encipher Only" },
    { MBEDTLS_X509_KU_DECIPHER_ONLY, "Decipher Only" }
};

#define X509_CRT_ERROR_INFO(code, name, text) { (code), (text) },
static const MbedFlagName mbedVerifyInfo[] = {
    MBEDTLS_X509_CRT_ERROR_INFO_LIST
};
#undef X509_CRT_ERROR_INFO

/* The names of the flags set, comma separated */
static int MbedInfoFlags(char** p, size_t* n, word32 flags,
    const MbedFlagName* names, size_t count)
{
    const char* sep = "";
    size_t i;
    int ret = 0;

    for (i = 0; ret == 0 && i < count; i++) {
        if ((flags & names[i].flag) != 0) {
            ret = MbedAdvance(XSNPRINTF(*p, *n, "%s%s", sep, names[i].name),
                p, n);
            sep = ", ";
        }
    }
    return ret;
}

/* The names of the OIDs in seq, comma separated, "???" when unknown */
static int MbedInfoOids(char** p, size_t* n, const mbedtls_x509_sequence* seq,
    const MbedOidName* names, size_t count)
{
    const char* sep = "";
    const char* name;
    int ret = 0;

    for (; ret == 0 && seq != NULL; seq = seq->next) {
        name = MbedOidFind(names, count, &seq->buf);
        ret = MbedAdvance(XSNPRINTF(*p, *n, "%s%s", sep,
            (name != NULL) ? name : "???"), p, n);
        sep = ", ";
    }
    return ret;
}

static int MbedInfoHwModuleName(char** p, size_t* n, const char* prefix,
    const mbedtls_x509_buf* hwType, const mbedtls_x509_buf* hwSerial)
{
    size_t i;
    int ret;

    ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%s        hardware module name :"
        "\n%s            hardware type          : ", prefix, prefix), p, n);
    if (ret == 0 && MbedOidPrint(p, n, hwType) != 0) {
        ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
    }
    if (ret == 0) {
        ret = MbedAdvance(XSNPRINTF(*p, *n,
            "\n%s            hardware serial number : ", prefix), p, n);
    }
    for (i = 0; ret == 0 && i < hwSerial->len; i++) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "%02X",
            (unsigned int)hwSerial->p[i]), p, n);
    }
    return ret;
}

/* IPv4 in dotted decimal, IPv6 as eight hex groups without leading zeros */
static int MbedInfoIp(char** p, size_t* n, const mbedtls_x509_buf* ip)
{
    size_t i;
    int ret = 0;

    for (i = 0; ret == 0 && i < ip->len; i++) {
        if (ip->len == 4) {
            ret = MbedAdvance(XSNPRINTF(*p, *n, "%s%u", (i > 0) ? "." : "",
                (unsigned int)ip->p[i]), p, n);
        }
        else if (i % 2 == 0) {
            ret = MbedAdvance(XSNPRINTF(*p, *n, "%s%X", (i > 0) ? ":" : "",
                ((unsigned int)ip->p[i] << 8) | ip->p[i + 1]), p, n);
        }
    }
    return ret;
}

/* The names Mbed TLS prints, by GeneralName tag */
static const char* const mbedSanNames[] = {
    "otherName", "rfc822Name", "dNSName", NULL, "directoryName", NULL,
    "uniformResourceIdentifier", "iPAddress"
};

/* One subject alternative name, as Mbed TLS prints it */
static int MbedInfoSan(char** p, size_t* n, const char* prefix,
    const mbedtls_x509_buf* san)
{
    mbedtls_x509_buf hwType;
    mbedtls_x509_buf hwSerial;
    mbedtls_x509_name name;
    int type = MbedSanType(san);
    int ret;

    ret = MbedSanParse(san, &hwType, &hwSerial, &name);
    if (ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%s    <unsupported>", prefix),
            p, n);
    }
    else if (ret != 0 && ret != MBEDTLS_ERR_X509_ALLOC_FAILED) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%s    <malformed>", prefix),
            p, n);
    }
    else if (ret == 0) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%s    %s :%s", prefix,
            mbedSanNames[type],
            (type == MBEDTLS_X509_SAN_OTHER_NAME) ? "" : " "), p, n);
        if (ret == 0 && type == MBEDTLS_X509_SAN_OTHER_NAME) {
            ret = MbedInfoHwModuleName(p, n, prefix, &hwType, &hwSerial);
        }
        else if (ret == 0 && type == MBEDTLS_X509_SAN_IP_ADDRESS) {
            ret = MbedInfoIp(p, n, san);
        }
        else if (ret == 0 && type == MBEDTLS_X509_SAN_DIRECTORY_NAME) {
            /* As Mbed TLS, an error from mbedtls_x509_dn_gets() as is */
            ret = mbedtls_x509_dn_gets(*p, *n, &name);
            if (ret >= 0) {
                ret = MbedAdvance(ret, p, n);
            }
        }
        else if (ret == 0 && san->len >= *n) {
            ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        else if (ret == 0) {
            /* The bytes as they are, as Mbed TLS */
            XMEMCPY(*p, san->p, san->len);
            *p += san->len;
            *n -= san->len;
        }
    }
    MbedNameFree(&name);
    return ret;
}

/* As Mbed TLS's mbedtls_x509_pk_type_as_string() */
static const char* MbedPkTypeName(const mbedtls_pk_context* pk)
{
    switch (pk->type) {
        case PK_TYPE_RSA:
        case PK_TYPE_RSA_PUBLIC:
            return "RSA";
        case PK_TYPE_ECC:
        case PK_TYPE_ECC_PUBLIC:
        case PK_TYPE_MONTGOMERY_PUBLIC:
            return "EC";
        default:
            return "NONE";
    }
}

static int MbedInfoTime(char** p, size_t* n, const char* prefix,
    const char* label, const mbedtls_x509_time* t)
{
    return MbedAdvance(XSNPRINTF(*p, *n,
        "\n%s%s: %04d-%02d-%02d %02d:%02d:%02d", prefix, label, t->year,
        t->mon, t->day, t->hour, t->min, t->sec), p, n);
}

/* Mbed TLS pads the key size label to this width */
#define MBED_INFO_KEY_WIDTH 18

static int MbedInfoCert(char** p, size_t* n, const char* prefix,
    const mbedtls_x509_crt* crt)
{
    const char* sigAlg = MBED_OID_FIND(mbedSigAlgs, &crt->sig_oid);
    const mbedtls_x509_sequence* san;
    char keySize[MBED_INFO_KEY_WIDTH];
    int ret;

    ret = MbedAdvance(XSNPRINTF(*p, *n, "%scert. version     : %d\n"
        "%sserial number     : ", prefix, crt->version, prefix), p, n);
    if (ret == 0) {
        ret = MbedAdvance(mbedtls_x509_serial_gets(*p, *n, &crt->serial), p,
            n);
    }
    if (ret == 0) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%sissuer name       : ",
            prefix), p, n);
    }
    if (ret == 0) {
        ret = MbedAdvance(mbedtls_x509_dn_gets(*p, *n, &crt->issuer), p, n);
    }
    if (ret == 0) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%ssubject name      : ",
            prefix), p, n);
    }
    if (ret == 0) {
        ret = MbedAdvance(mbedtls_x509_dn_gets(*p, *n, &crt->subject), p, n);
    }
    if (ret == 0) {
        ret = MbedInfoTime(p, n, prefix, "issued  on        ",
            &crt->valid_from);
    }
    if (ret == 0) {
        ret = MbedInfoTime(p, n, prefix, "expires on        ",
            &crt->valid_to);
    }
    if (ret == 0) {
        (void)XSNPRINTF(keySize, sizeof(keySize), "%s key size",
            MbedPkTypeName(&crt->pk));
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%ssigned using      : %s"
            "\n%s%-*s: %d bits", prefix, (sigAlg != NULL) ? sigAlg : "???",
            prefix, MBED_INFO_KEY_WIDTH, keySize,
            (int)mbedtls_pk_get_bitlen(&crt->pk)), p, n);
    }
    if (ret == 0 && (crt->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS)) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%sbasic constraints : CA=%s",
            prefix, crt->ca_istrue ? "true" : "false"), p, n);
        if (ret == 0 && crt->max_pathlen > 0) {
            ret = MbedAdvance(XSNPRINTF(*p, *n, ", max_pathlen=%d",
                crt->max_pathlen - 1), p, n);
        }
    }
    if (ret == 0 && (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%ssubject alt name  :",
            prefix), p, n);
        for (san = &crt->subject_alt_names; ret == 0 && san != NULL;
                san = san->next) {
            ret = MbedInfoSan(p, n, prefix, &san->buf);
        }
    }
    if (ret == 0 && (crt->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE)) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%scert. type        : ",
            prefix), p, n);
        if (ret == 0) {
            ret = MbedInfoFlags(p, n, crt->ns_cert_type, mbedCertTypes,
                XELEM_CNT(mbedCertTypes));
        }
    }
    if (ret == 0 && (crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE)) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%skey usage         : ",
            prefix), p, n);
        if (ret == 0) {
            ret = MbedInfoFlags(p, n, crt->key_usage, mbedKeyUsages,
                XELEM_CNT(mbedKeyUsages));
        }
    }
    if (ret == 0 && (crt->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE)) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%sext key usage     : ",
            prefix), p, n);
        if (ret == 0) {
            ret = MbedInfoOids(p, n, &crt->ext_key_usage, mbedExtKeyUsages,
                XELEM_CNT(mbedExtKeyUsages));
        }
    }
    if (ret == 0 &&
            (crt->ext_types & MBEDTLS_X509_EXT_CERTIFICATE_POLICIES)) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n%scertificate policies : ",
            prefix), p, n);
        if (ret == 0) {
            ret = MbedInfoOids(p, n, &crt->certificate_policies,
                mbedPolicies, XELEM_CNT(mbedPolicies));
        }
    }
    if (ret == 0) {
        ret = MbedAdvance(XSNPRINTF(*p, *n, "\n"), p, n);
    }
    return ret;
}

int mbedtls_x509_crt_info(char* buf, size_t size, const char* prefix,
    const mbedtls_x509_crt* crt)
{
    char* p = buf;
    size_t n = size;
    int ret;

    if (crt == NULL) {
        ret = MbedAdvance(XSNPRINTF(p, n, "\nCertificate is uninitialised!\n"),
            &p, &n);
    }
    else {
        ret = MbedInfoCert(&p, &n, prefix, crt);
    }
    return (ret == 0) ? (int)(size - n) : ret;
}

int mbedtls_x509_crt_verify_info(char* buf, size_t size, const char* prefix,
    uint32_t flags)
{
    char* p = buf;
    size_t n = size;
    size_t i;
    int ret = 0;

    if (size > 0) {
        buf[0] = '\0';
    }
    for (i = 0; ret == 0 && i < XELEM_CNT(mbedVerifyInfo); i++) {
        if ((flags & mbedVerifyInfo[i].flag) != 0) {
            ret = MbedAdvance(XSNPRINTF(p, n, "%s%s\n", prefix,
                mbedVerifyInfo[i].name), &p, &n);
            flags &= ~(uint32_t)mbedVerifyInfo[i].flag;
        }
    }
    if (ret == 0 && flags != 0) {
        ret = MbedAdvance(XSNPRINTF(p, n,
            "%sUnknown reason (this should not happen)\n", prefix), &p, &n);
    }
    return (ret == 0) ? (int)(size - n) : ret;
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */

/* Opaque, so applications cannot define their own. C needs a member. */
struct mbedtls_x509_crt_profile {
    char unused;
};

const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default = { 0 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next = { 0 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb = { 0 };

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
