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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfpsa/psa_engine.h>
#include <mbedtls/x509_crt.h>
#include "psa_tf_psa_internal.h"

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

/* Decodes der without verifying it. Free cert with wc_FreeDecodedCert()
 * whatever the result. */
static int MbedCertDecode(DecodedCert* cert, const byte* der, word32 len)
{
    wc_InitDecodedCert(cert, der, len, NULL);
    return wc_ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL);
}

/* Checks buf decodes as a certificate, without verifying it. Sets *len to
 * the certificate's length, dropping any trailing data. */
static int MbedCertCheck(const unsigned char* buf, size_t* len)
{
    DecodedCert* cert;
    word32 idx = 0;
    int seqLen;
    int ret;

    if (GetSequence(buf, &idx, &seqLen, (word32)*len) < 0) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    *len = idx + (word32)seqLen;
    cert = (DecodedCert*)XMALLOC(sizeof(*cert), NULL, DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    ret = MbedCertDecode(cert, buf, (word32)*len);
    wc_FreeDecodedCert(cert);
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);

    return wolfPSA_MbedRet(ret, MBEDTLS_ERR_X509_INVALID_FORMAT);
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
        XFREE(cur->raw.p, NULL, DYNAMIC_TYPE_CERT);
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
    unsigned char* copy;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_der");

    ret = MbedParseCheck(chain, buf);
    if (ret == 0 && (word32)buflen != buflen) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if (ret == 0) {
        ret = MbedCertCheck(buf, &buflen);
    }
    if (ret != 0) {
        return ret;
    }

    copy = (unsigned char*)XMALLOC(buflen, NULL, DYNAMIC_TYPE_CERT);
    if (copy == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    XMEMCPY(copy, buf, buflen);

    while (crt->next != NULL) {
        crt = crt->next;
    }

    if (crt->raw.p != NULL) {
        crt->next = (mbedtls_x509_crt*)XMALLOC(sizeof(*crt), NULL,
            DYNAMIC_TYPE_X509);
        if (crt->next == NULL) {
            XFREE(copy, NULL, DYNAMIC_TYPE_CERT);
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
        crt = crt->next;
        XMEMSET(crt, 0, sizeof(*crt));
    }

    crt->raw.p = copy;
    crt->raw.len = buflen;
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

/* Opaque, so applications cannot define their own. C needs a member. */
struct mbedtls_x509_crt_profile {
    char unused;
};

const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default = { 0 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next = { 0 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb = { 0 };

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* WOLFPSA_MBEDTLS_COMPAT */
