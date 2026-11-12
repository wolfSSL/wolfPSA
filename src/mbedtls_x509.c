/* mbedtls_x509.c
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

#ifndef MBEDTLS_X509_CRT_PARSE_C
    #error "The generated config must define MBEDTLS_X509_CRT_PARSE_C"
#endif /* !MBEDTLS_X509_CRT_PARSE_C */

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

static int MbedCertErr(int ret, int err)
{
    return (ret == WC_NO_ERR_TRACE(MEMORY_E)) ? MBEDTLS_ERR_X509_ALLOC_FAILED :
        err;
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

    return (ret == 0) ? 0 : MbedCertErr(ret, MBEDTLS_ERR_X509_INVALID_FORMAT);
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
 * else an error. Input without a PEM header is DER. Unlike Mbed TLS, PEM
 * need not be NUL terminated. */
int mbedtls_x509_crt_parse(mbedtls_x509_crt* chain,
    const unsigned char* buf, size_t buflen)
{
    const unsigned char* pem = buf;
    size_t len = buflen;
    EncryptedInfo info;
    DerBuffer* der;
    int parsed = 0;
    int failed = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse");

    if (chain == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }

    while (len > 0) {
        der = NULL;
        XMEMSET(&info, 0, sizeof(info));
        ret = wc_PemToDer(pem, (long)len, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
            break;
        }
        if (ret == 0) {
            ret = mbedtls_x509_crt_parse_der(chain, der->buffer,
                der->length);
        }
        else {
            ret = MbedCertErr(ret, MBEDTLS_ERR_X509_INVALID_FORMAT);
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
        if (info.consumed <= 0 || (size_t)info.consumed > len) {
            break;
        }
        pem += info.consumed;
        len -= (size_t)info.consumed;
    }

    if (parsed > 0) {
        ret = failed;
    }
    else if (failed > 0) {
        ret = MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    else {
        ret = mbedtls_x509_crt_parse_der(chain, buf, buflen);
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

    if (chain == NULL || buf == NULL || (word32)buflen != buflen) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }

    ret = MbedCertCheck(buf, &buflen);
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
    byte* buf = NULL;
    size_t len = 0;
    int ret;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_file");

    ret = wc_FileLoad(path, &buf, &len, NULL);
    if (ret == 0) {
        ret = mbedtls_x509_crt_parse(chain, buf, len);
    }
    else {
        /* As in Mbed TLS, which loads the file with mbedtls_pk_load_file() */
        ret = MbedCertErr(ret, MBEDTLS_ERR_PK_FILE_IO_ERROR);
    }
    /* wc_FileLoad() can fail with buf allocated */
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* As in Mbed TLS, a file that does not parse counts as one failure, and an
 * entry that stat() does not find, such as a dangling symlink, is skipped */
int mbedtls_x509_crt_parse_path(mbedtls_x509_crt* chain, const char* path)
{
#ifdef WOLFPSA_X509_DIR
    char name[MBEDTLS_X509_MAX_FILE_PATH_LEN];
    struct dirent* entry;
    struct stat st;
    DIR* dir;
    int failed = 0;
    int fileRet;
    int ret = 0;

    WOLFSSL_ENTER("mbedtls_x509_crt_parse_path");

    if (chain == NULL || path == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }
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
#else
    (void)chain;
    (void)path;
    return MBEDTLS_ERR_X509_FILE_IO_ERROR;
#endif /* WOLFPSA_X509_DIR */
}
#endif /* MBEDTLS_FS_IO */

struct mbedtls_x509_crt_profile {
    uint32_t rsa_min_bitlen;
};

const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default = { 2048 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next = { 2048 };
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb = { 0 };

#endif /* WOLFPSA_MBEDTLS_COMPAT */
