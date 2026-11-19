/* x509_crt_test.c
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

/* Certificate parsing through the Mbed TLS 4.x API, one node per
 * certificate. The cases of mbedtls_x509_crt_parse_file and
 * mbedtls_x509_crt_parse_path come from Mbed TLS's
 * tests/suites/test_suite_x509parse.data. Run from framework/data_files in
 * an Mbed TLS checkout. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef MBEDTLS_THREADING_C
#include <pthread.h>
#endif /* MBEDTLS_THREADING_C */

#include <psa/crypto.h>
#include <mbedtls/x509_crt.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/* Any error code */
#define ERR -1
/* ret with WOLFSSL_ASN_ORIGINAL. wolfCrypt's template parser rejects the
 * certificate first. */
#ifdef WOLFSSL_ASN_TEMPLATE
    #define ASN_ORIGINAL_RET(ret) MBEDTLS_ERR_X509_INVALID_FORMAT
#else
    #define ASN_ORIGINAL_RET(ret) (ret)
#endif /* WOLFSSL_ASN_TEMPLATE */
#define IN "parse_input/"

typedef int (*Parse)(mbedtls_x509_crt* chain, const char* path);

typedef struct {
    const char* file;
    int ret;    /* number that failed, or ERR */
    int certs;
} Case;

static const Case cases[] = {
    { IN "server5.basic-constraints-integer-first.badsign.crt", 0, 1 },
    { IN "server5.basic-constraints-integer-first.selfsigned.crt", 0, 1 },
    { IN "server1_pathlen_int_max.crt", ERR, 0 },
    { "dir3/Readme", ERR, 0 },
    { "dir3/test-ca2.crt", 0, 1 },
    { "dir3/test-ca.crt", 0, 1 },
    { IN "server7_int-ca.crt", 0, 2 },
    { IN "server7_trailing_space.crt", 0, 2 },
    { IN "cli-rsa-sha256-badalg.crt.der", ERR, 0 },
    { IN "server5.basic-constraints-sequence-overflow.badsign.crt", ERR, 0 },
    { IN "server5.basic-constraints-sequence-overflow.selfsigned.crt", ERR,
        0 },
    { "authorityKeyId_subjectKeyId_issuer_tag2_malformed.crt.der", ERR, 0 },
    { "authorityKeyId_subjectKeyId_tag_len_malformed.crt.der", ERR, 0 },
    /* Over WOLFSSL_MAX_PATH_LEN. Mbed TLS: 0, 1 */
    { IN "server1_pathlen_int_max-1.crt", ERR, 0 },
    /* wolfSSL skips spaces in base64. Mbed TLS: 1, 1 and ERR, 0 */
    { IN "server7_pem_space.crt", 0, 2 },
    { IN "server7_all_space.crt", 0, 2 },
    /* Not in Mbed TLS's cases */
    { "test-ca.der", 0, 1 },
    { "missing.crt", MBEDTLS_ERR_PK_FILE_IO_ERROR, 0 },
    /* NULL parameters after the ECDSA signature OID */
    { "test-ca2.crt", 0, 1 }
};

static const Case dirs[] = {
    { "dir1", 0, 1 },
    { "dir2", 0, 2 },
    { "dir3", 1, 2 },
    /* Not in Mbed TLS's cases */
    { "missing-dir", MBEDTLS_ERR_X509_FILE_IO_ERROR, 0 }
};

/* PEM blocks in one NUL terminated buffer, for ParseBundle(). G is
 * server5.crt, B does not decode and D is not a certificate. */
static const Case bundles[] = {
    { "GBG", 1, 2 },
    { "DG", 1, 1 },
    { "BD", ERR, 0 }
};

static char pem[1024];

/* -1 for an empty node, apart from the first when no certificate parsed */
static int CountCerts(const mbedtls_x509_crt* chain)
{
    const mbedtls_x509_crt* cur;
    int certs = 0;
    int nodes = 0;

    for (cur = chain; cur != NULL; cur = cur->next) {
        nodes++;
        if (cur->raw.p != NULL) {
            certs++;
        }
    }
    return (certs == nodes || (certs == 0 && nodes == 1)) ? certs : -1;
}

/* Returns 1 when parse of path does not give the result of c */
static int Check(Parse parse, const char* path, const Case* c)
{
    mbedtls_x509_crt crt;
    int certs;
    int ret;

    mbedtls_x509_crt_init(&crt);
    ret = parse(&crt, path);
    certs = CountCerts(&crt);
    mbedtls_x509_crt_free(&crt);
    if ((c->ret == ERR ? ret < 0 : ret == c->ret) && certs == c->certs) {
        printf("PASS: %s\n", c->file);
        return 0;
    }
    printf("FAIL: %s: returned %d with %d certificates, expected %d with %d\n",
        c->file, ret, certs, c->ret, c->certs);
    return 1;
}

/* Returns 1 when ret is not expected */
static int Expect(const char* what, int ret, int expected)
{
    if (ret == expected) {
        printf("PASS: %s\n", what);
        return 0;
    }
    printf("FAIL: %s: returned %d, expected %d\n", what, ret, expected);
    return 1;
}

/* Each case, also parsed into all, which only grows. Returns the number that
 * failed. */
static int CheckAll(Parse parse, const Case* c, size_t n,
    mbedtls_x509_crt* all, int* total)
{
    size_t i;
    int fails = 0;

    for (i = 0; i < n; i++) {
        fails += Check(parse, c[i].file, &c[i]);
        (void)parse(all, c[i].file);
        *total += c[i].certs;
    }
    return fails;
}

/* Reads file into pem */
static int LoadPem(const char* file)
{
    FILE* f = fopen(file, "rb");
    size_t n = 0;

    if (f != NULL) {
        n = fread(pem, 1, sizeof(pem) - 1, f);
        (void)fclose(f);
    }
    pem[n] = '\0';
    return n > 0 && n < sizeof(pem) - 1;
}

/* Parses the PEM blocks named in parts, as in bundles */
static int ParseBundle(mbedtls_x509_crt* chain, const char* parts)
{
    static const char notBase64[] =
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    static const char notCert[] =
        "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
    char buf[3 * sizeof(pem)];
    const char* block;

    buf[0] = '\0';
    for (; *parts != '\0'; parts++) {
        block = (*parts == 'G') ? pem : (*parts == 'B') ? notBase64 : notCert;
        if (strlen(buf) + strlen(block) >= sizeof(buf)) {
            return ERR;
        }
        strcat(buf, block);
    }
    return mbedtls_x509_crt_parse(chain, (const unsigned char*)buf,
        strlen(buf) + 1);
}

/* Writes the DER of the certificate in file to path */
static int WriteDer(const char* file, const char* path)
{
    mbedtls_x509_crt crt;
    FILE* f;
    int ok;

    mbedtls_x509_crt_init(&crt);
    f = fopen(path, "wb");
    ok = f != NULL && mbedtls_x509_crt_parse_file(&crt, file) == 0 &&
        fwrite(crt.raw.p, 1, crt.raw.len, f) == crt.raw.len;
    if (f != NULL && fclose(f) != 0) {
        ok = 0;
    }
    mbedtls_x509_crt_free(&crt);
    return ok;
}

/* Bad arguments, empty data, PEM without the NUL that Mbed TLS needs, and a
 * path too long with each entry name. Needs pem loaded. */
static int BadInput(void)
{
    static const unsigned char nul[1] = { 0 };
    char longPath[MBEDTLS_X509_MAX_FILE_PATH_LEN];
    mbedtls_x509_crt crt;
    size_t i;
    int fails;

    /* "./././." */
    longPath[0] = '.';
    for (i = 1; i + 2 < sizeof(longPath); i += 2) {
        longPath[i] = '/';
        longPath[i + 1] = '.';
    }
    longPath[i] = '\0';

    mbedtls_x509_crt_init(&crt);
    fails = Expect("parse, NULL chain",
        mbedtls_x509_crt_parse(NULL, nul, sizeof(nul)),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse, NULL buf", mbedtls_x509_crt_parse(&crt, NULL, 0),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse, empty", mbedtls_x509_crt_parse(&crt, nul, 0),
        MBEDTLS_ERR_X509_INVALID_FORMAT);
    fails += Expect("parse, NUL only",
        mbedtls_x509_crt_parse(&crt, nul, sizeof(nul)),
        MBEDTLS_ERR_X509_INVALID_FORMAT);
    fails += Expect("parse, PEM without a NUL",
        mbedtls_x509_crt_parse(&crt, (const unsigned char*)pem, strlen(pem)),
        MBEDTLS_ERR_X509_INVALID_FORMAT);
    fails += Expect("parse_der, NULL chain",
        mbedtls_x509_crt_parse_der(NULL, nul, sizeof(nul)),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse_der, NULL buf",
        mbedtls_x509_crt_parse_der(&crt, NULL, 0),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse_der, empty",
        mbedtls_x509_crt_parse_der(&crt, nul, 0),
        MBEDTLS_ERR_X509_INVALID_FORMAT);
    fails += Expect("parse_file, NULL chain",
        mbedtls_x509_crt_parse_file(NULL, "test-ca.der"),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse_file, NULL path",
        mbedtls_x509_crt_parse_file(&crt, NULL),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse_path, NULL chain",
        mbedtls_x509_crt_parse_path(NULL, "dir1"),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse_path, NULL path",
        mbedtls_x509_crt_parse_path(&crt, NULL),
        MBEDTLS_ERR_X509_BAD_INPUT_DATA);
    fails += Expect("parse_path, long names",
        mbedtls_x509_crt_parse_path(&crt, longPath),
        MBEDTLS_ERR_X509_BUFFER_TOO_SMALL);
    fails += Expect("no certificate after bad input", CountCerts(&crt), 0);
    mbedtls_x509_crt_free(&crt);
    return fails;
}

/* A directory made here: empty, then with a dangling symlink, then also with
 * a subdirectory that has a certificate. As in Mbed TLS, the symlink is
 * skipped and a subdirectory is not read. */
static int TempDirs(void)
{
    static const Case empty = { "empty directory", 0, 0 };
    static const Case dangling = { "dangling symlink", 0, 0 };
    static const Case subdir = { "subdirectory", 0, 0 };
    char dir[] = "/tmp/x509_crt_test.XXXXXX";
    char sym[sizeof(dir) + 4];
    char sub[sizeof(dir) + 4];
    char der[sizeof(sub) + 7];
    int fails;

    if (mkdtemp(dir) == NULL) {
        printf("FAIL: mkdtemp\n");
        return 1;
    }
    (void)snprintf(sym, sizeof(sym), "%s/sym", dir);
    (void)snprintf(sub, sizeof(sub), "%s/sub", dir);
    (void)snprintf(der, sizeof(der), "%s/ca.der", sub);
    fails = Check(mbedtls_x509_crt_parse_path, dir, &empty);
    if (symlink("missing.crt", sym) == 0) {
        fails += Check(mbedtls_x509_crt_parse_path, dir, &dangling);
    }
    else {
        printf("FAIL: making %s\n", sym);
        fails++;
    }
    if (mkdir(sub, 0700) == 0 && WriteDer("test-ca2.crt", der)) {
        fails += Check(mbedtls_x509_crt_parse_path, dir, &subdir);
    }
    else {
        printf("FAIL: making %s\n", der);
        fails++;
    }
    (void)remove(der);
    (void)rmdir(sub);
    (void)remove(sym);
    (void)rmdir(dir);
    return fails;
}

static void* NoMalloc(size_t size)
{
    (void)size;
    return NULL;
}

/* Each allocation fails */
static int NoMemory(void)
{
    static const Case file = { "parse_file, no memory",
        MBEDTLS_ERR_X509_ALLOC_FAILED, 0 };
    static const Case bundle = { "parse, no memory",
        MBEDTLS_ERR_X509_ALLOC_FAILED, 0 };
    wolfSSL_Malloc_cb mf;
    wolfSSL_Free_cb ff;
    wolfSSL_Realloc_cb rf;
    int fails;

    (void)wolfSSL_GetAllocators(&mf, &ff, &rf);
    (void)wolfSSL_SetAllocators(NoMalloc, ff, rf);
    fails = Check(mbedtls_x509_crt_parse_file, "test-ca.der", &file);
    fails += Check(ParseBundle, "G", &bundle);
    (void)wolfSSL_SetAllocators(mf, ff, rf);
    return fails;
}

typedef int (*ParseBuf)(mbedtls_x509_crt* chain, const unsigned char* buf,
    size_t buflen);

/* A DER buffer, as an embedded CA usually is. Mbed TLS ignores data after
 * the certificate, such as a NUL. */
static int ParseDerBuffer(void)
{
    static const struct {
        const char* what;
        ParseBuf parse;
        size_t extra;
    } parses[] = {
        { "parse, DER", mbedtls_x509_crt_parse, 0 },
        { "parse, DER and a NUL", mbedtls_x509_crt_parse, 1 },
        { "parse_der, DER and a NUL", mbedtls_x509_crt_parse_der, 1 }
    };
    mbedtls_x509_crt ca;
    mbedtls_x509_crt crt;
    unsigned char buf[2048];
    size_t len = 0;
    size_t i;
    int fails = 0;
    int ret;

    mbedtls_x509_crt_init(&ca);
    if (mbedtls_x509_crt_parse_file(&ca, "test-ca.der") == 0 &&
            ca.raw.len < sizeof(buf)) {
        len = ca.raw.len;
        memcpy(buf, ca.raw.p, len);
        buf[len] = 0;
    }
    mbedtls_x509_crt_free(&ca);
    if (len == 0) {
        printf("FAIL: reading test-ca.der\n");
        return 1;
    }

    for (i = 0; i < sizeof(parses) / sizeof(parses[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        ret = parses[i].parse(&crt, buf, len + parses[i].extra);
        if (ret == 0 && (CountCerts(&crt) != 1 || crt.raw.len != len)) {
            ret = ERR;
        }
        mbedtls_x509_crt_free(&crt);
        fails += Expect(parses[i].what, ret, 0);
    }
    return fails;
}

/* Parts of test certificates, with server5.crt's key and a bad signature */
#define BUILT_START "A003020102020101300A06082A8648CE3D040302" \
    "300D310B300906035504030C024341"
#define BUILT_KEY "3059301306072A8648CE3D020106082A8648CE3D030107034200" \
    "0437CC56D976091E5A723EC7592DFF206EEE7CF9069174D0AD14B5F76822596292" \
    "4EE500D82311FFEA2FD2345D5D16BD8A88C26B770D55CD8A2A0EFA01C8B4EDFF"
#define BUILT_SIG "300A06082A8648CE3D0403020309003006020101020101"

/* C=NL + O=PolarSSL, CN=Server, and UTCTime and GeneralizedTime without Z.
 * tag is the type of O's value. */
#define MVRDN(tag) "3081E93081CF" BUILT_START \
    "301E170C313930323130313434343036180E3230323930323130313434343036" \
    "302F311C3009060355040613024E4C300F060355040A" tag \
    "08506F6C617253534C310F300D06035504030C06536572766572" BUILT_KEY BUILT_SIG
static const char mvrdnHex[] = MVRDN("0C");

/* Up to the extensions: CN=Server, valid from the UTCTime from, in hex, to
 * 2029 */
#define BUILT_TBS(from) BUILT_START "301E170D" from \
    "170D3239303231303134343430365A" \
    "3011310F300D06035504030C06536572766572" BUILT_KEY
/* 190210144406Z */
#define BUILT_FROM "3139303231303134343430365A"
/* BUILT_TBS(from) and no extensions */
#define DATED(from) "3081CB3081B1" BUILT_TBS(from) BUILT_SIG

static int ParseHex(mbedtls_x509_crt* crt, const char* hex)
{
    unsigned char der[512];
    unsigned int b;
    size_t n = 0;

    while (n < sizeof(der) && sscanf(hex + 2 * n, "%2x", &b) == 1) {
        der[n++] = (unsigned char)b;
    }
    return mbedtls_x509_crt_parse_der(crt, der, n);
}

/* From Mbed TLS's x509_cert_info and mbedtls_x509_dn_gets cases */
typedef struct {
    const char* file;   /* or a name, with hex */
    int version;
    const char* serial;
    const char* issuer;
    const char* subject;
    const char* validity;
    int ca;     /* mbedtls_x509_crt_get_ca_istrue() */
    const char* hex;    /* DER, in place of the file */
} Fields;

#define NO_BC MBEDTLS_ERR_X509_INVALID_EXTENSIONS
#define TEST_CA "C=NL, O=PolarSSL, CN=PolarSSL Test CA"
#define SERVER1_DATES "2019-02-10 14:44:06 2029-02-10 14:44:06"
#define JP_NAME "C=JP, ST=Tokyo, " \
    "O=\\C3\\A3\\C2\\83\\C2\\86\\C3\\A3\\C2\\82\\C2\\B9\\C3\\A3\\C2\\83" \
    "\\C2\\88 Ltd, " \
    "CN=\\C3\\A3\\C2\\83\\C2\\86\\C3\\A3\\C2\\82\\C2\\B9\\C3\\A3\\C2\\83" \
    "\\C2\\88 CA"

static const Fields fields[] = {
    { IN "server1.crt", 3, "01", TEST_CA,
        "C=NL, O=PolarSSL, CN=PolarSSL Server 1", SERVER1_DATES, 0 },
    { IN "test-ca.crt", 3, "03", TEST_CA, TEST_CA,
        "2019-02-10 14:44:00 2029-02-10 14:44:00", 1 },
    { IN "test-ca-any_policy.crt", 3, "00", TEST_CA, TEST_CA,
        "2019-03-21 16:40:59 2029-03-21 16:40:59", 1 },
    { "server1-v1.crt", 1, "53:A2:B6:C7:04:CD:4D:8E:BC:80:0B:C1",
        "CN=PolarSSL Test CA v1, OU=testing, O=PolarSSL, C=NL",
        "CN=server1/int-ca-v1, OU=testing, O=PolarSSL, C=NL", SERVER1_DATES,
        NO_BC },
    { IN "bitstring-in-dn.pem", 3, "02",
        "CN=Test CA 01, ST=Ecnivorp, C=XX, emailAddress=tca@example.com, "
        "O=Test CA Authority",
        "C=XX, O=tca, ST=Ecnivorp, OU=TCA, CN=Client, "
        "emailAddress=client@example.com, serialNumber=7101012255, "
        "uniqueIdentifier=#030B0037313031303132323535",
        "2015-03-11 12:06:51 2025-03-08 12:06:51", 0 },
    { IN "non-ascii-string-in-issuer.crt", 3,
        "05:E6:53:E7:1B:74:F0:B5:D3:84:6D:0C:6D:DC:FA:3F:A4:5A:2B:E0",
        JP_NAME, JP_NAME, "2020-05-20 16:17:23 2020-06-19 16:17:23", 1 },
    { "server1.commas.crt", 3, "01", TEST_CA,
        "C=NL, O=PolarSSL\\, Commas, CN=PolarSSL Server 1", SERVER1_DATES,
        0 },
    { "server1.hashsymbol.crt", 3, "01", TEST_CA,
        "C=NL, O=\\#PolarSSL, CN=PolarSSL Server 1", SERVER1_DATES, 0 },
    { "server1.spaces.crt", 3, "01", TEST_CA,
        "C=NL, O=\\ PolarSSL\\ , CN=PolarSSL Server 1", SERVER1_DATES, 0 },
    { "server1.asciichars.crt", 3, "01", TEST_CA,
        "C=NL, O=\\E6\\9E\\81\\E5\\9C\\B0SSL, CN=PolarSSL Server 1",
        SERVER1_DATES, 0 },
    { "multi-valued RDN, dates without Z", 3, "01", "CN=CA",
        "C=NL + O=PolarSSL, CN=Server",
        "2019-02-10 14:44:06 2029-02-10 14:44:06", NO_BC, mvrdnHex }
};

/* Returns 1 when got is not want */
static int ExpectStr(const char* what, const char* got, const char* want)
{
    if (strcmp(got, want) == 0) {
        return 0;
    }
    printf("FAIL: %s: \"%s\", expected \"%s\"\n", what, got, want);
    return 1;
}

static int CheckFields(const Fields* f)
{
    mbedtls_x509_crt crt;
    char buf[512];
    size_t hdr;
    int fails = 0;
    int ret;

    mbedtls_x509_crt_init(&crt);
    ret = (f->hex != NULL) ? ParseHex(&crt, f->hex) :
        mbedtls_x509_crt_parse_file(&crt, f->file);
    if (ret != 0) {
        printf("FAIL: %s: parse returned %d\n", f->file, ret);
        return 1;
    }
    fails += Expect("version", crt.version, f->version);
    if (mbedtls_x509_serial_gets(buf, sizeof(buf), &crt.serial) < 0) {
        buf[0] = '\0';
    }
    fails += ExpectStr("serial", buf, f->serial);
    if (mbedtls_x509_dn_gets(buf, sizeof(buf), &crt.issuer) < 0) {
        buf[0] = '\0';
    }
    fails += ExpectStr("issuer", buf, f->issuer);
    if (mbedtls_x509_dn_gets(buf, sizeof(buf), &crt.subject) < 0) {
        buf[0] = '\0';
    }
    fails += ExpectStr("subject", buf, f->subject);
    (void)snprintf(buf, sizeof(buf),
        "%04d-%02d-%02d %02d:%02d:%02d %04d-%02d-%02d %02d:%02d:%02d",
        crt.valid_from.year, crt.valid_from.mon, crt.valid_from.day,
        crt.valid_from.hour, crt.valid_from.min, crt.valid_from.sec,
        crt.valid_to.year, crt.valid_to.mon, crt.valid_to.day,
        crt.valid_to.hour, crt.valid_to.min, crt.valid_to.sec);
    fails += ExpectStr("validity", buf, f->validity);
    fails += Expect("ca_istrue", mbedtls_x509_crt_get_ca_istrue(&crt), f->ca);
    /* The raw spans start with their own header */
    hdr = (crt.raw.p[1] & 0x80) ? 2 + (crt.raw.p[1] & 0x7F) : 2;
    if (crt.tbs.p != crt.raw.p + hdr || crt.issuer_raw.p[0] != 0x30 ||
            crt.subject_raw.p[0] != 0x30 || crt.pk_raw.p[0] != 0x30) {
        printf("FAIL: %s: raw spans\n", f->file);
        fails++;
    }
    mbedtls_x509_crt_free(&crt);
    printf("%s: %s fields\n", fails == 0 ? "PASS" : "FAIL", f->file);
    return fails;
}

/* From Mbed TLS's x509_check_key_usage and _extended_key_usage cases */
static int Usage(void)
{
    static const struct {
        const char* file;
        unsigned int usage;
        int ret;
    } ku[] = {
        { "server1.crt", MBEDTLS_X509_KU_KEY_CERT_SIGN, 0 },
        { "server1.key_usage.crt", 0, 0 },
        { "server1.key_usage.crt", MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
            MBEDTLS_X509_KU_KEY_ENCIPHERMENT, 0 },
        { "server1.key_usage.crt", MBEDTLS_X509_KU_KEY_CERT_SIGN,
            MBEDTLS_ERR_X509_BAD_INPUT_DATA },
        { "server1.key_usage.crt", MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
            MBEDTLS_X509_KU_KEY_ENCIPHERMENT |
            MBEDTLS_X509_KU_DECIPHER_ONLY, 0 },
        { "keyUsage.decipherOnly.crt", MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
            MBEDTLS_X509_KU_KEY_ENCIPHERMENT,
            MBEDTLS_ERR_X509_BAD_INPUT_DATA },
        { "keyUsage.decipherOnly.crt", MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
            MBEDTLS_X509_KU_KEY_ENCIPHERMENT |
            MBEDTLS_X509_KU_DECIPHER_ONLY, 0 }
    };
    static const struct {
        const char* file;
        const char* oid;
        int ret;
    } eku[] = {
        { "server5.crt", "\x2b\x06\x01\x05\x05\x07\x03\x01", 0 },
        { "server5.eku-cli.crt", "\x2b\x06\x01\x05\x05\x07\x03\x01",
            MBEDTLS_ERR_X509_BAD_INPUT_DATA },
        { "server5.eku-srv_cli.crt", "\x2b\x06\x01\x05\x05\x07\x03\x02", 0 },
        { "server5.eku-srv_cli.crt", "\x2b\x06\x01\x05\x05\x07\x03\x03",
            MBEDTLS_ERR_X509_BAD_INPUT_DATA },
        { "server5.eku-cs_any.crt", "\x2b\x06\x01\x05\x05\x07\x03\xff", 0 }
    };
    mbedtls_x509_crt crt;
    size_t i;
    int fails = 0;
    int ret;

    for (i = 0; i < sizeof(ku) / sizeof(ku[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        ret = mbedtls_x509_crt_parse_file(&crt, ku[i].file);
        if (ret == 0) {
            ret = mbedtls_x509_crt_check_key_usage(&crt, ku[i].usage);
        }
        mbedtls_x509_crt_free(&crt);
        fails += Expect(ku[i].file, ret, ku[i].ret);
    }
    for (i = 0; i < sizeof(eku) / sizeof(eku[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        ret = mbedtls_x509_crt_parse_file(&crt, eku[i].file);
        if (ret == 0) {
            ret = mbedtls_x509_crt_check_extended_key_usage(&crt,
                eku[i].oid, strlen(eku[i].oid));
        }
        mbedtls_x509_crt_free(&crt);
        fails += Expect(eku[i].file, ret, eku[i].ret);
    }
    return fails;
}

/* BUILT_TBS with the extensions exts, in hex, up to 48 bytes */
static int ParseExts(mbedtls_x509_crt* crt, const char* exts)
{
    static const char tbs[] = BUILT_TBS(BUILT_FROM);
    char hex[600];
    unsigned int extLen = (unsigned int)strlen(exts) / 2;
    unsigned int tbsLen = (unsigned int)(sizeof(tbs) - 1) / 2 + 4 + extLen;

    (void)snprintf(hex, sizeof(hex), "3081%02X3081%02X%sA3%02X30%02X%s%s",
        3 + tbsLen + (unsigned int)(sizeof(BUILT_SIG) - 1) / 2, tbsLen, tbs,
        2 + extLen, extLen, exts, BUILT_SIG);
    return ParseHex(crt, hex);
}

/* Key identifiers, subject alternative names and policies */
static int Extensions(void)
{
    static const unsigned char keyId[] = {
        0xA5, 0x05, 0xE8, 0x64, 0xB8, 0xDC, 0xDF, 0x60, 0x0F, 0x50,
        0x12, 0x4D, 0x60, 0xA8, 0x64, 0xAF, 0x4D, 0x8B, 0x43, 0x93
    };
    /* 1.2.3.4, then anyPolicy */
    static const mbedtls_x509_buf policies[] = {
        { MBEDTLS_ASN1_OID, 3, (unsigned char*)"\x2A\x03\x04" },
        { MBEDTLS_ASN1_OID, 4, (unsigned char*)"\x55\x1D\x20\x00" }
    };
    /* Extensions Mbed TLS rejects */
    static const struct {
        const char* what;
        const char* exts;
        int ret;
        int alt;    /* also accepted, when wolfCrypt refuses it first */
    } bad[] = {
        { "policies twice, the second shorter",
            "30170603551D200410300E300506032A0304300506032A0305"
            "30100603551D2004093007300506032A0306",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "policies twice, the second longer",
            "30100603551D2004093007300506032A0304"
            "30170603551D200410300E300506032A0305300506032A0306",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "empty extended key usage", "30090603551D2504023000",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "empty policies", "30090603551D2004023000",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "authority cert issuer twice",
            "30190603551D2304123010A106820161820162A106820163820164",
            ASN_ORIGINAL_RET(MBEDTLS_ERR_X509_INVALID_EXTENSIONS) },
        { "subject alt name not context specific",
            "300C0603551D11040530030C0161",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "hardware module name with data after the serial number",
            "30220603551D11041B3019A01706082B06010505070804A00B3009"
            "06012A040131020100",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "empty directoryName", "300D0603551D1104063004A4023000",
            MBEDTLS_ERR_X509_INVALID_NAME },
        { "directoryName with an RDN not a SET",
            "30190603551D1104123010A40E300C300A300806035504030C0161",
            MBEDTLS_ERR_X509_INVALID_NAME },
        { "directoryName with data after an attribute value",
            "301B0603551D1104143012A410300E310C300A06035504030C01610500",
            MBEDTLS_ERR_X509_INVALID_NAME },
        { "otherName with a truncated OID",
            "300E0603551D1104073005A00306052B",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
            MBEDTLS_ERR_X509_INVALID_FORMAT },
        { "5 byte iPAddress", "30100603551D110409300787050102030405",
            MBEDTLS_ERR_X509_INVALID_FORMAT },
        { "authority cert issuer not context specific",
            "30110603551D23040A3008A1030C0161820101",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "authority cert issuer with an empty directoryName",
            "30120603551D23040B3009A104A4023000820101",
            MBEDTLS_ERR_X509_INVALID_NAME },
        { "authority cert issuer with a 5 byte iPAddress",
            "30150603551D23040E300CA10787050102030405820101",
            MBEDTLS_ERR_X509_BAD_INPUT_DATA },
        { "authority cert issuer with a truncated otherName OID",
            "30130603551D23040C300AA105A00306052B820101",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "policies in a SET", "30100603551D2004093107300506032A0304",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "data after the policies",
            "30120603551D20040B3007300506032A03040500",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "data after the authority key identifier",
            "300E0603551D23040730038001010500",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS },
        { "data after the key usage", "30100603551D0F0101FF0406030207800500",
            MBEDTLS_ERR_X509_INVALID_EXTENSIONS }
    };
    mbedtls_x509_crt crt;
    const mbedtls_x509_sequence* cur;
    const mbedtls_x509_authority* akid = &crt.authority_key_id;
    size_t i;
    int fails = 0;
    int n = 0;
    int ret;

    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_file(&crt,
            "authorityKeyId_subjectKeyId.crt.der") != 0 ||
            crt.subject_key_id.len != sizeof(keyId) ||
            memcmp(crt.subject_key_id.p, keyId, sizeof(keyId)) != 0 ||
            akid->keyIdentifier.len != sizeof(keyId) ||
            memcmp(akid->keyIdentifier.p, keyId, sizeof(keyId)) != 0 ||
            akid->authorityCertIssuer.buf.tag != 0xA4 ||
            akid->authorityCertSerialNumber.len != 20 ||
            (crt.MBEDTLS_PRIVATE(ext_types) &
            MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER) == 0) {
        printf("FAIL: key identifiers\n");
        fails++;
    }
    mbedtls_x509_crt_free(&crt);

    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_file(&crt, IN "multiple_san.crt") == 0) {
        for (cur = &crt.subject_alt_names; cur != NULL; cur = cur->next) {
            n++;
        }
    }
    if (!mbedtls_x509_crt_has_ext_type(&crt,
            MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) ||
            mbedtls_x509_crt_has_ext_type(&crt, MBEDTLS_X509_EXT_KEY_USAGE)) {
        n = -1;
    }
    mbedtls_x509_crt_free(&crt);
    fails += Expect("subject alt names", n, 4);

    cur = NULL;
    n = 0;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_file(&crt, IN "test-ca-multi_policy.crt") == 0) {
        cur = &crt.certificate_policies;
    }
    for (; cur != NULL && n < 2; cur = cur->next, n++) {
        if (cur->buf.tag != policies[n].tag ||
                cur->buf.len != policies[n].len ||
                memcmp(cur->buf.p, policies[n].p, policies[n].len) != 0) {
            break;
        }
    }
    if (cur != NULL || !mbedtls_x509_crt_has_ext_type(&crt,
            MBEDTLS_X509_EXT_CERTIFICATE_POLICIES)) {
        n = -1;
    }
    mbedtls_x509_crt_free(&crt);
    fails += Expect("certificate policies", n, 2);

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        ret = ParseExts(&crt, bad[i].exts);
        if (bad[i].alt != 0 && ret == bad[i].alt) {
            ret = bad[i].ret;
        }
        fails += Expect(bad[i].what, ret, bad[i].ret);
        mbedtls_x509_crt_free(&crt);
    }
    return fails;
}

/* A multi-valued RDN, C + O, then CN, and short buffers */
static int Names(void)
{
    static unsigned char serial[33];
    mbedtls_x509_buf sn = { MBEDTLS_ASN1_INTEGER, sizeof(serial), serial };
    mbedtls_x509_crt crt;
    mbedtls_x509_name empty;
    mbedtls_x509_name* o;
    mbedtls_x509_name* cn;
    char buf[128];
    int fails = 0;
    int i;

    mbedtls_x509_crt_init(&crt);
    if (ParseHex(&crt, mvrdnHex) != 0 || crt.subject.next == NULL ||
            crt.subject.next->next == NULL) {
        printf("FAIL: multi-valued RDN: parse\n");
        fails++;
    }
    else {
        o = crt.subject.next;
        cn = o->next;
        fails += Expect("C, merged", crt.subject.MBEDTLS_PRIVATE(next_merged),
            1);
        fails += Expect("O, not merged", o->MBEDTLS_PRIVATE(next_merged), 0);
        fails += Expect("dn_get_next",
            mbedtls_x509_dn_get_next(&crt.subject) == cn, 1);
        fails += Expect("dn_gets, short buffer",
            mbedtls_x509_dn_gets(buf, 10, &crt.subject),
            MBEDTLS_ERR_X509_BUFFER_TOO_SMALL);
        o->val.tag = MBEDTLS_ASN1_OCTET_STRING;
        cn->oid.len = 2;
        if (mbedtls_x509_dn_gets(buf, sizeof(buf), &crt.subject) < 0) {
            buf[0] = '\0';
        }
        fails += ExpectStr("hex value, numeric OID", buf,
            "C=NL + O=#0408506F6C617253534C, 2.5.4=#0C06536572766572");
    }
    mbedtls_x509_crt_free(&crt);

    /* As Mbed TLS, a value is a string or a BIT STRING */
    mbedtls_x509_crt_init(&crt);
    fails += Expect("T61String value", ParseHex(&crt, MVRDN("14")), 0);
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_init(&crt);
    fails += Expect("OCTET STRING value", ParseHex(&crt, MVRDN("04")),
        ASN_ORIGINAL_RET(MBEDTLS_ERR_X509_INVALID_NAME));
    mbedtls_x509_crt_free(&crt);

    /* As Mbed TLS, over 32 bytes shows 28 and "....". Zero skipped. */
    for (i = 0; i < (int)sizeof(serial); i++) {
        serial[i] = (unsigned char)i;
    }
    if (mbedtls_x509_serial_gets(buf, sizeof(buf), &sn) < 0) {
        buf[0] = '\0';
    }
    fails += ExpectStr("long serial", buf,
        "01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:"
        "17:18:19:1A:1B....");
    fails += Expect("serial, short buffer",
        mbedtls_x509_serial_gets(buf, 4, &sn),
        MBEDTLS_ERR_X509_BUFFER_TOO_SMALL);

    memset(&empty, 0, sizeof(empty));
    strcpy(buf, "old");
    fails += Expect("empty name",
        mbedtls_x509_dn_gets(buf, sizeof(buf), &empty), 0);
    fails += ExpectStr("empty name", buf, "");
    sn.len = 0;
    strcpy(buf, "old");
    fails += Expect("empty serial",
        mbedtls_x509_serial_gets(buf, sizeof(buf), &sn), 0);
    fails += ExpectStr("empty serial", buf, "");
    return fails;
}

/* From Mbed TLS's x509_date_is_valid() */
static int Dates(void)
{
    static const struct {
        const char* from;
        const char* hex;
        int ret;
    } dates[] = {
        { "191310144406Z", DATED("3139313331303134343430365A"),
            MBEDTLS_ERR_X509_INVALID_DATE },
        { "190229144406Z", DATED("3139303232393134343430365A"),
            MBEDTLS_ERR_X509_INVALID_DATE },
        { "200229144406Z", DATED("3230303232393134343430365A"), 0 },
        { "190210244406Z", DATED("3139303231303234343430365A"),
            MBEDTLS_ERR_X509_INVALID_DATE }
    };
    mbedtls_x509_crt crt;
    size_t i;
    int fails = 0;

    for (i = 0; i < sizeof(dates) / sizeof(dates[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        fails += Expect(dates[i].from, ParseHex(&crt, dates[i].hex),
            dates[i].ret);
        mbedtls_x509_crt_free(&crt);
    }
    return fails;
}

#ifndef NO_ASN_TIME
/* What is_past and is_future return when the time is past or future */
#define CLOCK_TRUE 1

/* A clock that fails, as time() can */
static time_t NoClock(time_t* t)
{
    if (t != NULL) {
        *t = (time_t)-1;
    }
    return (time_t)-1;
}
#else
/* Without a clock, they return 0 */
#define CLOCK_TRUE 0
#endif /* !NO_ASN_TIME */

/* From Mbed TLS's mbedtls_x509_time_is_past and _is_future cases */
static int Times(void)
{
#ifndef NO_ASN_TIME
    const mbedtls_x509_time y1950 = { 1950, 1, 1, 0, 0, 0 };
    const mbedtls_x509_time y2049 = { 2049, 12, 31, 23, 59, 59 };
#endif /* !NO_ASN_TIME */
    mbedtls_x509_crt crt;
    int fails = 0;

    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_file(&crt, "server5-future.crt") == 0) {
        fails += Expect("future, valid_from",
            mbedtls_x509_time_is_future(&crt.valid_from), CLOCK_TRUE);
        fails += Expect("past, valid_to",
            mbedtls_x509_time_is_past(&crt.valid_to), 0);
    }
    else {
        fails++;
    }
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_file(&crt, "server5.crt") == 0) {
        fails += Expect("past, valid_from",
            mbedtls_x509_time_is_past(&crt.valid_from), CLOCK_TRUE);
        fails += Expect("future, valid_from",
            mbedtls_x509_time_is_future(&crt.valid_from), 0);
    }
    else {
        fails++;
    }
    mbedtls_x509_crt_free(&crt);
#ifndef NO_ASN_TIME
    /* As Mbed TLS, both are true when the clock fails */
    (void)wc_SetTimeCb(NoClock);
    fails += Expect("past, clock failed",
        mbedtls_x509_time_is_past(&y2049), 1);
    fails += Expect("future, clock failed",
        mbedtls_x509_time_is_future(&y1950), 1);
    (void)wc_SetTimeCb(NULL);
#endif /* !NO_ASN_TIME */
    return fails;
}

#if defined(MBEDTLS_THREADING_C) && !defined(NO_ASN_TIME)
#define RACE_LOOPS 100000

/* gmtime() of 1970 over and over, against the clock reads */
static void* GmtimeLoop(void* arg)
{
    const time_t epoch = 0;
    int i;

    (void)arg;
    for (i = 0; i < RACE_LOOPS; i++) {
        (void)gmtime(&epoch);
    }
    return NULL;
}

static int TimeThreads(void)
{
    const mbedtls_x509_time y2000 = { 2000, 1, 1, 0, 0, 0 };
    pthread_t thread;
    int past = 1;
    int i;

    if (pthread_create(&thread, NULL, GmtimeLoop, NULL) != 0) {
        printf("FAIL: pthread_create\n");
        return 1;
    }
    for (i = 0; i < RACE_LOOPS && past == 1; i++) {
        past = mbedtls_x509_time_is_past(&y2000);
    }
    (void)pthread_join(thread, NULL);
    return Expect("past, with gmtime() in another thread", past, 1);
}
#endif /* MBEDTLS_THREADING_C && !NO_ASN_TIME */

#if !defined(MBEDTLS_X509_REMOVE_INFO)
/* Mbed TLS's test data, from framework/data_files */
#define X509PARSE_DATA "../../tests/suites/test_suite_x509parse.data"
#define CERT_INFO "x509_cert_info:\"../framework/data_files/"
#define INFO_PREFIX "  | "

/* Removes the .data escapes from s, in place */
static void Unescape(char* s)
{
    char* out = s;

    for (; *s != '\0'; s++) {
        if (*s == '\\' && s[1] != '\0') {
            s++;
            *out++ = (*s == 'n') ? '\n' : *s;
        }
        else {
            *out++ = *s;
        }
    }
    *out = '\0';
}

/* want, with INFO_PREFIX starting each line but the empty last one */
static void Prefixed(char* out, size_t size, const char* want)
{
    size_t j = 0;
    size_t i;

    for (i = 0; want[i] != '\0' && j + sizeof(INFO_PREFIX) < size; i++) {
        if (i == 0 || want[i - 1] == '\n') {
            memcpy(out + j, INFO_PREFIX, sizeof(INFO_PREFIX) - 1);
            j += sizeof(INFO_PREFIX) - 1;
        }
        out[j++] = want[i];
    }
    out[j] = '\0';
}

/* Each size up to the text's fails, then the text fits */
static int InfoSizes(const mbedtls_x509_crt* crt, const char* file,
    size_t len)
{
    char* buf;
    size_t size;
    int ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;

    for (size = 1; size <= len + 1 &&
            ret == MBEDTLS_ERR_X509_BUFFER_TOO_SMALL; size++) {
        buf = (char*)malloc(size);
        if (buf == NULL) {
            printf("FAIL: %s: malloc\n", file);
            return 1;
        }
        ret = mbedtls_x509_crt_info(buf, size, "", crt);
        free(buf);
    }
    if (size != len + 2 || ret != (int)len) {
        printf("FAIL: %s: size %zu returned %d\n", file, size - 1, ret);
        return 1;
    }
    return 0;
}

/* One x509_cert_info case, with no prefix, then a prefix and each size */
static int CertInfoCase(char* line)
{
    char buf[2000];
    char want[2400];
    char* file = line + sizeof(CERT_INFO) - 1;
    char* text = strstr(file, "\":\"");
    char* end = strrchr(line, '"');
    mbedtls_x509_crt crt;
    int fails = 0;
    int ret;

    if (text == NULL || end < text + 2) {
        printf("FAIL: cannot read %s", line);
        return 1;
    }
    *text = '\0';
    text += 3;
    *end = '\0';
    Unescape(text);

    mbedtls_x509_crt_init(&crt);
    ret = mbedtls_x509_crt_parse_file(&crt, file);
    if (ret == 0) {
        ret = mbedtls_x509_crt_info(buf, sizeof(buf), "", &crt);
    }
    else if (ret > 0) {
        /* Some of the file's certificates did not parse */
        ret = ERR;
    }
    if (ret < 0) {
        printf("FAIL: %s: returned %d\n", file, ret);
        fails++;
    }
    else {
        fails += ExpectStr(file, buf, text);
        fails += Expect(file, ret, (int)strlen(text));
        Prefixed(want, sizeof(want), text);
        ret = mbedtls_x509_crt_info(buf, sizeof(buf), INFO_PREFIX, &crt);
        if (ret < 0) {
            buf[0] = '\0';
        }
        fails += ExpectStr(file, buf, want);
        fails += InfoSizes(&crt, file, strlen(text));
    }
    mbedtls_x509_crt_free(&crt);
    return fails;
}

/* Mbed TLS's x509_cert_info cases, read from its test data */
static int CertInfo(void)
{
    char line[4096];
    char buf[64];
    FILE* f;
    int skip = 0;
    int cases = 0;
    int fails = 0;

    f = fopen(X509PARSE_DATA, "r");
    if (f == NULL) {
        printf("FAIL: opening %s\n", X509PARSE_DATA);
        return 1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "depends_on:", 11) == 0) {
            /* Without it, no hash after RSASSA-PSS */
            skip = strstr(line, "MBEDTLS_X509_RSASSA_PSS_SUPPORT") != NULL;
        }
        else {
            if (!skip && strncmp(line, CERT_INFO, sizeof(CERT_INFO) - 1) == 0) {
                fails += CertInfoCase(line);
                cases++;
            }
            skip = 0;
        }
    }
    (void)fclose(f);
    if (cases == 0) {
        printf("FAIL: no x509_cert_info cases in %s\n", X509PARSE_DATA);
        fails++;
    }
    printf("%s: %d x509_cert_info cases\n", fails == 0 ? "PASS" : "FAIL",
        cases);

    if (mbedtls_x509_crt_info(buf, sizeof(buf), "", NULL) < 0) {
        buf[0] = '\0';
    }
    fails += ExpectStr("no certificate", buf,
        "\nCertificate is uninitialised!\n");
    return fails;
}

/* Subject alternative names not in Mbed TLS's x509_cert_info cases */
static int SanInfo(void)
{
    /* A hardware module name OID and no value */
    static unsigned char hwNoValue[] = {
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x04
    };
    static const struct {
        const char* what;
        const char* exts;
        unsigned char* other;   /* replaces the first name, as an otherName */
        const char* want;
    } sans[] = {
        { "registeredID", "300D0603551D110406300488022A03", NULL,
            "<unsupported>" },
        { "otherName of another type",
            "30180603551D110411300FA00D06032A0304A0060C0461626364", NULL,
            "<unsupported>" },
        { "malformed otherName, which parsing refuses",
            "300D0603551D110406300482026162", hwNoValue, "<malformed>" },
        { "IPv6 with a low byte under 0x10",
            "301B0603551D11041430128710" "20010DB8000000000000000000000001",
            NULL, "iPAddress : 2001:DB8:0:0:0:0:0:1" }
    };
    mbedtls_x509_buf* first;
    mbedtls_x509_crt crt;
    char buf[1000];
    char want[64];
    size_t i;
    int fails = 0;
    int ret;

    for (i = 0; i < sizeof(sans) / sizeof(sans[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        ret = ParseExts(&crt, sans[i].exts);
        first = &crt.subject_alt_names.buf;
        if (ret == 0 && sans[i].other != NULL) {
            first->tag = 0xA0;
            first->p = sans[i].other;
            first->len = sizeof(hwNoValue);
        }
        if (ret == 0) {
            ret = mbedtls_x509_crt_info(buf, sizeof(buf), "", &crt);
        }
        (void)snprintf(want, sizeof(want), "subject alt name  :\n    %s\n",
            sans[i].want);
        if (ret < 0 || strstr(buf, want) == NULL) {
            printf("FAIL: %s: returned %d, no \"%s\"\n", sans[i].what, ret,
                sans[i].want);
            fails++;
        }
        mbedtls_x509_crt_free(&crt);
    }
    return fails;
}

/* From Mbed TLS's x509_verify_info cases */
static int VerifyInfo(void)
{
    static const struct {
        uint32_t flags;
        const char* prefix;
        const char* want;
    } infos[] = {
        { 0, "", "" },
        { MBEDTLS_X509_BADCERT_MISSING, "", "Certificate was missing\n" },
        { MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCRL_EXPIRED, "",
            "The certificate validity has expired\nThe CRL is expired\n" },
        { MBEDTLS_X509_BADCERT_OTHER | 0x80000000, "",
            "Other reason (can be used by verify callback)\n"
            "Unknown reason (this should not happen)\n" },
        { 0, "  ! ", "" },
        { MBEDTLS_X509_BADCERT_MISSING, "  ! ",
            "  ! Certificate was missing\n" },
        { MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCRL_EXPIRED, "  ! ",
            "  ! The certificate validity has expired\n"
            "  ! The CRL is expired\n" }
    };
    char buf[256];
    size_t i;
    int fails = 0;
    int ret;

    for (i = 0; i < sizeof(infos) / sizeof(infos[0]); i++) {
        /* Old text, which no flags must also clear */
        memset(buf, 'x', sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        ret = mbedtls_x509_crt_verify_info(buf, sizeof(buf), infos[i].prefix,
            infos[i].flags);
        fails += ExpectStr("verify info", buf, infos[i].want);
        fails += Expect("verify info length", ret,
            (int)strlen(infos[i].want));
    }
    ret = mbedtls_x509_crt_verify_info(buf, strlen(infos[2].want),
        "", infos[2].flags);
    fails += Expect("verify info, short buffer", ret,
        MBEDTLS_ERR_X509_BUFFER_TOO_SMALL);
    return fails;
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */

/* wolfSSL's certificates with keys pk cannot hold parse with pk empty */
static int OtherKeys(void)
{
    static const char* const files[] = {
#ifdef HAVE_ED25519
        WOLFSSL_CERTS_DIR "/ed25519/server-ed25519.der",
#endif /* HAVE_ED25519 */
#ifdef HAVE_ED448
        WOLFSSL_CERTS_DIR "/ed448/server-ed448.der",
#endif /* HAVE_ED448 */
#ifdef WOLFSSL_HAVE_MLDSA
        WOLFSSL_CERTS_DIR "/mldsa/mldsa44-cert.der",
#endif /* WOLFSSL_HAVE_MLDSA */
#ifdef WC_RSA_PSS
        WOLFSSL_CERTS_DIR "/rsapss/server-rsapss.der",
#endif /* WC_RSA_PSS */
        NULL
    };
    static const psa_algorithm_t algs[] = {
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        PSA_ALG_RSA_PSS(PSA_ALG_SHA_256)
    };
    mbedtls_x509_crt crt;
    size_t i;
    size_t j;
    int fails = 0;
    int ret;
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    char buf[2000];
#endif /* !MBEDTLS_X509_REMOVE_INFO */

    for (i = 0; files[i] != NULL; i++) {
        mbedtls_x509_crt_init(&crt);
        ret = mbedtls_x509_crt_parse_file(&crt, files[i]);
        fails += Expect(files[i], ret, 0);
        fails += Expect("bits", (int)mbedtls_pk_get_bitlen(&crt.pk), 0);
        for (j = 0; j < sizeof(algs) / sizeof(algs[0]); j++) {
            fails += Expect("can do", mbedtls_pk_can_do_psa(&crt.pk, algs[j],
                PSA_KEY_USAGE_VERIFY_HASH), 0);
        }
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        if (ret == 0) {
            ret = mbedtls_x509_crt_info(buf, sizeof(buf), "", &crt);
        }
        if (ret < 0 || strstr(buf, "\nNONE key size     : 0 bits\n") == NULL) {
            printf("FAIL: %s: info\n", files[i]);
            fails++;
        }
#endif /* !MBEDTLS_X509_REMOVE_INFO */
        mbedtls_x509_crt_free(&crt);
    }
    return fails;
}

static int allocs;
static int failAt;

static void* FailAtMalloc(size_t size)
{
    return (++allocs == failAt) ? NULL : malloc(size);
}

/* Each allocation in turn fails, leaving the chain as it was */
static int FailEachAlloc(void)
{
    mbedtls_x509_crt crt;
    wolfSSL_Malloc_cb mf;
    wolfSSL_Free_cb ff;
    wolfSSL_Realloc_cb rf;
    int fails = 0;
    int ret;

    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_file(&crt, "test-ca.der") != 0) {
        printf("FAIL: reading test-ca.der\n");
        return 1;
    }
    (void)wolfSSL_GetAllocators(&mf, &ff, &rf);
    (void)wolfSSL_SetAllocators(FailAtMalloc, ff, rf);
    for (failAt = 1, ret = -1; ret != 0 && failAt < 100; failAt++) {
        allocs = 0;
        ret = mbedtls_x509_crt_parse_file(&crt, IN "bitstring-in-dn.pem");
        if (ret != 0 && (ret != MBEDTLS_ERR_X509_ALLOC_FAILED ||
                CountCerts(&crt) != 1)) {
            printf("FAIL: allocation %d failed: returned %d\n", failAt, ret);
            fails++;
        }
    }
    (void)wolfSSL_SetAllocators(mf, ff, rf);
    fails += Expect("each allocation fails", CountCerts(&crt), 2);
    /* A failed allocation does not leave the key empty */
    fails += Expect("each allocation fails, key",
        (crt.next != NULL) ? (int)mbedtls_pk_get_bitlen(&crt.next->pk) : 0,
        2048);
    mbedtls_x509_crt_free(&crt);
    return fails;
}

int main(void)
{
    mbedtls_x509_crt all;
    size_t i;
    int total = 0;
    int fails = 0;
    int certs;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    mbedtls_x509_crt_init(&all);
    fails += CheckAll(mbedtls_x509_crt_parse_file, cases,
        sizeof(cases) / sizeof(cases[0]), &all, &total);
    fails += CheckAll(mbedtls_x509_crt_parse_path, dirs,
        sizeof(dirs) / sizeof(dirs[0]), &all, &total);
    if (LoadPem("server5.crt")) {
        fails += CheckAll(ParseBundle, bundles,
            sizeof(bundles) / sizeof(bundles[0]), &all, &total);
    }
    else {
        printf("FAIL: reading server5.crt\n");
        fails++;
    }
    fails += BadInput();
    fails += TempDirs();
    fails += NoMemory();
    fails += ParseDerBuffer();
    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        fails += CheckFields(&fields[i]);
    }
    fails += Usage();
    fails += Extensions();
    fails += Names();
    fails += Dates();
    fails += Times();
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    fails += CertInfo();
    fails += SanInfo();
    fails += VerifyInfo();
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#if defined(MBEDTLS_THREADING_C) && !defined(NO_ASN_TIME)
    fails += TimeThreads();
#endif /* MBEDTLS_THREADING_C && !NO_ASN_TIME */
    fails += OtherKeys();
    fails += FailEachAlloc();
    certs = CountCerts(&all);
    if (certs == total) {
        printf("PASS: one chain\n");
    }
    else {
        printf("FAIL: one chain: %d certificates, expected %d\n", certs,
            total);
        fails++;
    }
    mbedtls_x509_crt_free(&all);
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
