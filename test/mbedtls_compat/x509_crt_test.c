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
#include <unistd.h>

#include <psa/crypto.h>
#include <mbedtls/x509_crt.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>

/* Any error code */
#define ERR -1
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
    { IN "server7_int-ca.crt", 0, 2 },
    { IN "server7_trailing_space.crt", 0, 2 },
    { IN "cli-rsa-sha256-badalg.crt.der", ERR, 0 },
    /* wolfSSL ignores bytes after an empty basicConstraints. Mbed TLS: ERR */
    { IN "server5.basic-constraints-sequence-overflow.badsign.crt", 0, 1 },
    { IN "server5.basic-constraints-sequence-overflow.selfsigned.crt", 0, 1 },
    /* Over WOLFSSL_MAX_PATH_LEN, and serial number 0. Mbed TLS: 0, 1 */
    { IN "server1_pathlen_int_max-1.crt", ERR, 0 },
    { "dir3/test-ca.crt", ERR, 0 },
    /* wolfSSL skips spaces in base64. Mbed TLS: 1, 1 and ERR, 0 */
    { IN "server7_pem_space.crt", 0, 2 },
    { IN "server7_all_space.crt", 0, 2 },
    /* Not in Mbed TLS's cases */
    { "test-ca.der", 0, 1 },
    { "missing.crt", MBEDTLS_ERR_PK_FILE_IO_ERROR, 0 },
    /* NULL parameters after the ECDSA signature OID */
    { "test-ca2.crt", 0, 1 }
};

/* Each test-ca.crt fails, as in the cases above. Mbed TLS: 0, 1 and 0, 2 and
 * 1, 2. */
static const Case dirs[] = {
    { "dir1", 1, 0 },
    { "dir2", 1, 1 },
    { "dir3", 2, 1 },
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

/* Mbed TLS ignores data after a DER certificate, such as a NUL */
static int TrailingByte(void)
{
    mbedtls_x509_crt crt;
    mbedtls_x509_crt copy;
    unsigned char buf[2048];
    int ok = 0;

    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&copy);
    if (mbedtls_x509_crt_parse_file(&crt, "test-ca.der") == 0 &&
            crt.raw.len < sizeof(buf)) {
        memcpy(buf, crt.raw.p, crt.raw.len);
        buf[crt.raw.len] = 0;
        ok = mbedtls_x509_crt_parse_der(&copy, buf, crt.raw.len + 1) == 0 &&
            copy.raw.len == crt.raw.len;
    }
    mbedtls_x509_crt_free(&copy);
    mbedtls_x509_crt_free(&crt);
    return ok;
}

int main(void)
{
    mbedtls_x509_crt all;
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
    certs = CountCerts(&all);
    if (certs == total) {
        printf("PASS: one chain\n");
    }
    else {
        printf("FAIL: one chain: %d certificates, expected %d\n", certs,
            total);
        fails++;
    }
    if (TrailingByte()) {
        printf("PASS: DER with a trailing byte\n");
    }
    else {
        printf("FAIL: DER with a trailing byte\n");
        fails++;
    }
    mbedtls_x509_crt_free(&all);
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
