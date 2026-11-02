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
 * certificate. The cases of mbedtls_x509_crt_parse_file come from Mbed TLS's
 * tests/suites/test_suite_x509parse.data. Run from framework/data_files in
 * an Mbed TLS checkout. */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/x509_crt.h>

/* Any error code */
#define ERR -1
#define IN "parse_input/"

static const struct {
    const char* file;
    int ret;    /* number that failed, or ERR */
    int certs;
} cases[] = {
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
    { "missing.crt", ERR, 0 },
    /* NULL parameters after the ECDSA signature OID */
    { "test-ca2.crt", 0, 1 }
};

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
    mbedtls_x509_crt crt;
    mbedtls_x509_crt all;
    size_t i;
    int total = 0;
    int fails = 0;
    int certs;
    int ret;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    /* Every file also goes into one chain, which only grows */
    mbedtls_x509_crt_init(&all);
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        mbedtls_x509_crt_init(&crt);
        ret = mbedtls_x509_crt_parse_file(&crt, cases[i].file);
        certs = CountCerts(&crt);
        if ((cases[i].ret == ERR ? ret < 0 : ret == cases[i].ret) &&
                certs == cases[i].certs) {
            printf("PASS: %s\n", cases[i].file);
        }
        else {
            printf("FAIL: %s: returned %d with %d certificates, expected %d "
                "with %d\n", cases[i].file, ret, certs, cases[i].ret,
                cases[i].certs);
            fails++;
        }
        mbedtls_x509_crt_free(&crt);
        (void)mbedtls_x509_crt_parse_file(&all, cases[i].file);
        total += cases[i].certs;
    }
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
