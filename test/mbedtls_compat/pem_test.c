/* pem_test.c
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

/* PEM decoding through the TF-PSA-Crypto 1.x API. The unencrypted cases come
 * from TF-PSA-Crypto's tests/suites/test_suite_pem.data. Run from
 * framework/data_files in an Mbed TLS checkout. */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/pem.h>

#define CERT_BEGIN "-----BEGIN CERTIFICATE-----"
#define CERT_END   "-----END CERTIFICATE-----"
/* Mbed TLS adds MBEDTLS_ERR_BASE64_INVALID_CHARACTER, -0x002C */
#define BAD_BASE64 (MBEDTLS_ERR_PEM_INVALID_DATA - 0x002C)
/* Larger than the test files */
#define FILE_SZ 8192

static const struct {
    const char* name;
    const char* data;
    int ret;
    const char* out;
} cases[] = {
    { "valid", "^\nTWJlZCBUTFM=\n$", 0, "Mbed TLS" },
    { "empty content", "^\n\n$", MBEDTLS_ERR_PEM_BAD_INPUT_DATA, NULL },
    { "encrypted",
        "^\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nTWJl\n$",
        MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE, NULL },
    { "bad Base64", "^\nTW!lZCBUTFM=\n$", BAD_BASE64, NULL },
    { "no header", "TWJlZCBUTFM=\n$", MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT,
        NULL },
    { "no footer", "^\nTWJlZCBUTFM=\n",
        MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT, NULL },
    { "footer first", "$\n^\nTWJlZCBUTFM=\n",
        MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT, NULL },
    { "data on the header line", "^TWJlZCBUTFM=\n$",
        MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT, NULL },
    { "CRLF and a space", "^ \r\nTWJlZCBU\r\nTFM=\r\n$", 0, "Mbed TLS" }
};

static long ReadFile(const char* path, unsigned char* buf, size_t sz)
{
    FILE* f = fopen(path, "rb");
    size_t len = 0;

    if (f != NULL) {
        len = fread(buf, 1, sz, f);
        fclose(f);
    }
    return (f == NULL || len == sz) ? -1 : (long)len;
}

/* Two certificates in one buffer: use_len is where the second starts */
static int TwoCerts(void)
{
    static unsigned char pem[2 * FILE_SZ + 1];
    static unsigned char der[FILE_SZ];
    mbedtls_pem_context ctx;
    const unsigned char* out;
    size_t outLen = 0;
    size_t used = 0;
    long pemLen = ReadFile("server5.crt", pem, FILE_SZ);
    long derLen = ReadFile("server5.crt.der", der, sizeof(der));
    int ok = pemLen > 0 && derLen > 0;

    mbedtls_pem_init(&ctx);
    if (ok) {
        memcpy(pem + pemLen, pem, (size_t)pemLen);
        pem[2 * pemLen] = '\0';
        ok = mbedtls_pem_read_buffer(&ctx, CERT_BEGIN, CERT_END, pem, NULL, 0,
            &used) == 0 && used == (size_t)pemLen;
    }
    if (ok) {
        out = mbedtls_pem_get_buffer(&ctx, &outLen);
        ok = outLen == (size_t)derLen && memcmp(out, der, outLen) == 0;
    }
    /* A second read into the context replaces the first */
    if (ok) {
        ok = mbedtls_pem_read_buffer(&ctx, CERT_BEGIN, CERT_END, pem + used,
            NULL, 0, &used) == 0 && used == (size_t)pemLen;
    }
    if (ok) {
        out = mbedtls_pem_get_buffer(&ctx, &outLen);
        ok = outLen == (size_t)derLen && memcmp(out, der, outLen) == 0;
    }
    mbedtls_pem_free(&ctx);
    return ok;
}

static int BadInput(void)
{
    mbedtls_pem_context ctx;
    size_t used = 0;

    mbedtls_pem_init(&ctx);
    return mbedtls_pem_read_buffer(NULL, "^", "$",
            (const unsigned char*)"^\nTWJl\n$", NULL, 0, &used) ==
        MBEDTLS_ERR_PEM_BAD_INPUT_DATA &&
        mbedtls_pem_read_buffer(&ctx, "^", "$", NULL, NULL, 0, &used) ==
            MBEDTLS_ERR_PEM_BAD_INPUT_DATA;
}

static int Case(size_t i)
{
    mbedtls_pem_context ctx;
    const unsigned char* out;
    size_t outLen = 0;
    size_t used = 0;
    int ret;
    int ok;

    mbedtls_pem_init(&ctx);
    ret = mbedtls_pem_read_buffer(&ctx, "^", "$",
        (const unsigned char*)cases[i].data, NULL, 0, &used);
    ok = ret == cases[i].ret;
    if (ok && ret == 0) {
        out = mbedtls_pem_get_buffer(&ctx, &outLen);
        ok = used == strlen(cases[i].data) &&
            outLen == strlen(cases[i].out) &&
            memcmp(out, cases[i].out, outLen) == 0;
    }
    if (!ok) {
        printf("FAIL: %s: returned %d, expected %d\n", cases[i].name, ret,
            cases[i].ret);
    }
    mbedtls_pem_free(&ctx);
    return ok;
}

int main(void)
{
    size_t i;
    int fails = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (Case(i)) {
            printf("PASS: %s\n", cases[i].name);
        }
        else {
            fails++;
        }
    }
    if (TwoCerts()) {
        printf("PASS: two certificates\n");
    }
    else {
        printf("FAIL: two certificates\n");
        fails++;
    }
    if (BadInput()) {
        printf("PASS: bad input\n");
    }
    else {
        printf("FAIL: bad input\n");
        fails++;
    }
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
