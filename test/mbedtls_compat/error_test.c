/* error_test.c
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

/* mbedtls_strerror, starting with the cases of Mbed TLS's error suite */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#define UNKNOWN_BOTH "UNKNOWN ERROR CODE (8880) : UNKNOWN ERROR CODE (007F)"

static const struct {
    const char* name;
    int code;
    size_t len;
    const char* str;
} cases[] = {
    { "low-level code", MBEDTLS_ERR_NET_SOCKET_FAILED, 500,
        "NET - Failed to open a socket" },
    { "high-level code", MBEDTLS_ERR_X509_INVALID_FORMAT, 500,
        "X509 - The CRT/CRL/CSR format is invalid, e.g. different type "
        "expected" },
    { "unknown high-level code", -0x8880, 500, "UNKNOWN ERROR CODE (8880)" },
    { "unknown low-level code", -0x007F, 500, "UNKNOWN ERROR CODE (007F)" },
    { "unknown high and low-level code", -0x88FF, 500, UNKNOWN_BOTH },
    { "high and low-level code",
        MBEDTLS_ERR_PK_FILE_IO_ERROR + MBEDTLS_ERR_NET_SOCKET_FAILED, 500,
        "PK - Read/write of file failed : NET - Failed to open a socket" },
    { "fatal alert, low-level part left out",
        MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE + MBEDTLS_ERR_NET_SOCKET_FAILED,
        500, "SSL - A fatal alert message was received from our peer" },
    { "positive code", -(MBEDTLS_ERR_NET_SOCKET_FAILED), 500,
        "NET - Failed to open a socket" },
    { "0", 0, 500, "" },
    { "INT_MIN", INT_MIN, 500, "UNKNOWN ERROR CODE (80000000)" },
    { "five hex digits", -0x10000, 500, "UNKNOWN ERROR CODE (10000)" },
    { "truncated", MBEDTLS_ERR_NET_SOCKET_FAILED, 10, "NET - Fai" },
    { "truncated unknown code", -0x007F, 10, "UNKNOWN E" },
    { "one byte", MBEDTLS_ERR_NET_SOCKET_FAILED, 1, "" },
    { "truncated low-level part", -0x88FF, 30,
        "UNKNOWN ERROR CODE (8880) : U" },
    { "no room for the low-level part", -0x88FF, 29,
        "UNKNOWN ERROR CODE (8880)" }
};

/* The byte after the given length is left alone */
static int Case(size_t i)
{
    char buf[512];
    int ok;

    memset(buf, 'x', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    mbedtls_strerror(cases[i].code, buf, cases[i].len);
    ok = strcmp(buf, cases[i].str) == 0 && buf[cases[i].len] == 'x';
    if (!ok) {
        printf("FAIL: %s: \"%s\", expected \"%s\"\n", cases[i].name, buf,
            cases[i].str);
    }
    return ok;
}

/* A zero length or NULL buffer is left alone */
static int NoBuffer(void)
{
    char buf[1] = { 'x' };

    mbedtls_strerror(MBEDTLS_ERR_NET_SOCKET_FAILED, buf, 0);
    mbedtls_strerror(MBEDTLS_ERR_NET_SOCKET_FAILED, NULL, sizeof(buf));
    return buf[0] == 'x';
}

int main(void)
{
    size_t i;
    int fails = 0;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (Case(i)) {
            printf("PASS: %s\n", cases[i].name);
        }
        else {
            fails++;
        }
    }
    if (NoBuffer()) {
        printf("PASS: no buffer\n");
    }
    else {
        printf("FAIL: no buffer\n");
        fails++;
    }
    return (fails == 0) ? 0 : 1;
}
