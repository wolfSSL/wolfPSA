/* version_test.c
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

/* The version macros and functions, as Mbed TLS's version suite checks */

#include <stdio.h>
#include <string.h>

#include <mbedtls/version.h>

/* The macros agree with each other */
static int CompileTime(void)
{
    char str[32];
    char full[48];

    (void)snprintf(str, sizeof(str), "%d.%d.%d", MBEDTLS_VERSION_MAJOR,
        MBEDTLS_VERSION_MINOR, MBEDTLS_VERSION_PATCH);
    (void)snprintf(full, sizeof(full), "Mbed TLS %s", str);
    return MBEDTLS_VERSION_NUMBER == ((MBEDTLS_VERSION_MAJOR << 24) |
            (MBEDTLS_VERSION_MINOR << 16) | (MBEDTLS_VERSION_PATCH << 8)) &&
        strcmp(str, MBEDTLS_VERSION_STRING) == 0 &&
        strcmp(full, MBEDTLS_VERSION_STRING_FULL) == 0;
}

/* The library was built with these headers, so the functions match them */
static int RunTime(void)
{
    const unsigned int number = mbedtls_version_get_number();
    char str[32];

    (void)snprintf(str, sizeof(str), "%u.%u.%u", (number >> 24) & 0xFF,
        (number >> 16) & 0xFF, (number >> 8) & 0xFF);
    return number == MBEDTLS_VERSION_NUMBER &&
        strcmp(str, mbedtls_version_get_string()) == 0 &&
        strcmp(mbedtls_version_get_string(), MBEDTLS_VERSION_STRING) == 0 &&
        strcmp(mbedtls_version_get_string_full(),
            MBEDTLS_VERSION_STRING_FULL) == 0;
}

int main(void)
{
    static const struct {
        const char* name;
        int (*test)(void);
    } cases[] = {
        { "version macros", CompileTime },
        { "version functions", RunTime }
    };
    size_t i;
    int fails = 0;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].test()) {
            printf("PASS: %s\n", cases[i].name);
        }
        else {
            printf("FAIL: %s\n", cases[i].name);
            fails++;
        }
    }
    return (fails == 0) ? 0 : 1;
}
