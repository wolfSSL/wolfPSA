/* mbedtls3_test.c
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

/* The Mbed TLS 3.6 API, built with WOLFPSA_MBEDTLS_3 */

#include <stdio.h>
#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/version.h>

static int Version(void)
{
    return MBEDTLS_VERSION_MAJOR == 3 &&
        MBEDTLS_VERSION_NUMBER == 0x03060800 &&
        strcmp(MBEDTLS_VERSION_STRING, "3.6.8") == 0;
}

#ifndef MBEDTLS_DEPRECATED_REMOVED
/* Each range by minor version is the range by TLS version. ssl_test checks
 * the handshakes of the ranges by TLS version. */
static int VersionsMajorMinor(void)
{
    static const struct {
        int minor;
        mbedtls_ssl_protocol_version tls_version;
    } versions[] = {
        { MBEDTLS_SSL_MINOR_VERSION_3, MBEDTLS_SSL_VERSION_TLS1_2 },
        { MBEDTLS_SSL_MINOR_VERSION_4, MBEDTLS_SSL_VERSION_TLS1_3 }
    };
    const size_t count = sizeof(versions) / sizeof(versions[0]);
    mbedtls_ssl_config byMinor;
    mbedtls_ssl_config byVersion;
    size_t i;
    size_t j;
    int ok = 1;

    mbedtls_ssl_config_init(&byMinor);
    mbedtls_ssl_config_init(&byVersion);
    for (i = 0; ok && i < count; i++) {
        for (j = 0; ok && j < count; j++) {
            mbedtls_ssl_conf_min_version(&byMinor, MBEDTLS_SSL_MAJOR_VERSION_3,
                versions[i].minor);
            mbedtls_ssl_conf_max_version(&byMinor, MBEDTLS_SSL_MAJOR_VERSION_3,
                versions[j].minor);
            mbedtls_ssl_conf_min_tls_version(&byVersion,
                versions[i].tls_version);
            mbedtls_ssl_conf_max_tls_version(&byVersion,
                versions[j].tls_version);
            ok = byMinor.min_tls_version == byVersion.min_tls_version &&
                byMinor.max_tls_version == byVersion.max_tls_version;
        }
    }
    mbedtls_ssl_config_free(&byMinor);
    mbedtls_ssl_config_free(&byVersion);
    return ok;
}
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

static const struct {
    const char* name;
    int (*test)(void);
} cases[] = {
    { "version 3.6.8", Version },
#ifndef MBEDTLS_DEPRECATED_REMOVED
    { "version ranges by major and minor", VersionsMajorMinor },
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
};

int main(void)
{
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
