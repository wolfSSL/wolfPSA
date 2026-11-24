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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
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

/* The 3.6-only codes, with Mbed TLS 3.6's text */
static int Strerror(void)
{
    static const struct {
        int code;
        const char* str;
    } errs[] = {
        { MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
            "CTR_DRBG - The entropy source failed" },
        { MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG,
            "CTR_DRBG - The requested random buffer length is too big" },
        { MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG,
            "CTR_DRBG - The input (entropy + additional data) is too large" },
        { MBEDTLS_ERR_ENTROPY_SOURCE_FAILED,
            "ENTROPY - Critical entropy source failure" },
        { MBEDTLS_ERR_ENTROPY_MAX_SOURCES,
            "ENTROPY - No more sources can be added" },
        { MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED,
            "ENTROPY - No sources have been added to poll" }
    };
    char buf[128];
    size_t i;
    int ok = 1;

    for (i = 0; ok && i < sizeof(errs) / sizeof(errs[0]); i++) {
        mbedtls_strerror(errs[i].code, buf, sizeof(buf));
        ok = strcmp(buf, errs[i].str) == 0;
        if (!ok) {
            printf("strerror: \"%s\", expected \"%s\"\n", buf, errs[i].str);
        }
    }
    return ok;
}

#ifdef MBEDTLS_ENTROPY_C
/* An application's own error code */
#define TEST_ENTROPY_ERR -1

/* Entropy for a DRBG or a source: counts calls, returns ret */
typedef struct {
    int calls;
    size_t len; /* asked for by the last call */
    size_t size;
    int ret;
} TestEntropy;

static int TestSource(void* data, unsigned char* output, size_t len,
    size_t* olen)
{
    TestEntropy* e = (TestEntropy*)data;

    e->calls++;
    e->len = len;
    *olen = (e->size < len) ? e->size : len;
    memset(output, 0x5A, *olen);
    return e->ret;
}

/* Each output is at most a block, and new */
static int EntropyOutput(void)
{
    mbedtls_entropy_context entropy;
    unsigned char a[MBEDTLS_ENTROPY_BLOCK_SIZE + 1];
    unsigned char b[MBEDTLS_ENTROPY_BLOCK_SIZE];
    int ok;

    mbedtls_entropy_init(&entropy);
    ok = mbedtls_entropy_func(&entropy, a, sizeof(b)) == 0 &&
        mbedtls_entropy_func(&entropy, b, sizeof(b)) == 0 &&
        memcmp(a, b, sizeof(b)) != 0 &&
        mbedtls_entropy_func(&entropy, a, sizeof(a)) ==
            MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    mbedtls_entropy_free(&entropy);
    ok = ok && mbedtls_entropy_func(&entropy, b, sizeof(b)) != 0;
    mbedtls_entropy_free(&entropy);
    return ok;
}

/* Polled up to its threshold; its error fails the output */
static int EntropySource(void)
{
    TestEntropy e = { 0, 0, 8, 0 };
    mbedtls_entropy_context entropy;
    unsigned char out[MBEDTLS_ENTROPY_BLOCK_SIZE];
    int ok;

    mbedtls_entropy_init(&entropy);
    ok = mbedtls_entropy_add_source(&entropy, TestSource, &e, 32,
            MBEDTLS_ENTROPY_SOURCE_STRONG) == 0 &&
        mbedtls_entropy_func(&entropy, out, sizeof(out)) == 0 &&
        e.calls == 4 && e.len == MBEDTLS_ENTROPY_MAX_GATHER;
    e.ret = TEST_ENTROPY_ERR;
    ok = ok && mbedtls_entropy_func(&entropy, out, sizeof(out)) ==
        TEST_ENTROPY_ERR;
    mbedtls_entropy_free(&entropy);
    return ok;
}

/* A source that never reaches its threshold fails the output */
static int EntropyThresholdNotReached(void)
{
    TestEntropy e = { 0, 0, 0, 0 };
    mbedtls_entropy_context entropy;
    unsigned char out[MBEDTLS_ENTROPY_BLOCK_SIZE];
    int ok;

    mbedtls_entropy_init(&entropy);
    ok = mbedtls_entropy_add_source(&entropy, TestSource, &e, 1,
            MBEDTLS_ENTROPY_SOURCE_WEAK) == 0 &&
        mbedtls_entropy_func(&entropy, out, sizeof(out)) ==
            MBEDTLS_ERR_ENTROPY_SOURCE_FAILED &&
        e.calls > 1;
    mbedtls_entropy_free(&entropy);
    return ok;
}

/* The default source is one of MBEDTLS_ENTROPY_MAX_SOURCES */
static int EntropyMaxSources(void)
{
    TestEntropy e = { 0, 0, 0, 0 };
    mbedtls_entropy_context entropy;
    int ok = 1;
    int i;

    mbedtls_entropy_init(&entropy);
    for (i = 1; ok && i < MBEDTLS_ENTROPY_MAX_SOURCES; i++) {
        ok = mbedtls_entropy_add_source(&entropy, TestSource, &e, 0,
            MBEDTLS_ENTROPY_SOURCE_WEAK) == 0;
    }
    ok = ok && mbedtls_entropy_add_source(&entropy, TestSource, &e, 0,
        MBEDTLS_ENTROPY_SOURCE_WEAK) == MBEDTLS_ERR_ENTROPY_MAX_SOURCES;
    mbedtls_entropy_free(&entropy);
    return ok;
}

#ifdef MBEDTLS_CTR_DRBG_C
static int TestDrbgEntropy(void* data, unsigned char* output, size_t len)
{
    TestEntropy* e = (TestEntropy*)data;

    e->calls++;
    e->len = len;
    memset(output, 0x5A, len);
    return e->ret;
}

/* Seeded from the default entropy source, as most applications do */
static int DrbgRandom(void)
{
    static const unsigned char pers[] = "mbedtls3_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    unsigned char a[32];
    unsigned char b[32];
    unsigned char big[MBEDTLS_CTR_DRBG_MAX_REQUEST + 1];
    int ok;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    ok = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, pers,
            sizeof(pers)) == 0 &&
        mbedtls_ctr_drbg_random(&drbg, a, sizeof(a)) == 0 &&
        mbedtls_ctr_drbg_random(&drbg, b, sizeof(b)) == 0 &&
        memcmp(a, b, sizeof(a)) != 0 &&
        mbedtls_ctr_drbg_random(&drbg, big, sizeof(big) - 1) == 0 &&
        mbedtls_ctr_drbg_random(&drbg, big, sizeof(big)) ==
            MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG;
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ok;
}

/* Entropy at seed, reseed, and each output with prediction resistance */
static int DrbgEntropyCalls(void)
{
    static const unsigned char add[16] = { 0 };
    TestEntropy e = { 0, 0, 0, 0 };
    mbedtls_ctr_drbg_context drbg;
    unsigned char out[16];
    int ok;

    mbedtls_ctr_drbg_init(&drbg);
    ok = mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, NULL, 0) == 0 &&
        e.calls == 1 && e.len == MBEDTLS_CTR_DRBG_ENTROPY_LEN &&
        mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) == 0 &&
        e.calls == 1 &&
        mbedtls_ctr_drbg_reseed(&drbg, add, sizeof(add)) == 0 &&
        e.calls == 2;
    mbedtls_ctr_drbg_set_prediction_resistance(&drbg, MBEDTLS_CTR_DRBG_PR_ON);
    ok = ok && mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) == 0 &&
        mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) == 0 &&
        e.calls == 4;
    mbedtls_ctr_drbg_free(&drbg);
    return ok;
}

static int DrbgReseedInterval(void)
{
    TestEntropy e = { 0, 0, 0, 0 };
    mbedtls_ctr_drbg_context drbg;
    unsigned char out[1];
    int ok;
    int i;

    mbedtls_ctr_drbg_init(&drbg);
    ok = mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, NULL, 0) == 0;
    for (i = 0; ok && i < MBEDTLS_CTR_DRBG_RESEED_INTERVAL; i++) {
        ok = mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) == 0;
    }
    ok = ok && e.calls == 1 &&
        mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) == 0 &&
        e.calls == 2;
    mbedtls_ctr_drbg_free(&drbg);
    return ok;
}

/* Entropy function errors, too much input and a DRBG not seeded */
static int DrbgErrors(void)
{
    static const unsigned char custom[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT -
        MBEDTLS_CTR_DRBG_ENTROPY_LEN + 1] = { 0 };
    TestEntropy e = { 0, 0, 0, TEST_ENTROPY_ERR };
    mbedtls_ctr_drbg_context drbg;
    unsigned char out[16];
    int ok;

    mbedtls_ctr_drbg_init(&drbg);
    ok = mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) ==
            MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED &&
        mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, NULL, 0) ==
            MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED &&
        mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) ==
            MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    e.ret = 0;
    ok = ok && mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, custom,
            sizeof(custom)) == MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG &&
        mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, custom,
            sizeof(custom) - 1) == 0 &&
        mbedtls_ctr_drbg_reseed(&drbg, custom, sizeof(custom)) ==
            MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    e.ret = TEST_ENTROPY_ERR;
    mbedtls_ctr_drbg_set_prediction_resistance(&drbg, MBEDTLS_CTR_DRBG_PR_ON);
    ok = ok && mbedtls_ctr_drbg_reseed(&drbg, NULL, 0) ==
            MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED &&
        mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) ==
            MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_ctr_drbg_free(&drbg);
    return ok;
}

/* NULL custom or additional input is empty, its length still checked */
static int DrbgNullInput(void)
{
    const size_t tooBig = MBEDTLS_CTR_DRBG_MAX_SEED_INPUT -
        MBEDTLS_CTR_DRBG_ENTROPY_LEN + 1;
    TestEntropy e = { 0, 0, 0, 0 };
    mbedtls_ctr_drbg_context drbg;
    unsigned char out[16];
    int ok;

    mbedtls_ctr_drbg_init(&drbg);
    ok = mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, NULL, tooBig) ==
            MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG &&
        mbedtls_ctr_drbg_seed(&drbg, TestDrbgEntropy, &e, NULL, 1) == 0 &&
        mbedtls_ctr_drbg_reseed(&drbg, NULL, tooBig) ==
            MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG &&
        mbedtls_ctr_drbg_reseed(&drbg, NULL, 1) == 0 &&
        mbedtls_ctr_drbg_random(&drbg, out, sizeof(out)) == 0;
    mbedtls_ctr_drbg_free(&drbg);
    return ok;
}

/* wolfCrypt adds its own seed, so the same entropy gives other output */
static int DrbgOwnSeed(void)
{
    TestEntropy e = { 0, 0, 0, 0 };
    mbedtls_ctr_drbg_context drbg[2];
    unsigned char out[2][32];
    int ok = 1;
    int i;

    for (i = 0; i < 2; i++) {
        mbedtls_ctr_drbg_init(&drbg[i]);
        ok = ok && mbedtls_ctr_drbg_seed(&drbg[i], TestDrbgEntropy, &e, NULL,
                0) == 0 &&
            mbedtls_ctr_drbg_random(&drbg[i], out[i], sizeof(out[i])) == 0;
    }
    ok = ok && memcmp(out[0], out[1], sizeof(out[0])) != 0;
    for (i = 0; i < 2; i++) {
        mbedtls_ctr_drbg_free(&drbg[i]);
    }
    return ok;
}

/* An entropy source error fails the seed */
static int DrbgSourceError(void)
{
    TestEntropy e = { 0, 0, 8, TEST_ENTROPY_ERR };
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    int ok;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    ok = mbedtls_entropy_add_source(&entropy, TestSource, &e, 32,
            MBEDTLS_ENTROPY_SOURCE_STRONG) == 0 &&
        mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL,
            0) == MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ok;
}

/* The setup of every 3.6 application */
static int ConfRng(void)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    int ok;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    ok = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL,
            0) == 0 &&
        mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0;
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    ok = ok && mbedtls_ssl_setup(&ssl, &conf) == 0;
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ok;
}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */

static const struct {
    const char* name;
    int (*test)(void);
} cases[] = {
    { "version 3.6.8", Version },
#ifndef MBEDTLS_DEPRECATED_REMOVED
    { "version ranges by major and minor", VersionsMajorMinor },
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
    { "strerror of the ctr_drbg and entropy codes", Strerror },
#ifdef MBEDTLS_ENTROPY_C
    { "entropy output", EntropyOutput },
    { "entropy source", EntropySource },
    { "entropy threshold not reached", EntropyThresholdNotReached },
    { "entropy max sources", EntropyMaxSources },
#ifdef MBEDTLS_CTR_DRBG_C
    { "ctr_drbg random", DrbgRandom },
    { "ctr_drbg entropy calls", DrbgEntropyCalls },
    { "ctr_drbg reseed interval", DrbgReseedInterval },
    { "ctr_drbg errors", DrbgErrors },
    { "ctr_drbg NULL input", DrbgNullInput },
    { "ctr_drbg own seed", DrbgOwnSeed },
    { "ctr_drbg entropy source error", DrbgSourceError },
    { "ssl_conf_rng", ConfRng },
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
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
