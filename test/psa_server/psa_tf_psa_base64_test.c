/* psa_tf_psa_base64_test.c
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

/* mbedtls/base64.h. Most cases come from TF-PSA-Crypto's
 * tests/suites/test_suite_base64.data. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/base64.h>

#if defined(MBEDTLS_BASE64_C)

#define INVALID MBEDTLS_ERR_BASE64_INVALID_CHARACTER
#define TOO_SMALL MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
/* Line ends that are not on a block boundary */
#define LINE_LEN 63

/* dlen is the size of the buffer for the result */
static const struct {
    const char* src;
    const char* dst;
    size_t dlen;
    int ret;
} encodeCases[] = {
    { "", "", 0, 0 },
    { "f", "Zg==", 5, 0 },
    { "f", "Zg==", 4, TOO_SMALL },
    { "fo", "Zm8=", 5, 0 },
    { "fo", "Zm8=", 4, TOO_SMALL },
    { "foo", "Zm9v", 5, 0 },
    { "foo", "Zm9v", 4, TOO_SMALL },
    { "foobar", "Zm9vYmFy", 9, 0 },
    { "foobar", "Zm9vYmFy", 8, TOO_SMALL }
};

/* The length of dst is the size of the buffer for the result */
static const struct {
    const char* src;
    const char* dst;
    int ret;
} decodeCases[] = {
    { "", "", 0 },
    { "Zg==", "f", 0 },
    { "Zm8=", "fo", 0 },
    { "Zm9vYmFy", "foobar", 0 },
    { "zm#=", "", INVALID },
    { "zm===", "", INVALID },
    { "zm=masd", "", INVALID },
    { "zm masd", "", INVALID },
    { "Y", "", INVALID },
    { "Yw", "c", INVALID },
    { "Yw=", "c", INVALID },
    { "Yw===", "c", INVALID },
    { "Y29t=", "com", INVALID },
    { "Y29tcA==", "comp", 0 },
    { "Y29tcG8=", "compo", 0 },
    { "Zm9vYmFy\n", "foobar", 0 },
    { "Zm9vYmFy\r\n", "foobar", 0 },
    { "Zm9vYmFy\r", "", INVALID },
    { "Zm9vYmFy  ", "foobar", 0 },
    { "Zm9vYmFy  \r\n", "foobar", 0 },
    { "Zm9vYmF\ny", "foobar", 0 },
    { "Zm9vYmF\ry", "", INVALID },
    { "Zm9vYmF y", "", INVALID },
    { "Zm9vYmF  \r\ny", "foobar", 0 },
    { "Zm9v\n\n\r\nYmFy", "foobar", 0 },
    { "Zm8=\nZm8=", "", INVALID },
    { "\x80Zm9v", "", INVALID }
};

static int fails;

static void Check(int ok, const char* name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

static void Encode(void)
{
    unsigned char dst[16];
    char name[48];
    size_t len;
    size_t want;
    size_t i;
    int ret;

    for (i = 0; i < sizeof(encodeCases) / sizeof(encodeCases[0]); i++) {
        (void)snprintf(name, sizeof(name), "encode \"%s\" into %u",
            encodeCases[i].src, (unsigned)encodeCases[i].dlen);
        want = strlen(encodeCases[i].dst);
        memset(dst, 0xff, sizeof(dst));
        len = 0;
        ret = mbedtls_base64_encode(dst, encodeCases[i].dlen, &len,
            (const unsigned char*)encodeCases[i].src,
            strlen(encodeCases[i].src));
        if (ret != 0) {
            Check(ret == encodeCases[i].ret && len == want + 1, name);
        }
        else {
            Check(encodeCases[i].ret == 0 && len == want &&
                memcmp(dst, encodeCases[i].dst, want) == 0 &&
                (want == 0 || dst[want] == 0), name);
        }
    }
}

/* Size queries, up to overflow. src is not read when sizing. */
static void EncodeSize(void)
{
    static const unsigned char src[] = "foo";
    unsigned char dst[5];
    size_t len = 0;

    Check(mbedtls_base64_encode(NULL, 0, &len, src, 3) == TOO_SMALL &&
        len == sizeof(dst), "encode size query");
    len = 0;
    Check(mbedtls_base64_encode(dst, sizeof(dst), &len, src, 3) == 0 &&
        len == 4 && memcmp(dst, "Zm9v", sizeof(dst)) == 0,
        "encode into the queried size");
    len = 0;
    Check(mbedtls_base64_encode(NULL, 0, &len, src, 0x3FFFFFFF) ==
        TOO_SMALL && len == 0x55555555, "encode size of 1 GiB");
    len = 0;
    Check(mbedtls_base64_encode(NULL, 0, &len, src, SIZE_MAX) == TOO_SMALL &&
        len == SIZE_MAX, "encode size overflow");
}

/* Longer than a few KiB, with padding at the end */
static void EncodeLong(void)
{
    static unsigned char src[3 * 1100 + 1];
    static unsigned char dst[4 * 1101 + 1];
    size_t len = 0;
    size_t i;
    int ok;

    for (i = 0; i + 3 <= sizeof(src); i += 3) {
        memcpy(src + i, "foo", 3);
    }
    src[i] = 'f';
    ok = mbedtls_base64_encode(dst, sizeof(dst), &len, src, sizeof(src)) ==
        0 && len == sizeof(dst) - 1;
    for (i = 0; ok && i + 4 < len; i += 4) {
        ok = memcmp(dst + i, "Zm9v", 4) == 0;
    }
    Check(ok && memcmp(dst + i, "Zg==", 5) == 0, "encode long input");
}

/* Every digit both ways, and every other byte value rejected */
static void Digits(void)
{
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char src[4] = { 0, 'A', 'A', 'A' };
    unsigned char raw[3] = { 0, 0, 0 };
    unsigned char out[5];
    const char* p;
    size_t len;
    int c;
    int ret;
    int ok = 1;

    for (c = 0; ok && c < 256; c++) {
        src[0] = (unsigned char)c;
        p = (c != 0) ? strchr(digits, c) : NULL;
        len = 0;
        ret = mbedtls_base64_decode(out, sizeof(out), &len, src, sizeof(src));
        if (p == NULL) {
            ok = ret == INVALID;
        }
        else {
            ok = ret == 0 && len == 3 && out[0] == ((p - digits) << 2) &&
                out[1] == 0 && out[2] == 0;
        }
    }
    for (c = 0; ok && c < 64; c++) {
        raw[0] = (unsigned char)(c << 2);
        len = 0;
        ok = mbedtls_base64_encode(out, sizeof(out), &len, raw,
            sizeof(raw)) == 0 && len == 4 && out[0] == digits[c] &&
            memcmp(out + 1, "AAA", 3) == 0;
    }
    Check(ok, "every digit");
}

/* As the suite: the exact size, one byte less, and no buffer */
static int DecodeCase(size_t i)
{
    const unsigned char* src = (const unsigned char*)decodeCases[i].src;
    size_t srcLen = strlen(decodeCases[i].src);
    size_t want = strlen(decodeCases[i].dst);
    unsigned char dst[16];
    size_t len = 0;
    int ret;

    ret = mbedtls_base64_decode(dst, want, &len, src, srcLen);
    if (ret != decodeCases[i].ret) {
        return 0;
    }
    if (ret != 0) {
        return 1;
    }
    if (len != want || memcmp(dst, decodeCases[i].dst, want) != 0) {
        return 0;
    }
    if (want == 0) {
        return 1;
    }
    len = 0;
    if (mbedtls_base64_decode(dst, want - 1, &len, src, srcLen) !=
            TOO_SMALL || len != want) {
        return 0;
    }
    len = 0;
    if (mbedtls_base64_decode(NULL, 0, &len, src, srcLen) != TOO_SMALL ||
            len != want) {
        return 0;
    }
    len = 0;
    return mbedtls_base64_decode(NULL, sizeof(dst), &len, src, srcLen) ==
        TOO_SMALL && len == want;
}

static void Decode(void)
{
    char name[32];
    size_t i;

    for (i = 0; i < sizeof(decodeCases) / sizeof(decodeCases[0]); i++) {
        (void)snprintf(name, sizeof(name), "decode case %u", (unsigned)i);
        Check(DecodeCase(i), name);
    }
}

/* Every byte value at every offset, and back with line ends inside blocks */
static void RoundTrip(void)
{
    unsigned char in[258];
    unsigned char enc[sizeof(in) / 3 * 4 + 1];
    unsigned char lines[sizeof(enc) * 2];
    unsigned char out[sizeof(in)];
    size_t inLen;
    size_t encLen = 0;
    size_t linesLen;
    size_t len = 0;
    size_t i;
    size_t off;
    int ok = 1;

    for (off = 0; ok && off < 3; off++) {
        inLen = sizeof(in) - off;
        for (i = 0; i < inLen; i++) {
            in[i] = (unsigned char)(i + off);
        }
        ok = mbedtls_base64_encode(enc, sizeof(enc), &encLen, in, inLen) == 0;
        for (i = 0, linesLen = 0; ok && i < encLen; i++) {
            if (i > 0 && i % LINE_LEN == 0) {
                lines[linesLen++] = '\r';
                lines[linesLen++] = '\n';
            }
            lines[linesLen++] = enc[i];
        }
        ok = ok && mbedtls_base64_decode(out, sizeof(out), &len, lines,
            linesLen) == 0 && len == inLen && memcmp(out, in, len) == 0;
    }
    Check(ok, "round trip");
}

static void BadInput(void)
{
    static const unsigned char nul[] = "Zm9v\0Zm9v";
    unsigned char dst[8];
    size_t len = 1;

    Check(mbedtls_base64_decode(dst, sizeof(dst), &len, nul,
        sizeof(nul) - 1) == INVALID, "decode NUL");
    Check(mbedtls_base64_decode(NULL, 0, &len, NULL, 0) == 0 && len == 0,
        "decode nothing");
    len = 1;
    Check(mbedtls_base64_encode(NULL, 0, &len, NULL, 0) == 0 && len == 0,
        "encode nothing");
    Check(mbedtls_base64_decode(dst, sizeof(dst), &len, NULL, 1) ==
        PSA_ERROR_INVALID_ARGUMENT, "decode NULL source");
    Check(mbedtls_base64_encode(dst, sizeof(dst), NULL, nul, 1) ==
        PSA_ERROR_INVALID_ARGUMENT, "encode NULL length");
}

int main(void)
{
    Encode();
    EncodeSize();
    EncodeLong();
    Digits();
    Decode();
    RoundTrip();
    BadInput();
    return (fails == 0) ? 0 : 1;
}

#else

int main(void)
{
    printf("base64 tests: skipped, no MBEDTLS_BASE64_C\n");
    return 0;
}

#endif /* MBEDTLS_BASE64_C */
