/* pem.c
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

/* Mbed TLS 4.x PEM decoding on wolfCrypt's Base64 (MBEDTLS_COMPAT=1). */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfpsa/psa_engine.h>
#include <mbedtls/pem.h>

/* The generated config has MBEDTLS_PEM_PARSE_C with wolfCrypt's Base64
 * decoding */
#if defined(MBEDTLS_PEM_PARSE_C) != \
        (!defined(NO_CODING) && defined(WOLFSSL_BASE64_DECODE))
    #error "MBEDTLS_PEM_PARSE_C does not match wolfCrypt's Base64 decoding"
#endif /* MBEDTLS_PEM_PARSE_C != (!NO_CODING && WOLFSSL_BASE64_DECODE) */

#if defined(MBEDTLS_PEM_PARSE_C)

/* Mbed TLS adds MBEDTLS_ERR_BASE64_INVALID_CHARACTER to the PEM error */
#define MBED_PEM_BAD_BASE64 (MBEDTLS_ERR_PEM_INVALID_DATA - 0x002C)

void mbedtls_pem_init(mbedtls_pem_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_pem_init");

    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
}

/* Skips a space and the end of the line after it. Returns NULL when the line
 * does not end there and the end is required. */
static const char* MbedPemEol(const char* s, int required)
{
    if (*s == ' ') {
        s++;
    }
    if (*s == '\r') {
        s++;
    }
    if (*s == '\n') {
        return s + 1;
    }
    return required ? NULL : s;
}

/* As in Mbed TLS, *use_len is set once the header and footer are found */
int mbedtls_pem_read_buffer(mbedtls_pem_context* ctx, const char* header,
    const char* footer, const unsigned char* data, const unsigned char* pwd,
    size_t pwdlen, size_t* use_len)
{
    const char* s1;
    const char* s2;
    unsigned char* buf;
    word32 inLen;
    word32 size;
    word32 len;
    int ret = 0;

    WOLFSSL_ENTER("mbedtls_pem_read_buffer");

    (void)pwd;
    (void)pwdlen;
    if (ctx == NULL || header == NULL || footer == NULL || data == NULL ||
            use_len == NULL) {
        return MBEDTLS_ERR_PEM_BAD_INPUT_DATA;
    }

    s1 = XSTRSTR((const char*)data, header);
    s2 = XSTRSTR((const char*)data, footer);
    if (s1 == NULL || s2 == NULL || s2 <= s1) {
        return MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }
    s1 = MbedPemEol(s1 + XSTRLEN(header), 1);
    if (s1 == NULL) {
        return MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }
    *use_len = (size_t)(MbedPemEol(s2 + XSTRLEN(footer), 0) -
        (const char*)data);

    if (s2 - s1 >= 22 && XMEMCMP(s1, "Proc-Type: 4,ENCRYPTED", 22) == 0) {
        return MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE;
    }
    if (s1 >= s2) {
        return MBEDTLS_ERR_PEM_INVALID_DATA;
    }
    if ((size_t)(s2 - s1) > (size_t)WOLFSSL_MAX_32BIT) {
        return MBEDTLS_ERR_PEM_BAD_INPUT_DATA;
    }
    if (!wolfPSA_CryptoReady()) {
        return PSA_ERROR_BAD_STATE;
    }

    inLen = (word32)(s2 - s1);
    size = (inLen / 4 + 1) * 3;
    buf = (unsigned char*)XMALLOC(size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return MBEDTLS_ERR_PEM_ALLOC_FAILED;
    }
    len = size;
    if (Base64_Decode((const byte*)s1, inLen, buf, &len) != 0) {
        ret = MBED_PEM_BAD_BASE64;
    }
    else if (len == 0) {
        ret = MBEDTLS_ERR_PEM_BAD_INPUT_DATA;
    }
    if (ret != 0) {
        wc_ForceZero(buf, size);
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    mbedtls_pem_free(ctx);
    ctx->buf = buf;
    ctx->buflen = len;
    return 0;
}

void mbedtls_pem_free(mbedtls_pem_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_pem_free");

    if (ctx != NULL && ctx->buf != NULL) {
        wc_ForceZero(ctx->buf, ctx->buflen);
        XFREE(ctx->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    mbedtls_pem_init(ctx);
}

#endif /* MBEDTLS_PEM_PARSE_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
