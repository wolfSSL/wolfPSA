/* ssl.h
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

#ifndef MBEDTLS_SSL_H
#define MBEDTLS_SSL_H

#include "mbedtls/build_info.h"
#include "mbedtls/x509_crt.h"
/* From wolfPSA, as Mbed TLS takes it from TF-PSA-Crypto */
#include "psa/crypto.h"
/* Mbed TLS includes it through ssl_cache.h, on by default there */
#include "mbedtls/threading.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_SSL_IS_CLIENT             0
#define MBEDTLS_SSL_IS_SERVER             1
#define MBEDTLS_SSL_TRANSPORT_STREAM      0
#define MBEDTLS_SSL_TRANSPORT_DATAGRAM    1
#define MBEDTLS_SSL_PRESET_DEFAULT        0
#define MBEDTLS_SSL_VERIFY_NONE           0
#define MBEDTLS_SSL_VERIFY_OPTIONAL       1
#define MBEDTLS_SSL_VERIFY_REQUIRED       2
#define MBEDTLS_SSL_MAX_HOST_NAME_LEN     255

/* Mbed TLS defines -135 and -141 as PSA_ERROR_INVALID_ARGUMENT and
 * PSA_ERROR_INSUFFICIENT_MEMORY */
#define MBEDTLS_ERR_SSL_TIMEOUT              -0x6800
#define MBEDTLS_ERR_SSL_WANT_WRITE           -0x6880
#define MBEDTLS_ERR_SSL_WANT_READ            -0x6900
#define MBEDTLS_ERR_SSL_INTERNAL_ERROR       -0x6C00
#define MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE  -0x7080
#define MBEDTLS_ERR_SSL_CONN_EOF             -0x7280
#define MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY    -0x7880
#define MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET -0x7B00
#define MBEDTLS_ERR_SSL_HW_ACCEL_FAILED      -0x7F80
#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA       -135
#define MBEDTLS_ERR_SSL_ALLOC_FAILED         -141

/* wolfSSL objects, opaque to the application */
struct WOLFSSL_CTX;
struct WOLFSSL;

typedef int mbedtls_ssl_send_t(void* ctx, const unsigned char* buf,
    size_t len);
typedef int mbedtls_ssl_recv_t(void* ctx, unsigned char* buf, size_t len);
typedef int mbedtls_ssl_recv_timeout_t(void* ctx, unsigned char* buf,
    size_t len, uint32_t timeout);

typedef struct mbedtls_ssl_config {
    struct WOLFSSL_CTX* ctx;
    int err; /* first failure of a void conf call, see mbedtls_ssl_setup() */
    int authmode;
} mbedtls_ssl_config;

typedef struct mbedtls_ssl_context {
    const mbedtls_ssl_config* conf;
    struct WOLFSSL* ssl;
    char* hostname; /* applied again by mbedtls_ssl_session_reset() */
    void* p_bio;
    mbedtls_ssl_send_t* f_send;
    mbedtls_ssl_recv_t* f_recv;
    mbedtls_ssl_recv_timeout_t* f_recv_timeout;
    int authmode;
    uint32_t verify_flags; /* MBEDTLS_X509_BADCERT_* from the handshake */
} mbedtls_ssl_context;

void mbedtls_ssl_config_init(mbedtls_ssl_config* conf);
void mbedtls_ssl_config_free(mbedtls_ssl_config* conf);
int mbedtls_ssl_config_defaults(mbedtls_ssl_config* conf,
    int endpoint, int transport, int preset);
void mbedtls_ssl_conf_authmode(mbedtls_ssl_config* conf, int authmode);
void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config* conf,
    mbedtls_x509_crt* ca_chain, mbedtls_x509_crl* ca_crl);
int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config* conf,
    mbedtls_x509_crt* own_cert, mbedtls_pk_context* pk_key);
void mbedtls_ssl_conf_dbg(mbedtls_ssl_config* conf,
    void (*f_dbg)(void*, int, const char*, int, const char*), void* p_dbg);

void mbedtls_ssl_init(mbedtls_ssl_context* ssl);
void mbedtls_ssl_free(mbedtls_ssl_context* ssl);
int mbedtls_ssl_setup(mbedtls_ssl_context* ssl, const mbedtls_ssl_config* conf);
int mbedtls_ssl_session_reset(mbedtls_ssl_context* ssl);
void mbedtls_ssl_set_bio(mbedtls_ssl_context* ssl, void* p_bio,
    mbedtls_ssl_send_t* f_send, mbedtls_ssl_recv_t* f_recv,
    mbedtls_ssl_recv_timeout_t* f_recv_timeout);
int mbedtls_ssl_set_hostname(mbedtls_ssl_context* ssl, const char* hostname);
int mbedtls_ssl_handshake(mbedtls_ssl_context* ssl);
uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context* ssl);
const char* mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context* ssl);
int mbedtls_ssl_read(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len);
int mbedtls_ssl_write(mbedtls_ssl_context* ssl,
    const unsigned char* buf, size_t len);
int mbedtls_ssl_close_notify(mbedtls_ssl_context* ssl);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_SSL_H */
