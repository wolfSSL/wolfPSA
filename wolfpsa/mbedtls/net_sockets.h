/* net_sockets.h
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

#ifndef MBEDTLS_NET_SOCKETS_H
#define MBEDTLS_NET_SOCKETS_H

#include "mbedtls/ssl.h"

#include <stddef.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

#define MBEDTLS_NET_PROTO_TCP             0
#define MBEDTLS_NET_PROTO_UDP             1

#define MBEDTLS_ERR_NET_SOCKET_FAILED        -0x0042
#define MBEDTLS_ERR_NET_CONNECT_FAILED       -0x0044
#define MBEDTLS_ERR_NET_INVALID_CONTEXT      -0x0045
#define MBEDTLS_ERR_NET_BIND_FAILED          -0x0046
#define MBEDTLS_ERR_NET_LISTEN_FAILED        -0x0048
#define MBEDTLS_ERR_NET_ACCEPT_FAILED        -0x004A
#define MBEDTLS_ERR_NET_RECV_FAILED          -0x004C
#define MBEDTLS_ERR_NET_SEND_FAILED          -0x004E
#define MBEDTLS_ERR_NET_CONN_RESET           -0x0050
#define MBEDTLS_ERR_NET_UNKNOWN_HOST         -0x0052
#define MBEDTLS_ERR_NET_BUFFER_TOO_SMALL     PSA_ERROR_BUFFER_TOO_SMALL

#define MBEDTLS_NET_LISTEN_BACKLOG        10

typedef struct mbedtls_net_context {
    int fd;
} mbedtls_net_context;

void mbedtls_net_init(mbedtls_net_context* ctx);
int mbedtls_net_connect(mbedtls_net_context* ctx, const char* host,
    const char* port, int proto);
int mbedtls_net_bind(mbedtls_net_context* ctx, const char* bind_ip,
    const char* port, int proto);
int mbedtls_net_accept(mbedtls_net_context* bind_ctx,
    mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size,
    size_t* cip_len);
void mbedtls_net_usleep(unsigned long usec);
void mbedtls_net_close(mbedtls_net_context* ctx);
void mbedtls_net_free(mbedtls_net_context* ctx);
int mbedtls_net_recv(void* ctx, unsigned char* buf, size_t len);
int mbedtls_net_send(void* ctx, const unsigned char* buf, size_t len);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_NET_SOCKETS_H */
