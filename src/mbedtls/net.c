/* net.c
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

/* Mbed TLS 4.x network API on wolfSSL's sockets (MBEDTLS_COMPAT=1). */

/* getaddrinfo() with -std=c99 */
#if defined(WOLFPSA_MBEDTLS_COMPAT) && !defined(_POSIX_C_SOURCE)
    #define _POSIX_C_SOURCE 200112L
#endif /* WOLFPSA_MBEDTLS_COMPAT && !_POSIX_C_SOURCE */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <mbedtls/net_sockets.h>
#if defined(MBEDTLS_SSL_TLS_C)
    #include <wolfssl/ssl.h>
    #include <wolfssl/wolfio.h>
#endif /* MBEDTLS_SSL_TLS_C */

/* The generated config has MBEDTLS_NET_C with TLS and wolfSSL's sockets */
#if defined(MBEDTLS_NET_C) != \
        (defined(MBEDTLS_SSL_TLS_C) && defined(USE_WOLFSSL_IO))
    #error "MBEDTLS_NET_C does not match MBEDTLS_SSL_TLS_C and USE_WOLFSSL_IO"
#endif /* MBEDTLS_NET_C != (MBEDTLS_SSL_TLS_C && USE_WOLFSSL_IO) */

#if defined(MBEDTLS_NET_C)

#include <limits.h>
#include "mbedtls_compat_internal.h"
#ifndef USE_WINDOWS_API
    #include <netdb.h>
    #include <signal.h>
    #include <sys/select.h>
#endif /* !USE_WINDOWS_API */

void mbedtls_net_init(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_init");

    if (ctx != NULL) {
        ctx->fd = -1;
    }
}

/* As in Mbed TLS: Winsock starts on first use and is not stopped, and a send
 * to a closed peer fails instead of ending the process. Returns 1 when
 * sockets can be used. */
static int MbedNetPrepare(void)
{
#ifdef USE_WINDOWS_API
    static int started = 0;
    WSADATA data;

    if (!started) {
        started = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
    }
    return started;
#else
    (void)signal(SIGPIPE, SIG_IGN);
    return 1;
#endif /* USE_WINDOWS_API */
}

static int MbedNetBind(int fd, const struct addrinfo* ai, int proto)
{
    int on = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on,
            (XSOCKLENT)sizeof(on)) != 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
    if (bind(fd, ai->ai_addr, (XSOCKLENT)ai->ai_addrlen) != 0) {
        return MBEDTLS_ERR_NET_BIND_FAILED;
    }
    if (proto == MBEDTLS_NET_PROTO_TCP &&
            listen(fd, MBEDTLS_NET_LISTEN_BACKLOG) != 0) {
        return MBEDTLS_ERR_NET_LISTEN_FAILED;
    }
    return 0;
}

/* Connects to host, or binds to it when server is set. A server with no
 * host binds to every address. */
static int MbedNetOpen(mbedtls_net_context* ctx, const char* host,
    const char* port, int proto, int server)
{
    struct addrinfo hints;
    struct addrinfo* list = NULL;
    struct addrinfo* ai;
    int ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;

    if (ctx == NULL || (host == NULL && !server) || port == NULL) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    XMEMSET(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (proto == MBEDTLS_NET_PROTO_UDP) {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else {
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }
    if (host == NULL) {
        hints.ai_flags = AI_PASSIVE;
    }

    if (!MbedNetPrepare()) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
    if (getaddrinfo(host, port, &hints, &list) != 0) {
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;
    }

    for (ai = list; ai != NULL; ai = ai->ai_next) {
        ctx->fd = (int)socket(ai->ai_family, ai->ai_socktype,
            ai->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }
        if (server) {
            ret = MbedNetBind(ctx->fd, ai, proto);
        }
        else if (connect(ctx->fd, ai->ai_addr,
                (XSOCKLENT)ai->ai_addrlen) == 0) {
            ret = 0;
        }
        else {
            ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
        }
        if (ret == 0) {
            break;
        }
        CloseSocket(ctx->fd);
        ctx->fd = -1;
    }

    freeaddrinfo(list);
    return ret;
}

int mbedtls_net_connect(mbedtls_net_context* ctx, const char* host,
    const char* port, int proto)
{
    WOLFSSL_ENTER("mbedtls_net_connect");

    return MbedNetOpen(ctx, host, port, proto, 0);
}

int mbedtls_net_bind(mbedtls_net_context* ctx, const char* bind_ip,
    const char* port, int proto)
{
    WOLFSSL_ENTER("mbedtls_net_bind");

    return MbedNetOpen(ctx, bind_ip, port, proto, 1);
}

/* The last socket call failed only because it would block */
static int MbedNetWouldBlock(void)
{
#ifdef USE_WINDOWS_API
    int err = WSAGetLastError();
#else
    int err = errno;
#endif /* USE_WINDOWS_API */

    return err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN;
}

/* TCP only. client_ip gets the 4 or 16 bytes of the client's address. */
int mbedtls_net_accept(mbedtls_net_context* bind_ctx,
    mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size,
    size_t* cip_len)
{
    struct sockaddr_storage addr;
    XSOCKLENT addrLen = (XSOCKLENT)sizeof(addr);
    const void* ip;
    size_t ipLen;

    WOLFSSL_ENTER("mbedtls_net_accept");

    if (bind_ctx == NULL || client_ctx == NULL || bind_ctx->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    client_ctx->fd = (int)accept(bind_ctx->fd, (struct sockaddr*)&addr,
        &addrLen);
    if (client_ctx->fd < 0) {
        return MbedNetWouldBlock() ? MBEDTLS_ERR_SSL_WANT_READ :
            MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }
    if (client_ip == NULL) {
        return 0;
    }

    if (addr.ss_family == AF_INET) {
        ip = &((struct sockaddr_in*)&addr)->sin_addr;
        ipLen = sizeof(struct in_addr);
    }
    else {
        ip = &((struct sockaddr_in6*)&addr)->sin6_addr;
        ipLen = sizeof(struct in6_addr);
    }
    *cip_len = ipLen;
    if (buf_size < ipLen) {
        return MBEDTLS_ERR_NET_BUFFER_TOO_SMALL;
    }
    XMEMCPY(client_ip, ip, ipLen);
    return 0;
}

void mbedtls_net_usleep(unsigned long usec)
{
    WOLFSSL_ENTER("mbedtls_net_usleep");

#ifdef USE_WINDOWS_API
    Sleep((DWORD)((usec + 999) / 1000));
#else
    struct timeval tv;

    tv.tv_sec = (time_t)(usec / 1000000);
    tv.tv_usec = (suseconds_t)(usec % 1000000);
    (void)select(0, NULL, NULL, NULL, &tv);
#endif /* USE_WINDOWS_API */
}

void mbedtls_net_close(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_close");

    if (ctx != NULL && ctx->fd >= 0) {
        CloseSocket(ctx->fd);
        ctx->fd = -1;
    }
}

/* Also ends the connection for a forked process that shares the socket */
void mbedtls_net_free(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_free");

    if (ctx != NULL && ctx->fd >= 0) {
        (void)shutdown(ctx->fd, 2);
    }
    mbedtls_net_close(ctx);
}

int mbedtls_net_recv(void* ctx, unsigned char* buf, size_t len)
{
    mbedtls_net_context* net = (mbedtls_net_context*)ctx;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_recv");

    if (net == NULL || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    ret = wolfIO_Recv(net->fd, (char*)buf, MbedIoLen(len, INT_MAX), 0);
    if (ret >= 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_RECV, 0);
}

int mbedtls_net_send(void* ctx, const unsigned char* buf, size_t len)
{
    mbedtls_net_context* net = (mbedtls_net_context*)ctx;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_send");

    if (net == NULL || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    ret = wolfIO_Send(net->fd, (char*)(wc_ptr_t)buf, MbedIoLen(len, INT_MAX),
        0);
    if (ret >= 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_SEND, 0);
}

#endif /* MBEDTLS_NET_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
