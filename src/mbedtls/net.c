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
#include <mbedtls/platform_time.h>
#include "mbedtls_compat_internal.h"
#ifndef USE_WINDOWS_API
    #include <fcntl.h>
    #include <netdb.h>
    #include <signal.h>
    #include <sys/select.h>
#endif /* !USE_WINDOWS_API */

/* A receive that does not block, where the system has one */
#ifdef MSG_DONTWAIT
    #define MBED_NET_DONTWAIT MSG_DONTWAIT
#else
    #define MBED_NET_DONTWAIT 0
#endif /* MSG_DONTWAIT */

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

static int MbedNetBind(int fd, const struct sockaddr* addr, XSOCKLENT addrLen,
    int proto)
{
    int on = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on,
            (XSOCKLENT)sizeof(on)) != 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
    if (bind(fd, addr, addrLen) != 0) {
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
            ret = MbedNetBind(ctx->fd, ai->ai_addr, (XSOCKLENT)ai->ai_addrlen,
                proto);
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

/* The error of the last socket call */
static int MbedNetError(void)
{
#ifdef USE_WINDOWS_API
    return WSAGetLastError();
#else
    return errno;
#endif /* USE_WINDOWS_API */
}

/* The last socket call failed only because it would block */
static int MbedNetWouldBlock(void)
{
    int err = MbedNetError();

    return err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN;
}

/* Waits for a datagram and leaves it queued */
static int MbedNetPeek(int fd, struct sockaddr_storage* addr,
    XSOCKLENT* addrLen)
{
    char peek[1];
    int ret;

    ret = (int)recvfrom(fd, peek, sizeof(peek), MSG_PEEK,
        (struct sockaddr*)addr, addrLen);
#ifdef USE_WINDOWS_API
    /* Only the first byte fits, which is enough */
    if (ret < 0 && WSAGetLastError() == WSAEMSGSIZE) {
        ret = 0;
    }
#endif /* USE_WINDOWS_API */
    return ret;
}

/* Gives the bound socket to the client and binds a new one for the next */
static int MbedNetUdpAccept(mbedtls_net_context* bind_ctx,
    mbedtls_net_context* client_ctx, const struct sockaddr_storage* addr,
    XSOCKLENT addrLen)
{
    struct sockaddr_storage local;
    XSOCKLENT localLen = (XSOCKLENT)sizeof(local);
    int fd;
#ifndef USE_WINDOWS_API
    int flags;
#endif /* !USE_WINDOWS_API */
    int ret = 0;

    /* Before connect() narrows an address such as 0.0.0.0 */
    if (getsockname(bind_ctx->fd, (struct sockaddr*)&local, &localLen) != 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
    if (connect(bind_ctx->fd, (const struct sockaddr*)addr, addrLen) != 0) {
        return MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }
    client_ctx->fd = bind_ctx->fd;
    bind_ctx->fd = -1;

    fd = (int)socket(local.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
#ifndef USE_WINDOWS_API
    /* Keeps the blocking mode, which Winsock cannot read */
    flags = fcntl(client_ctx->fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & O_NONBLOCK) != 0) {
        ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
#endif /* !USE_WINDOWS_API */
    if (ret == 0) {
        ret = MbedNetBind(fd, (const struct sockaddr*)&local, localLen,
            MBEDTLS_NET_PROTO_UDP);
    }
    if (ret == 0) {
        bind_ctx->fd = fd;
    }
    else {
        CloseSocket(fd);
    }
    return ret;
}

/* client_ip gets the 4 or 16 bytes of the client's address */
int mbedtls_net_accept(mbedtls_net_context* bind_ctx,
    mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size,
    size_t* cip_len)
{
    struct sockaddr_storage addr;
    XSOCKLENT addrLen = (XSOCKLENT)sizeof(addr);
    int type = 0;
    XSOCKLENT typeLen = (XSOCKLENT)sizeof(type);
    const void* ip;
    size_t ipLen;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_accept");

    if (bind_ctx == NULL || client_ctx == NULL || bind_ctx->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    if (getsockopt(bind_ctx->fd, SOL_SOCKET, SO_TYPE, (char*)&type,
            &typeLen) != 0 || (type != SOCK_STREAM && type != SOCK_DGRAM)) {
        return MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }

    if (type == SOCK_STREAM) {
        client_ctx->fd = (int)accept(bind_ctx->fd, (struct sockaddr*)&addr,
            &addrLen);
        ret = client_ctx->fd;
    }
    else {
        ret = MbedNetPeek(bind_ctx->fd, &addr, &addrLen);
    }
    if (ret < 0) {
        return MbedNetWouldBlock() ? MBEDTLS_ERR_SSL_WANT_READ :
            MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }
    if (type == SOCK_DGRAM) {
        ret = MbedNetUdpAccept(bind_ctx, client_ctx, &addr, addrLen);
        if (ret != 0) {
            return ret;
        }
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

/* 0 when ctx has a socket that select() takes */
static int MbedNetSelectable(const mbedtls_net_context* ctx)
{
    if (ctx == NULL || ctx->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
#ifndef USE_WINDOWS_API
    /* FD_SET() writes past an fd_set for a larger descriptor */
    if (ctx->fd >= FD_SETSIZE) {
        return MBEDTLS_ERR_NET_POLL_FAILED;
    }
#endif /* !USE_WINDOWS_API */
    return 0;
}

/* ms for a deadline. Without a clock, 0: each wait gets the whole timeout. */
static mbedtls_ms_time_t MbedNetNow(void)
{
#ifdef MBEDTLS_HAVE_TIME
    return mbedtls_ms_time();
#else
    return 0;
#endif /* MBEDTLS_HAVE_TIME */
}

/* Events of rw ready by deadline, no limit if forever; <0 on error */
static int MbedNetSelect(int fd, uint32_t rw, mbedtls_ms_time_t deadline,
    int forever)
{
    fd_set readFds;
    fd_set writeFds;
    struct timeval tv;
    mbedtls_ms_time_t left = deadline - MbedNetNow();
    uint32_t ms = (left > 0) ? (uint32_t)left : 0;
    int ret;

    FD_ZERO(&readFds);
    FD_ZERO(&writeFds);
    if ((rw & MBEDTLS_NET_POLL_READ) != 0) {
        FD_SET((SOCKET_T)fd, &readFds);
    }
    if ((rw & MBEDTLS_NET_POLL_WRITE) != 0) {
        FD_SET((SOCKET_T)fd, &writeFds);
    }
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    /* Winsock takes no empty set */
    ret = select(fd + 1,
        ((rw & MBEDTLS_NET_POLL_READ) != 0) ? &readFds : NULL,
        ((rw & MBEDTLS_NET_POLL_WRITE) != 0) ? &writeFds : NULL,
        NULL, forever ? NULL : &tv);
    if (ret > 0) {
        ret = 0;
        if (FD_ISSET(fd, &readFds)) {
            ret |= MBEDTLS_NET_POLL_READ;
        }
        if (FD_ISSET(fd, &writeFds)) {
            ret |= MBEDTLS_NET_POLL_WRITE;
        }
    }
    return ret;
}

/* A timeout of UINT32_MAX waits until an event comes */
int mbedtls_net_poll(mbedtls_net_context* ctx, uint32_t rw, uint32_t timeout)
{
    const mbedtls_ms_time_t deadline = MbedNetNow() + timeout;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_poll");

    ret = MbedNetSelectable(ctx);
    if (ret != 0) {
        return ret;
    }
    if (rw > (MBEDTLS_NET_POLL_READ | MBEDTLS_NET_POLL_WRITE)) {
        return MBEDTLS_ERR_NET_BAD_INPUT_DATA;
    }
    /* After a signal, the wait goes on to the same deadline */
    do {
        ret = MbedNetSelect(ctx->fd, rw, deadline, timeout == UINT32_MAX);
    } while (ret < 0 && MbedNetError() == SOCKET_EINTR);

    return (ret < 0) ? MBEDTLS_ERR_NET_POLL_FAILED : ret;
}

static int MbedNetSetNonBlock(mbedtls_net_context* ctx, int nonBlock)
{
#ifdef USE_WINDOWS_API
    u_long on = (u_long)nonBlock;
#else
    int flags;
#endif /* USE_WINDOWS_API */

    if (ctx == NULL || ctx->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
#ifdef USE_WINDOWS_API
    if (ioctlsocket(ctx->fd, FIONBIO, &on) != 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
#else
    flags = fcntl(ctx->fd, F_GETFL);
    if (flags < 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
    flags = nonBlock ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (fcntl(ctx->fd, F_SETFL, flags) != 0) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }
#endif /* USE_WINDOWS_API */
    return 0;
}

int mbedtls_net_set_block(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_set_block");

    return MbedNetSetNonBlock(ctx, 0);
}

int mbedtls_net_set_nonblock(mbedtls_net_context* ctx)
{
    WOLFSSL_ENTER("mbedtls_net_set_nonblock");

    return MbedNetSetNonBlock(ctx, 1);
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

static int MbedNetRecv(const mbedtls_net_context* net, unsigned char* buf,
    size_t len, int flags)
{
    int ret;

    if (net == NULL || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    ret = wolfIO_Recv(net->fd, (char*)buf, MbedIoLen(len, INT_MAX), flags);
    if (ret >= 0) {
        return ret;
    }
    return MbedIoErr(ret, MBED_IO_RECV, 0);
}

int mbedtls_net_recv(void* ctx, unsigned char* buf, size_t len)
{
    WOLFSSL_ENTER("mbedtls_net_recv");

    return MbedNetRecv((const mbedtls_net_context*)ctx, buf, len, 0);
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

/* Waits for data even on a non-blocking socket, without a limit for 0 */
int mbedtls_net_recv_timeout(void* ctx, unsigned char* buf, size_t len,
    uint32_t timeout)
{
    const mbedtls_net_context* net = (const mbedtls_net_context*)ctx;
    const mbedtls_ms_time_t deadline = MbedNetNow() + timeout;
    int ret;

    WOLFSSL_ENTER("mbedtls_net_recv_timeout");

    ret = MbedNetSelectable(net);
    if (ret != 0) {
        return ret;
    }
    do {
        ret = MbedNetSelect(net->fd, MBEDTLS_NET_POLL_READ, deadline,
            timeout == 0);
        if (ret == 0) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        if (ret < 0) {
            return (MbedNetError() == SOCKET_EINTR) ?
                MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
        }
        /* Readable can still have no data, as on Linux: wait again */
        ret = MbedNetRecv(net, buf, len, MBED_NET_DONTWAIT);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ);

    return ret;
}

#endif /* MBEDTLS_NET_C */

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
