/* mbedtls_compat_internal.h
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

/* Shared by mbedtls_compat.c and mbedtls_net.c. Not part of the public
 * API. */

#ifndef MBEDTLS_COMPAT_INTERNAL_H
#define MBEDTLS_COMPAT_INTERNAL_H

#include <stddef.h>
#include <wolfssl/wolfcrypt/visibility.h>

enum {
    MBED_IO_RECV = 0,
    MBED_IO_SEND = 1
};

/* I/O error code in one direction, toWolf from Mbed TLS to wolfSSL */
WOLFSSL_LOCAL int MbedIoErr(int code, int dir, int toWolf);
/* An I/O length as an int, at most max */
WOLFSSL_LOCAL int MbedIoLen(size_t len, int max);

#endif /* MBEDTLS_COMPAT_INTERNAL_H */
