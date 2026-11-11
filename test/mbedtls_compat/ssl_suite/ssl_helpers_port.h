/* ssl_helpers_port.h
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

/* In place of ssl_helpers_internal.h; TEST_SSL_INTERNALS is never defined */

#ifndef SSL_HELPERS_PORT_H
#define SSL_HELPERS_PORT_H

#include <test/ssl_helpers.h>
#include <test/macros.h>
#include <mbedtls/error.h>
#include <mbedtls/private/pk_private.h>

/* Fails the case where the port to the public API is not done yet */
#define NOT_PORTED(what) \
    mbedtls_test_fail("not ported: " what, __LINE__, __FILE__)

#endif /* SSL_HELPERS_PORT_H */
