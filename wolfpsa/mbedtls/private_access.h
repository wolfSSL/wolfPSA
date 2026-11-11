/* private_access.h
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

/* For code that marks private struct members, such as Mbed TLS's tests */

#ifndef MBEDTLS_PRIVATE_ACCESS_H
#define MBEDTLS_PRIVATE_ACCESS_H

#if defined(MBEDTLS_ALLOW_PRIVATE_ACCESS)
    #define MBEDTLS_PRIVATE(member) member
    #define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#else
    #define MBEDTLS_PRIVATE(member) private_##member
#endif /* MBEDTLS_ALLOW_PRIVATE_ACCESS */

#endif /* MBEDTLS_PRIVATE_ACCESS_H */
