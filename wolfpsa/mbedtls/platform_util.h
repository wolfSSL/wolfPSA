/* platform_util.h
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

#ifndef MBEDTLS_PLATFORM_UTIL_H
#define MBEDTLS_PLATFORM_UTIL_H

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
    #define MBEDTLS_DEPRECATED __attribute__((deprecated))
#else
    #define MBEDTLS_DEPRECATED
#endif /* MBEDTLS_DEPRECATED_WARNING */
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

#if !defined(MBEDTLS_CHECK_RETURN)
#if defined(__GNUC__)
    #define MBEDTLS_CHECK_RETURN __attribute__((__warn_unused_result__))
#elif defined(_MSC_VER) && _MSC_VER >= 1700
    #include <sal.h>
    #define MBEDTLS_CHECK_RETURN _Check_return_
#else
    #define MBEDTLS_CHECK_RETURN
#endif /* __GNUC__ */
#endif /* !MBEDTLS_CHECK_RETURN */

#define MBEDTLS_CHECK_RETURN_CRITICAL MBEDTLS_CHECK_RETURN
#if defined(MBEDTLS_CHECK_RETURN_WARNING)
    #define MBEDTLS_CHECK_RETURN_TYPICAL MBEDTLS_CHECK_RETURN
#else
    #define MBEDTLS_CHECK_RETURN_TYPICAL
#endif /* MBEDTLS_CHECK_RETURN_WARNING */
#define MBEDTLS_CHECK_RETURN_OPTIONAL

/* (void) alone does not silence GCC's warn_unused_result */
#if !defined(MBEDTLS_IGNORE_RETURN)
    #define MBEDTLS_IGNORE_RETURN(result) ((void)!(result))
#endif /* !MBEDTLS_IGNORE_RETURN */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Zero a buffer in a way the compiler does not remove. buf may be NULL when
 * len is 0. */
void mbedtls_platform_zeroize(void *buf, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MBEDTLS_PLATFORM_UTIL_H */
