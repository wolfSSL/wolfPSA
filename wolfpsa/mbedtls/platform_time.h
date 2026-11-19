/* platform_time.h
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

/* TF-PSA-Crypto time types and functions, mapped to the C library. */

#ifndef MBEDTLS_PLATFORM_TIME_H
#define MBEDTLS_PLATFORM_TIME_H

#include "tf-psa-crypto/build_info.h"

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

typedef time_t mbedtls_time_t;
typedef int64_t mbedtls_ms_time_t;

#define mbedtls_time time

/* With MBEDTLS_HAVE_TIME: monotonic, from an unspecified start */
mbedtls_ms_time_t mbedtls_ms_time(void);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_PLATFORM_TIME_H */
