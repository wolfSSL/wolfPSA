/* version.h
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

/* The version macros are in build_info.h */

#ifndef MBEDTLS_VERSION_H
#define MBEDTLS_VERSION_H

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_VERSION_C)

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

unsigned int mbedtls_version_get_number(void);
const char* mbedtls_version_get_string(void);
const char* mbedtls_version_get_string_full(void);

#ifdef __cplusplus
    } /* extern "C" */
#endif /* __cplusplus */

#endif /* MBEDTLS_VERSION_C */

#endif /* MBEDTLS_VERSION_H */
