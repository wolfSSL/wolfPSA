/* platform.h
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

/* TF-PSA-Crypto platform names, mapped to the C library. */

#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H

#include "tf-psa-crypto/build_info.h"

#include <stdio.h>
#include <stdlib.h>

#define mbedtls_calloc   calloc
#define mbedtls_free     free
#define mbedtls_printf   printf
#define mbedtls_fprintf  fprintf
#define mbedtls_snprintf snprintf
#define mbedtls_setbuf   setbuf
#define mbedtls_exit     exit

#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE

#endif /* MBEDTLS_PLATFORM_H */
