/* version.c
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

/* Mbed TLS 4.x version functions (MBEDTLS_COMPAT=1). */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <mbedtls/version.h>

#ifndef MBEDTLS_VERSION_C
    #error "The generated config needs MBEDTLS_VERSION_C"
#endif /* !MBEDTLS_VERSION_C */

/* The version the library was built with, which may differ from the headers' */
unsigned int mbedtls_version_get_number(void)
{
    return MBEDTLS_VERSION_NUMBER;
}

const char* mbedtls_version_get_string(void)
{
    return MBEDTLS_VERSION_STRING;
}

const char* mbedtls_version_get_string_full(void)
{
    return MBEDTLS_VERSION_STRING_FULL;
}

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
