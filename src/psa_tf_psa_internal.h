/* psa_tf_psa_internal.h
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

#ifndef WOLFPSA_TF_PSA_INTERNAL_H
#define WOLFPSA_TF_PSA_INTERNAL_H

#include <stddef.h>

#include <wolfssl/wolfcrypt/types.h>
#include <mbedtls/pk.h>

/* MEMORY_E becomes PSA_ERROR_INSUFFICIENT_MEMORY, other errors become err */
WOLFSSL_LOCAL int wolfPSA_MbedRet(int wcRet, int err);

#if defined(MBEDTLS_FS_IO)
/* Loads path with the errors of Mbed TLS's mbedtls_pk_load_file(). Free *buf
 * with wolfPSA_MbedFreeFile() whatever the result. */
WOLFSSL_LOCAL int wolfPSA_MbedLoadFile(const char* path, unsigned char** buf,
    size_t* len);
WOLFSSL_LOCAL void wolfPSA_MbedFreeFile(unsigned char* buf, size_t len);
#endif /* MBEDTLS_FS_IO */

#endif /* WOLFPSA_TF_PSA_INTERNAL_H */
