/* psa_output.h
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

#ifndef WOLFPSA_OUTPUT_H
#define WOLFPSA_OUTPUT_H

#include <stddef.h>

#include <psa/crypto.h>

static inline void wolfpsa_clear_length(size_t* length)
{
    if (length != NULL) {
        *length = 0;
    }
}

static inline void wolfpsa_clear_key_id(psa_key_id_t* key)
{
    if (key != NULL) {
        *key = PSA_KEY_ID_NULL;
    }
}

#endif /* WOLFPSA_OUTPUT_H */
