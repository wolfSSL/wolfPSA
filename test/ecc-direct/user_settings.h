/* user_settings.h
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

/* The Secure set with P-256 on wolfPSA's direct SP path in place of ecc.c. */
#ifndef WOLFPSA_ECC_DIRECT_USER_SETTINGS_H
#define WOLFPSA_ECC_DIRECT_USER_SETTINGS_H

#include "../secure-set/user_settings.h"

#undef WOLFSSL_ECDSA_DETERMINISTIC_K
#define WOLFSSL_HAVE_SP_ECC
#define ECC_USER_CURVES
#define NO_ECC192
#define NO_ECC224
#define NO_ECC384
#define NO_ECC521
#define WOLFPSA_ECC_SP_DIRECT

#endif /* WOLFPSA_ECC_DIRECT_USER_SETTINGS_H */
