/* psa_engine.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Runtime-settable devId threaded through every wolfPSA-internal
 * wc_*Init()/wc_NewRsaKey() call. INVALID_DEVID (the default) keeps
 * the original behaviour: wolfCrypt runs the operation locally. */
static int wolfPSA_default_devid = INVALID_DEVID;

int wolfPSA_SetDefaultDevID(int devId)
{
    wolfPSA_default_devid = devId;
    return 0;
}

int wolfPSA_GetDefaultDevID(void)
{
    return wolfPSA_default_devid;
}

/* wolfCrypt error code to PSA status code conversion */
psa_status_t wc_error_to_psa_status(int ret)
{
    psa_status_t status;

    if (ret == 0) {
        return PSA_SUCCESS;
    }

    switch (ret) {
        case NOT_COMPILED_IN:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        case BAD_FUNC_ARG:
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case ECC_BAD_ARG_E:
        case ECC_CURVE_OID_E:
        case ECC_PRIV_KEY_E:
        case ECC_OUT_OF_RANGE_E:
        case ECC_PRIVATEONLY_E:
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case BUFFER_E:
        case RSA_BUFFER_E:
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            break;
        case MEMORY_E:
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
            break;
        case WC_HW_E:
            status = PSA_ERROR_HARDWARE_FAILURE;
            break;
        case SIG_VERIFY_E:
            status = PSA_ERROR_INVALID_SIGNATURE;
            break;
        case AES_GCM_AUTH_E:
        case AES_CCM_AUTH_E:
        case AES_EAX_AUTH_E:
        case AES_SIV_AUTH_E:
        case MAC_CMP_FAILED_E:
            status = PSA_ERROR_INVALID_SIGNATURE;
            break;
        case RNG_FAILURE_E:
            status = PSA_ERROR_INSUFFICIENT_ENTROPY;
            break;
        case BAD_PADDING_E:
            status = PSA_ERROR_INVALID_PADDING;
            break;
        case BAD_STATE_E:
            status = PSA_ERROR_BAD_STATE;
            break;
        default:
            status = PSA_ERROR_GENERIC_ERROR;
            break;
    }

    return status;
}

#endif /* WOLFSSL_PSA_ENGINE */
