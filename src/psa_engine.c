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

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Runtime-settable devId threaded through every wolfPSA-internal
 * wc_*Init()/wc_NewRsaKey() call. WOLFPSA_DEVID_DEFAULT means wolfPSA
 * expresses no preference; keeping that state in the same variable means a
 * reader takes one atomic load and can never observe a half-updated pair.
 * Atomic because the setter may run while PSA operations are in flight on
 * other threads, and the load costs nothing next to the crypto it precedes.
 */
static wolfSSL_Atomic_Int wolfPSA_default_devid =
    WOLFSSL_ATOMIC_INITIALIZER(WOLFPSA_DEVID_DEFAULT);

int wolfPSA_SetDefaultDevID(int devId)
{
#ifndef WOLF_CRYPTO_CB
    /* The dispatch a real devId selects is compiled out of this library, so
     * accepting one would promise an offload that cannot happen. The two
     * values that ask for no offload stay valid. */
    if (devId != INVALID_DEVID && devId != WOLFPSA_DEVID_DEFAULT) {
        return NOT_COMPILED_IN;
    }
#endif

    WOLFSSL_ATOMIC_STORE(wolfPSA_default_devid, devId);
    return 0;
}

int wolfPSA_GetDefaultDevID(void)
{
    int devId = (int)WOLFSSL_ATOMIC_LOAD(wolfPSA_default_devid);

#ifdef WOLF_CRYPTO_CB
    /* Several wolfCrypt initializers pick a device themselves rather than
     * defaulting to INVALID_DEVID: the SHA-2 family through
     * wc_CryptoCb_DefaultDevID(), and wc_ecc_init or wc_InitCmac on CAAM
     * targets. Deferring to the same selection is what keeps those on the
     * behaviour they had before wolfPSA passed a devId. For the rest, whose
     * plain initializers do pin INVALID_DEVID, it widens the default from
     * local to whatever wolfCrypt selects, so that the whole library follows
     * one policy rather than splitting by algorithm. */
    if (devId == WOLFPSA_DEVID_DEFAULT) {
        return wc_CryptoCb_DefaultDevID();
    }
#else
    if (devId == WOLFPSA_DEVID_DEFAULT) {
        return INVALID_DEVID;
    }
#endif
    return devId;
}

int wolfPSA_RegisterCryptoCb(int devId, wolfPSA_CryptoCbFunc cb, void *ctx)
{
#ifdef WOLF_CRYPTO_CB
    return wc_CryptoCb_RegisterDevice(devId, cb, ctx);
#else
    (void)devId;
    (void)cb;
    (void)ctx;
    return NOT_COMPILED_IN;
#endif
}

int wolfPSA_UnRegisterCryptoCb(int devId)
{
#ifdef WOLF_CRYPTO_CB
    wc_CryptoCb_UnRegisterDevice(devId);
    return 0;
#else
    (void)devId;
    return NOT_COMPILED_IN;
#endif
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
        /* wc_RsaPrivateDecrypt() reports a failed unpad this way; the
         * verification paths translate it to INVALID_SIGNATURE themselves. */
        case RSA_PAD_E:
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
