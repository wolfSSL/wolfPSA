/* psa_config.h
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

/* Build-configuration policy shared by every wolfPSA translation unit.
 * Include this instead of <wolfssl/wolfcrypt/settings.h>: it pulls settings.h
 * in first, then applies the checks, so a partial build (one TU compiled on
 * its own) gets the same diagnostics as a full one. */

#ifndef WOLFPSA_CONFIG_H
#define WOLFPSA_CONFIG_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && !defined(NO_AES)

/* AES backends, none of which loads a table at a secret-dependent index:
 *
 *   WC_AES_BITSLICED         adds 15 * 16 * W words of W bits to Aes, where W
 *                            is WC_AES_BS_WORD_SIZE: 30 * W^2 bytes, 122,880
 *                            at W = 64 down to 1,920 at W = 8
 *   WOLFSSL_AES_TOUCH_LINES  every lookup touches each cache line of the
 *                            table; sizeof(Aes) is unchanged
 *   a hardware AES core      the list below, which compiles no software
 *                            tables. WOLFSSL_AESNI and WOLFSSL_ESP32_CRYPT
 *                            are absent: both keep the T-table core as a
 *                            runtime fallback
 *   WOLFPSA_AES_FAST         waives the check and accepts the T-table core:
 *                            faster, not constant time, not PSA compliant
 */

/* Internal marker, derived here and nowhere else: a definition arriving from
 * outside would otherwise satisfy the policy check below on any build. */
#undef WOLFPSA_AES_HW_BACKEND

#if defined(WOLFSSL_ARMASM) || defined(WOLFSSL_RISCV_ASM) || \
    defined(FREESCALE_LTC) || defined(FREESCALE_MMCAU) || \
    defined(WOLFSSL_SILABS_SE_ACCEL) || defined(WOLFSSL_PSOC6_CRYPTO) || \
    defined(WOLFSSL_AFALG) || defined(WOLFSSL_DEVCRYPTO_AES) || \
    defined(WOLFSSL_PIC32MZ_CRYPT) || defined(WOLFSSL_NRF51_AES) || \
    defined(WOLFSSL_SCE) || defined(HAVE_COLDFIRE_SEC) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
    #define WOLFPSA_AES_HW_BACKEND
#endif

#if !defined(WOLFPSA_AES_FAST) && !defined(WC_AES_BITSLICED) && \
    !defined(WOLFSSL_AES_TOUCH_LINES) && !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: AES backend is not constant time. Select WC_AES_BITSLICED or WOLFSSL_AES_TOUCH_LINES, or define WOLFPSA_AES_FAST to accept the T-table core."
#endif

#if defined(WOLFPSA_AES_FAST) && \
    (defined(WC_AES_BITSLICED) || defined(WOLFSSL_AES_TOUCH_LINES))
#error "wolfPSA: WOLFPSA_AES_FAST conflicts with WC_AES_BITSLICED/WOLFSSL_AES_TOUCH_LINES"
#endif

#endif /* WOLFSSL_PSA_ENGINE && !NO_AES */

/* PSA treats the hash as opaque bytes, but wolfcrypt/src/ecc.c rejects an
 * all-zero digest unless this is set, in a split build in libwolfssl too. */
#if defined(WOLFSSL_PSA_ENGINE) && defined(HAVE_ECC) \
    && !defined(WC_ALLOW_ECC_ZERO_HASH)
#error "wolfPSA needs WC_ALLOW_ECC_ZERO_HASH (psa_sign_hash/psa_verify_hash must accept an all-zero digest)"
#endif

/* Require init when using TRACK_MEMORY, or hardware crypto engines */
#if defined(WOLFSSL_PSA_ENGINE) && \
    ((defined(WOLFSSL_TRACK_MEMORY) && defined(USE_WOLFSSL_MEMORY) && \
      !defined(WOLFSSL_STATIC_MEMORY)) || \
     defined(WOLF_CRYPTO_CB) || defined(WOLFSSL_RENESAS_TSIP) || \
     defined(WOLFSSL_RENESAS_RX64_HASH) || defined(WOLFSSL_RENESAS_FSPSM) || \
     defined(WOLFSSL_PSOC6_CRYPTO) || defined(WOLFSSL_SILABS_SE_TYPES) || \
     defined(WOLFSSL_SCE) || defined(WOLFSSL_DEVCRYPTO) || \
     defined(WOLFSSL_CAAM) || defined(WOLFSSL_IMXRT_DCP) || \
     defined(WOLFSSL_NXP_HASHCRYPT) || defined(WOLFSSL_SE050_INIT))
    #define WOLFPSA_NEEDS_INIT
#endif /* WOLFSSL_PSA_ENGINE && (tracker, callbacks or hash engine) */

#endif /* WOLFPSA_CONFIG_H */
