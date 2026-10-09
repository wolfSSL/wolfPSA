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
#include <wolfssl/wolfcrypt/types.h>

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

#if (defined(WOLFSSL_RISCV_ASM) && \
     (defined(WOLFSSL_RISCV_SCALAR_CRYPTO_ASM) || \
      defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM))) || \
    defined(FREESCALE_LTC) || defined(FREESCALE_MMCAU) || \
    defined(WOLFSSL_SILABS_SE_ACCEL) || defined(WOLFSSL_PSOC6_CRYPTO) || \
    defined(WOLFSSL_AFALG) || defined(WOLFSSL_DEVCRYPTO_AES) || \
    defined(WOLFSSL_PIC32MZ_CRYPT) || defined(WOLFSSL_NRF51_AES) || \
    defined(WOLFSSL_SCE) || defined(HAVE_COLDFIRE_SEC) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
    #define WOLFPSA_AES_HW_BACKEND
#endif

/* The RISC-V crypto extensions run all of GCM in assembly, never the C GHASH. */
#undef WOLFPSA_GHASH_HW_BACKEND
#if defined(WOLFSSL_RISCV_ASM) && \
    (defined(WOLFSSL_RISCV_SCALAR_CRYPTO_ASM) || \
     defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM))
    #define WOLFPSA_GHASH_HW_BACKEND
#endif

#ifndef WOLFPSA_AES_FAST
#if defined(WOLFSSL_ARMASM)
#error "wolfPSA: the Arm AES assembly falls back to a T-table core and ignores WOLFSSL_AES_TOUCH_LINES. Define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED, to accept it."
#elif defined(WOLFSSL_PPC64_ASM) || defined(WOLFSSL_PPC32_ASM)
#error "wolfPSA: the PowerPC AES assembly falls back to a T-table core and ignores WOLFSSL_AES_TOUCH_LINES. Define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED, to accept it."
#elif defined(WOLFSSL_RISCV_ASM) && !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: the RISC-V assembly without the scalar or vector crypto extension uses a T-table AES and a branching GHASH. Define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED, to accept it."
#elif defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0) && \
    !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: FIPS modules before v6 have neither WC_AES_BITSLICED nor WOLFSSL_AES_TOUCH_LINES. Define WOLFPSA_AES_FAST, without either of them, to accept the T-table core."
#elif !defined(WC_AES_BITSLICED) && !defined(WOLFSSL_AES_TOUCH_LINES) && \
    !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: AES backend is not constant time. Select WC_AES_BITSLICED or WOLFSSL_AES_TOUCH_LINES, or define WOLFPSA_AES_FAST to accept the T-table core."
#endif

/* Only the 64-bit GHASH built with no GCM method set is masked; FIPS v5 masks
 * it only under AES_GCM_GMULT_CT, and FIPS v2 never does. */
#if defined(HAVE_AESGCM) && !defined(WOLFPSA_GHASH_HW_BACKEND)
#if defined(GCM_SMALL) || defined(GCM_WORD32) || defined(GCM_TABLE) || \
    defined(GCM_TABLE_4BIT) || defined(AES_GCM_GMULT_NCT)
#error "wolfPSA: GHASH is not constant time. Leave the GCM method unset and AES_GCM_GMULT_NCT undefined for the masked multiply (an LTC part without its GCM engine sets GCM_TABLE itself), or define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED."
#elif !defined(WORD64_AVAILABLE)
#error "wolfPSA: the masked GHASH needs a 64-bit type, and WORD64_AVAILABLE is off (NO_64BIT, or a 16-bit CPU). Remove NO_64BIT, or define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED, to accept the branching one."
#elif defined(HAVE_FIPS) && FIPS_VERSION3_LT(5,0,0)
#error "wolfPSA: FIPS v2 has no constant-time GHASH. Define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED, to accept it."
#elif defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0) && \
    !defined(AES_GCM_GMULT_CT)
#error "wolfPSA: FIPS v5 masks GHASH only under AES_GCM_GMULT_CT. Define it, or define WOLFPSA_AES_FAST, without WOLFSSL_AES_TOUCH_LINES or WC_AES_BITSLICED."
#endif
#endif /* HAVE_AESGCM && !WOLFPSA_GHASH_HW_BACKEND */
#endif /* !WOLFPSA_AES_FAST */

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

#endif /* WOLFPSA_CONFIG_H */
