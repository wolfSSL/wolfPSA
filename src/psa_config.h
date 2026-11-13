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
#include <wolfssl/version.h>

#if defined(WOLFSSL_PSA_ENGINE) && !defined(NO_AES)

/* AES backends, none of which loads a table at a secret-dependent index:
 *
 *   WC_AES_BITSLICED         adds 15 * 16 * W words of W bits to Aes, where W
 *                            is WC_AES_BS_WORD_SIZE: 30 * W^2 bytes, 122,880
 *                            at W = 64 down to 1,920 at W = 8
 *   WOLFSSL_AES_TOUCH_LINES  every lookup touches each cache line of the
 *                            table; sizeof(Aes) is unchanged
 *   a listed backend         the list below: hardware AES cores, the RISC-V
 *                            AES instructions and the AArch64 NEON core, none
 *                            with a table in memory. WOLFSSL_AESNI and
 *                            WOLFSSL_ESP32_CRYPT are absent: both keep the
 *                            T-table core as a runtime fallback
 *   WOLFPSA_AES_FAST         waives the check and accepts the T-table core:
 *                            faster, not constant time, not PSA compliant
 */

/* Internal marker, derived here and nowhere else: a definition arriving from
 * outside would otherwise satisfy the policy check below on any build. */
#undef WOLFPSA_AES_HW_BACKEND

/* FIPS v2 and v5 have no RISC-V AES, and the older port in v6 runs a branching
 * GHASH unless its carry-less multiply macros are also set. */
#undef WOLFPSA_RISCV_CRYPTO_CT
#if defined(WOLFSSL_RISCV_ASM) && \
    (defined(WOLFSSL_RISCV_SCALAR_CRYPTO_ASM) || \
     defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM)) && !defined(HAVE_FIPS)
    #define WOLFPSA_RISCV_CRYPTO_CT
#endif

/* The AArch64 NEON AES and GHASH keep their tables in registers. wolfSSL 5.9.0
 * added WOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP; no FIPS aes.c up to v6 has it. */
#undef WOLFPSA_ARM64_NEON_CT
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__) && \
    !defined(WOLFSSL_ARMASM_NO_NEON) && \
    defined(WOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP) && !defined(HAVE_FIPS) && \
    LIBWOLFSSL_VERSION_HEX >= 0x05009000
    #define WOLFPSA_ARM64_NEON_CT
#endif

/* wolfSSL after 5.9.4 (first to define WOLFSSL_AES_TABLE_SECTION) runs this
 * AES on the C touch-lines core; its GHASH stays on the table assembly. */
#undef WOLFPSA_ARM32_TOUCH_LINES_CT
#if defined(WOLFSSL_ARMASM) && !defined(__aarch64__) && \
    (defined(WOLFSSL_ARMASM_THUMB2) || \
     defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)) && \
    defined(WOLFSSL_AES_TOUCH_LINES) && !defined(HAVE_AESGCM) && \
    !defined(HAVE_FIPS) && (defined(WOLFSSL_AES_TABLE_SECTION) || \
    LIBWOLFSSL_VERSION_HEX > 0x05009004)
    #define WOLFPSA_ARM32_TOUCH_LINES_CT
#endif

/* Grouped by the FIPS aes.c that has them: every version, v5 on, none. */
#if defined(FREESCALE_LTC) || defined(FREESCALE_MMCAU) || \
    defined(WOLFSSL_PIC32MZ_CRYPT) || defined(WOLFSSL_NRF51_AES) || \
    defined(HAVE_COLDFIRE_SEC) || \
    ((!defined(HAVE_FIPS) || FIPS_VERSION3_GE(5,0,0)) && \
     (defined(WOLFSSL_SILABS_SE_ACCEL) || defined(WOLFSSL_AFALG) || \
      defined(WOLFSSL_DEVCRYPTO_AES) || defined(WOLFSSL_SCE))) || \
    (!defined(HAVE_FIPS) && \
     (defined(WOLFSSL_PSOC6_CRYPTO) || defined(WOLF_CRYPTO_CB_ONLY_AES))) || \
    defined(WOLFPSA_RISCV_CRYPTO_CT) || defined(WOLFPSA_ARM64_NEON_CT)
    #define WOLFPSA_AES_HW_BACKEND
#endif

/* These run GHASH in assembly, except GHASH() under GCM_SMALL on AArch64,
 * which keeps the branching C GMULT. */
#undef WOLFPSA_GHASH_HW_BACKEND
#if defined(WOLFPSA_RISCV_CRYPTO_CT) || \
    (defined(WOLFPSA_ARM64_NEON_CT) && !defined(GCM_SMALL))
    #define WOLFPSA_GHASH_HW_BACKEND
#endif

#ifndef WOLFPSA_AES_FAST
#if defined(WOLFSSL_ARMASM) && !defined(WOLFPSA_ARM64_NEON_CT) && \
    !defined(WOLFPSA_ARM32_TOUCH_LINES_CT)
#error "wolfPSA: the Arm AES assembly is not constant time: it falls back to T-table lookups, whose timing depends on the key and data. Outside FIPS, define WOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP on AArch64 with NEON on (wolfSSL 5.9.0 or later), or WOLFSSL_AES_TOUCH_LINES on 32-bit Thumb-2 or WOLFSSL_ARMASM_NO_HW_CRYPTO without AES-GCM (wolfSSL after 5.9.4); or define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif defined(WOLFSSL_PPC64_ASM) || defined(WOLFSSL_PPC32_ASM)
#error "wolfPSA: the PowerPC AES assembly is not constant time: it falls back to T-table lookups, whose timing depends on the key and data. Define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif defined(WOLFSSL_RISCV_ASM) && !defined(WOLFPSA_RISCV_CRYPTO_CT)
#error "wolfPSA: the RISC-V assembly is not constant time without the scalar or vector crypto extension, or in a FIPS module: it uses a T-table AES or a GHASH that branches on the key. Outside FIPS, define WOLFSSL_RISCV_SCALAR_CRYPTO_ASM or WOLFSSL_RISCV_VECTOR_CRYPTO_ASM if the CPU has one; or define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0) && \
    !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: AES in FIPS modules before v6 is not constant time: they have neither WC_AES_BITSLICED nor WOLFSSL_AES_TOUCH_LINES. Use a hardware AES backend, or define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif !defined(WC_AES_BITSLICED) && !defined(WOLFSSL_AES_TOUCH_LINES) && \
    !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: the AES backend is not constant time: the T-table core's timing depends on the key and data. Select WC_AES_BITSLICED (constant time, larger Aes) or WOLFSSL_AES_TOUCH_LINES (constant time, slower), or define WOLFPSA_AES_FAST to trade the timing leak for speed."
#endif

/* Only the 64-bit GHASH built with no GCM method set is masked; FIPS v5 masks
 * it only under AES_GCM_GMULT_CT, and FIPS v2 never does. */
#if defined(HAVE_AESGCM) && !defined(WOLFPSA_GHASH_HW_BACKEND)
#if defined(GCM_SMALL) || defined(GCM_WORD32) || defined(GCM_TABLE) || \
    defined(GCM_TABLE_4BIT) || defined(AES_GCM_GMULT_NCT)
#error "wolfPSA: GHASH is not constant time: GCM_SMALL and GCM_WORD32 branch on the hash key, and the GCM tables and AES_GCM_GMULT_NCT load from secret-indexed memory. Leave the GCM method unset and AES_GCM_GMULT_NCT undefined for the masked multiply (an LTC part without its GCM engine sets GCM_TABLE itself), or define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif !defined(WORD64_AVAILABLE)
#error "wolfPSA: GHASH is not constant time without a 64-bit type: WORD64_AVAILABLE is off (NO_64BIT, or a 16-bit CPU), so wolfCrypt uses a multiply that branches on the hash key. Remove NO_64BIT, or define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif defined(HAVE_FIPS) && FIPS_VERSION3_LT(5,0,0)
#error "wolfPSA: GHASH in FIPS v2 is not constant time. Define WOLFPSA_AES_FAST to trade the timing leak for speed."
#elif defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0) && \
    !defined(AES_GCM_GMULT_CT)
#error "wolfPSA: GHASH in FIPS v5 is constant time only under AES_GCM_GMULT_CT. Define it, or define WOLFPSA_AES_FAST to trade the timing leak for speed."
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
