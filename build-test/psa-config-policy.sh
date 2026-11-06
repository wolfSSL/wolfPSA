#!/bin/sh
#
# Preprocess src/psa_config.h against a wolfSSL tree and check which AES and
# GHASH configurations it accepts and refuses.
#
# Usage: build-test/psa-config-policy.sh [WOLFSSL_PATH]

set -u

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
wolfssl="${1:-${repo_root}/../wolfssl}"
cc="${CC:-cc}"
fails=0

# wolfcrypt/fips.h ships only with a FIPS bundle; an empty one lets the
# HAVE_FIPS cases preprocess against a plain wolfSSL tree.
stub="$(mktemp -d)"
trap 'rm -rf "${stub}"' EXIT
mkdir -p "${stub}/wolfssl/wolfcrypt"
: > "${stub}/wolfssl/wolfcrypt/fips.h"

# check <"pass" | fragment of the expected wolfPSA #error> [-DFLAG ...]
check() {
    want="$1"
    shift
    out="$(echo '#include "psa_config.h"' | "${cc}" -x c -fsyntax-only \
            -I"${repo_root}/build-test" -I"${repo_root}/src" -I"${stub}" \
            -I"${wolfssl}" \
            -DWOLFSSL_USER_SETTINGS -DHAVE_AESGCM -DHAVE_AES_ECB "$@" - 2>&1)"
    rc=$?
    if [ "${want}" = "pass" ]; then
        [ "${rc}" -eq 0 ] && ok=1 || ok=0
    else
        case "${out}" in
            *"wolfPSA: ${want}"*) ok=1 ;;
            *) ok=0 ;;
        esac
    fi
    if [ "${ok}" -eq 1 ]; then
        echo "ok    $*"
    else
        echo "FAIL  expected '${want}':  $*"
        echo "${out}" | grep -m3 "error"
        fails=$((fails + 1))
    fi
}

ghash="GHASH is not constant time:"
nobs="-DWOLFPSA_NO_AES_BITSLICED"
hwaes="-DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_ONLY_AES"
# Backends that every FIPS aes.c, FIPS v5 on, and none of them carry.
hwall="-DWOLFSSL_PIC32MZ_CRYPT"
hwv5="-DWOLFSSL_DEVCRYPTO_AES"
hwnofips="-DWOLFSSL_PSOC6_CRYPTO"
fips2="-DHAVE_FIPS -DHAVE_FIPS_VERSION=2 -DHAVE_FIPS_VERSION_MAJOR=2"
fips5="-DHAVE_FIPS -DHAVE_FIPS_VERSION=5 -DHAVE_FIPS_VERSION_MAJOR=5"
fips6="-DHAVE_FIPS -DHAVE_FIPS_VERSION=6 -DHAVE_FIPS_VERSION_MAJOR=6"
neon="-DWOLFSSL_ARMASM -D__aarch64__ -DWOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP"
a32="-DWOLFSSL_ARMASM -U__aarch64__ -DWOLFSSL_AES_TOUCH_LINES"
t2="${a32} -DWOLFSSL_ARMASM_THUMB2"
nohw="${a32} -DWOLFSSL_ARMASM_NO_HW_CRYPTO"
nogcm="-UHAVE_AESGCM"
if grep -q WC_AES_TOUCH_LINES_C_CORE "${wolfssl}/wolfcrypt/src/aes.c"; then
    a32_nogcm="pass"
else
    a32_nogcm="the Arm AES assembly"
fi

check pass
check pass ${nobs} -DWOLFSSL_AES_TOUCH_LINES
check pass ${nobs} ${hwaes}
check "the AES backend is not constant time" ${nobs}
check "the AES backend is not constant time" ${nobs} -DWOLFPSA_AES_HW_BACKEND
check "${ghash}" ${nobs} ${hwaes} -DGCM_TABLE
check "${ghash}" -DGCM_SMALL
check "${ghash}" -DGCM_WORD32
check "${ghash}" -DGCM_TABLE
check "${ghash}" -DGCM_TABLE -DWOLFPSA_GHASH_HW_BACKEND
check "${ghash}" -DGCM_TABLE_4BIT
check "${ghash}" -DAES_GCM_GMULT_NCT
check "GHASH is not constant time without a 64-bit type" -DNO_64BIT
check "the Arm AES assembly" -DWOLFSSL_ARMASM
check pass ${nobs} ${neon}
check pass ${nobs} ${neon} -DGCM_TABLE_4BIT
check pass ${nobs} ${neon} -DGCM_TABLE
check "the Arm AES assembly" ${nobs} ${neon} -U__aarch64__
check "the Arm AES assembly" ${nobs} ${neon} -DWOLFSSL_ARMASM_NO_NEON
check "the Arm AES assembly" ${nobs} ${neon} ${fips6}
check "the Arm AES assembly" ${nobs} -DWOLFSSL_ARMASM -DWOLFPSA_ARM64_NEON_CT
check "${ghash}" ${nobs} ${neon} -DGCM_SMALL
check "${a32_nogcm}" ${nobs} ${t2} ${nogcm}
check "${a32_nogcm}" ${nobs} ${nohw} ${nogcm}
check "the Arm AES assembly" ${nobs} ${t2}
check "the Arm AES assembly" ${nobs} ${nohw}
check "the Arm AES assembly" ${nobs} ${t2} ${nogcm} ${fips6}
check "the Arm AES assembly" ${nobs} ${t2} ${nogcm} -UWOLFSSL_AES_TOUCH_LINES
check "the Arm AES assembly" ${nobs} ${a32} ${nogcm}
check "the Arm AES assembly" ${nobs} ${t2} ${nogcm} -D__aarch64__
check "the Arm AES assembly" ${nobs} -DWOLFSSL_ARMASM -U__aarch64__ \
    -DWOLFPSA_ARM32_TOUCH_LINES_CT ${nogcm}
check "the PowerPC AES assembly" -DWOLFSSL_PPC64_ASM
check "the PowerPC AES assembly" -DWOLFSSL_PPC32_ASM
check "the RISC-V assembly" -DWOLFSSL_RISCV_ASM
check "the RISC-V assembly" ${nobs} ${hwaes} -DWOLFSSL_RISCV_ASM
check "the RISC-V assembly" -DWOLFSSL_RISCV_ASM -DWOLFPSA_RISCV_CRYPTO_CT
check pass ${nobs} -DWOLFSSL_RISCV_ASM -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM
check pass ${nobs} -DWOLFSSL_RISCV_ASM -DWOLFSSL_RISCV_VECTOR_CRYPTO_ASM
check pass ${nobs} -DWOLFSSL_RISCV_ASM -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM \
    -DGCM_TABLE_4BIT
check pass ${nobs} ${hwnofips}

check "AES in FIPS modules before v6" ${fips5}
check "GHASH in FIPS v2 is not constant time" ${fips2} ${nobs} ${hwall}
check "AES in FIPS modules before v6" ${fips2} ${nobs} ${hwv5}
check "GHASH in FIPS v5 is constant time only under" ${fips5} ${nobs} ${hwv5}
check pass ${fips5} ${nobs} ${hwv5} -DAES_GCM_GMULT_CT
check "AES in FIPS modules before v6" ${fips5} ${nobs} ${hwaes} \
    -DAES_GCM_GMULT_CT
check pass ${fips6}
check pass ${fips6} ${nobs} ${hwv5}
check "the AES backend is not constant time" ${fips6} ${nobs} ${hwaes}
check "the RISC-V assembly" ${fips5} ${nobs} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM -DAES_GCM_GMULT_CT
check "the RISC-V assembly" ${fips6} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_VECTOR_CRYPTO_ASM
check pass -DWOLFPSA_AES_FAST ${fips2}
check pass -DWOLFPSA_AES_FAST ${fips5}

# WOLFPSA_AES_FAST waives each of the refusals above.
for flag in GCM_SMALL GCM_WORD32 GCM_TABLE GCM_TABLE_4BIT AES_GCM_GMULT_NCT \
            NO_64BIT WOLFSSL_ARMASM WOLFSSL_PPC64_ASM WOLFSSL_PPC32_ASM \
            WOLFSSL_RISCV_ASM; do
    check pass -DWOLFPSA_AES_FAST "-D${flag}"
done

[ "${fails}" -eq 0 ]
