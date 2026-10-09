#!/bin/sh
#
# Check that src/psa_config.h accepts and refuses the AES and GHASH
# configurations it should, by preprocessing it against the sibling wolfSSL.
# build-test/user_settings.h is the config, so WOLFPSA_NO_AES_BITSLICED can
# take the constant-time AES core away.
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

# check <expected outcome> [-DFLAG ...]
# The outcome is "pass", or a fragment of the wolfPSA #error the build must
# stop on, so a failure for any other reason does not count.
check() {
    want="$1"
    shift
    out="$(echo '#include "psa_config.h"' | "${cc}" -x c -fsyntax-only \
            -I"${repo_root}/build-test" -I"${repo_root}/src" -I"${wolfssl}" \
            -I"${stub}" \
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

ghash="GHASH is not constant time"
nobs="-DWOLFPSA_NO_AES_BITSLICED"
hwaes="-DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_ONLY_AES"
fips2="-DHAVE_FIPS -DHAVE_FIPS_VERSION=2 -DHAVE_FIPS_VERSION_MAJOR=2"
fips5="-DHAVE_FIPS -DHAVE_FIPS_VERSION=5 -DHAVE_FIPS_VERSION_MAJOR=5"
fips6="-DHAVE_FIPS -DHAVE_FIPS_VERSION=6 -DHAVE_FIPS_VERSION_MAJOR=6"

check pass
check pass ${nobs} -DWOLFSSL_AES_TOUCH_LINES
check pass ${nobs} ${hwaes}
check "AES backend is not constant time" ${nobs}
check "AES backend is not constant time" ${nobs} -DWOLFPSA_AES_HW_BACKEND
check "${ghash}" ${nobs} ${hwaes} -DGCM_TABLE
check "${ghash}" -DGCM_SMALL
check "${ghash}" -DGCM_WORD32
check "${ghash}" -DGCM_TABLE
check "${ghash}" -DGCM_TABLE -DWOLFPSA_GHASH_HW_BACKEND
check "${ghash}" -DGCM_TABLE_4BIT
check "${ghash}" -DAES_GCM_GMULT_NCT
check "the masked GHASH needs a 64-bit type" -DNO_64BIT
check "the Arm AES assembly" -DWOLFSSL_ARMASM
check "the PowerPC AES assembly" -DWOLFSSL_PPC64_ASM
check "the PowerPC AES assembly" -DWOLFSSL_PPC32_ASM
check "the RISC-V assembly" -DWOLFSSL_RISCV_ASM
check pass -DWOLFSSL_RISCV_ASM -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM
check pass -DWOLFSSL_RISCV_ASM -DWOLFSSL_RISCV_VECTOR_CRYPTO_ASM
check pass -DWOLFSSL_RISCV_ASM -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM -DGCM_TABLE_4BIT

check "FIPS modules before v6" ${fips5}
check "FIPS v2 has no constant-time GHASH" ${fips2} ${nobs} ${hwaes}
check "FIPS v5 masks GHASH only under" ${fips5} ${nobs} ${hwaes}
check pass ${fips5} ${nobs} ${hwaes} -DAES_GCM_GMULT_CT
check pass ${fips6}
check pass -DWOLFPSA_AES_FAST ${fips2}
check pass -DWOLFPSA_AES_FAST ${fips5}

# WOLFPSA_AES_FAST waives each of the refusals above.
for flag in GCM_SMALL GCM_WORD32 GCM_TABLE GCM_TABLE_4BIT AES_GCM_GMULT_NCT \
            NO_64BIT WOLFSSL_ARMASM WOLFSSL_PPC64_ASM WOLFSSL_PPC32_ASM \
            WOLFSSL_RISCV_ASM; do
    check pass -DWOLFPSA_AES_FAST "-D${flag}"
done

[ "${fails}" -eq 0 ]
