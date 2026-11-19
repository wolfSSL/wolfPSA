#!/bin/sh
#
# Build a wolfPSA variant with a baseline set of wolfcrypt-native defines,
# optionally modified by lane-specific +/- tokens.
#
# Usage: build-variant.sh <lane-name> [modifier ...]
#
# A modifier is one of:
#   +FLAG          add -DFLAG to the compile flags
#   +FLAG=VALUE    add -DFLAG=VALUE
#   -FLAG          remove -DFLAG (or -DFLAG=...) from the baseline
#
# The baseline below must list every wolfcrypt-native knob wolfPSA needs for
# a full build. Keep the names in sync with wolfssl/wolfcrypt/settings.h.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
variant_name=${1:?usage: build-variant.sh <lane-name> [modifier ...]}
shift

# Baseline — every feature enabled. Listed one per line for easy grep/edit.
BASELINE="
WOLFSSL_SP_MATH_ALL
WOLFSSL_HAVE_SP_RSA
WOLFSSL_HAVE_SP_ECC
HAVE_SP_ECC
WOLFSSL_KEY_GEN
WC_NO_HARDEN
HAVE_ECC
HAVE_ECC_KEY_EXPORT
HAVE_ECC_KEY_IMPORT
WOLFSSL_ECDSA_DETERMINISTIC_K
WC_RSA_PSS
WOLFSSL_PSS_SALT_LEN_DISCOVER
WOLFSSL_RSA_OAEP
WOLFSSL_SP_1024
RSA_MIN_SIZE=1024
WOLFSSL_SP_384
HAVE_ECC384
WOLFSSL_HAVE_PRF
HAVE_HKDF
HAVE_ECC_ENCRYPT
HAVE_PBKDF2
WOLFSSL_MD5
WOLFSSL_RIPEMD
WOLFSSL_SHA224
WOLFSSL_SHA384
WOLFSSL_SHA512
WOLFSSL_SHA3
WOLFSSL_SHAKE128
WOLFSSL_SHAKE256
WOLFSSL_DES3
WOLFSSL_DES_ECB
HAVE_AESGCM
WOLFSSL_AESGCM_STREAM
HAVE_AESCCM
HAVE_AES_ECB
WOLFSSL_AES_COUNTER
WOLFSSL_AES_CFB
WOLFSSL_AES_OFB
WOLFSSL_CMAC
HAVE_CHACHA
HAVE_POLY1305
HAVE_CURVE25519
HAVE_ED25519
WOLFSSL_ED25519_STREAMING_VERIFY
HAVE_CURVE448
HAVE_ED448
WOLFSSL_ED448_STREAMING_VERIFY
WOLFSSL_HAVE_MLDSA
WOLFSSL_HAVE_MLKEM
WOLFSSL_HAVE_LMS
WOLFSSL_LMS_VERIFY_ONLY
WOLFSSL_HAVE_XMSS
WOLFSSL_XMSS_VERIFY_ONLY
WOLFSSL_EXPERIMENTAL_SETTINGS
HAVE_ASCON
WOLFSSL_AES_DIRECT
HAVE_AES_KEYWRAP
HAVE_XCHACHA
HAVE_CMAC_KDF
"

flags="${BASELINE}"

for mod in "$@"; do
    case "${mod}" in
        +*)
            token=${mod#+}
            flags="${flags}
${token}"
            ;;
        -*)
            name=${mod#-}
            # Drop any line that is either exactly "name" or "name=...".
            flags=$(printf '%s\n' "${flags}" | awk -v n="${name}" '
                $0 == n { next }
                index($0, n "=") == 1 { next }
                { print }')
            ;;
        *)
            printf 'build-variant.sh: unknown modifier %s\n' "${mod}" >&2
            exit 2
            ;;
    esac
done

cppflags="-DWOLFSSL_USER_SETTINGS"
for tok in ${flags}; do
    [ -z "${tok}" ] && continue
    cppflags="${cppflags} -D${tok}"
done

# BUILD_TARGET lets a lane compile only part of the library (e.g.
# psa-objects for a configuration the bundled wolfCrypt sources do not
# support).
target="${BUILD_TARGET:-libwolfpsa.a}"

make -C "${repo_root}" clean BUILD_DIR="${repo_root}/build-test/out/${variant_name}" >/dev/null
make -C "${repo_root}" \
    BUILD_DIR="${repo_root}/build-test/out/${variant_name}" \
    USER_SETTINGS_PATH="${repo_root}/build-test" \
    WOLFSSL_CPPFLAGS="${cppflags}" \
    "${target}"
