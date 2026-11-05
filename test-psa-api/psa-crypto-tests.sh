#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)
PSA_ARCH_TESTS_DIR="${SCRIPT_DIR}/psa-arch-tests"
PATCH_FILE="${SCRIPT_DIR}/psa-arch-tests_ec_overflow.patch"
TARGET_NAME="tgt_dev_apis_wolfpsa"
TARGET_SRC_DIR="${SCRIPT_DIR}/${TARGET_NAME}"
TARGET_DST_DIR="${PSA_ARCH_TESTS_DIR}/api-tests/platform/targets/${TARGET_NAME}"
PSA_INCLUDE_PATHS="${REPO_ROOT}/wolfpsa;${REPO_ROOT}/build/include"
PSA_CRYPTO_LIB_FILENAME="${REPO_ROOT}/libwolfpsa.a"
PSA_STORAGE_LIB_FILENAME=""
PSA_ARCH_TESTS_REPO=${PSA_ARCH_TESTS_REPO:-"https://github.com/ARM-software/psa-arch-tests.git"}
BUILD_DIR="${PSA_ARCH_TESTS_DIR}/api-tests/build-crypto"

if [[ -d "${PSA_ARCH_TESTS_DIR}" ]]; then
  git -C "${PSA_ARCH_TESTS_DIR}" clean -fdx
  git -C "${PSA_ARCH_TESTS_DIR}" reset --hard
else
  git clone "${PSA_ARCH_TESTS_REPO}" "${PSA_ARCH_TESTS_DIR}"
fi
git -C "${PSA_ARCH_TESTS_DIR}" submodule update --init --recursive --single-branch

if [[ ! -f "${PATCH_FILE}" ]]; then
  echo "Patch file not found: ${PATCH_FILE}" >&2
  exit 1
fi

if [[ ! -d "${TARGET_SRC_DIR}" ]]; then
  echo "Target directory not found: ${TARGET_SRC_DIR}" >&2
  echo "Create or copy ${TARGET_NAME} into ${SCRIPT_DIR} before running." >&2
  exit 1
fi

pushd "${PSA_ARCH_TESTS_DIR}" >/dev/null
patch -p1 --batch < "${PATCH_FILE}"
popd >/dev/null

rm -rf "${TARGET_DST_DIR}"
cp -R "${TARGET_SRC_DIR}" "${TARGET_DST_DIR}"

cmake -S "${PSA_ARCH_TESTS_DIR}/api-tests" -B "${BUILD_DIR}" \
  -DTARGET="${TARGET_NAME}" -DSUITE=CRYPTO \
  -DPSA_INCLUDE_PATHS="${PSA_INCLUDE_PATHS}" \
  -DTOOLCHAIN=HOST_GCC -DCPU_ARCH=armv8a \
  -DPSA_CRYPTO_LIB_FILENAME="${PSA_CRYPTO_LIB_FILENAME}" \
  -DPSA_STORAGE_LIB_FILENAME="${PSA_STORAGE_LIB_FILENAME}"

cmake --build "${BUILD_DIR}" -j4

"${BUILD_DIR}/psa-arch-tests-crypto"
