#!/usr/bin/env bash
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and run every wolfPSA Zephyr sample and test on native_sim, reporting a
# pass/fail summary and exiting non-zero on any failure. Used by CI
# (.github/workflows/zephyr-4.x.yml, via .github/scripts/zephyr-4.x/zephyr-test.sh)
# and handy locally.
#
# Must be invoked from inside a west workspace that has the Zephyr RTOS, the
# wolfSSL module, and the mbedtls module (the latter defines the
# PSA_CRYPTO_PROVIDER choice wolfPSA plugs into). The wolfPSA module itself is
# added via EXTRA_ZEPHYR_MODULES, so no manifest entry is required.
#
# Env:
#   BOARD             board/qualifier (default native_sim/native/64)
#   BUILD_ROOT        where build dirs go (default: $PWD/build-wolfpsa-ci)
#   EXTRA_MODULE_ARG  CMake arg to locate the wolfPSA module. Defaults to
#                     -DEXTRA_ZEPHYR_MODULES=<repo root> (for workspaces where
#                     wolfPSA is NOT in the west manifest). Set it to "" when
#                     wolfPSA is already a manifest module (e.g. CI, where
#                     zephyr-test.sh injects it into the manifest), to avoid
#                     registering it twice.

set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# repo root is two levels up: .github/scripts/ -> repo root
WOLFPSA_ROOT=$(CDPATH= cd -- "${script_dir}/../.." && pwd)
BOARD="${BOARD:-native_sim/native/64}"
BUILD_ROOT="${BUILD_ROOT:-${PWD}/build-wolfpsa-ci}"
EXTRA_MODULE_ARG="${EXTRA_MODULE_ARG--DEXTRA_ZEPHYR_MODULES=${WOLFPSA_ROOT}}"

# name | app path | mode(ztest|sample) | extra west-build args (optional)
#
# psa_consumer_st reruns the consumer with CONFIG_WOLFPSA_THREAD_SAFE=n so the
# single-threaded baseline path (SINGLE_THREADED, no-op lock macros) is built
# and run in CI, not just the default thread-safe (=y) path.
TARGETS="
psa_smoke|${WOLFPSA_ROOT}/zephyr/samples/psa_smoke|sample
psa_consumer|${WOLFPSA_ROOT}/zephyr/tests/psa_consumer|ztest
psa_consumer_st|${WOLFPSA_ROOT}/zephyr/tests/psa_consumer|ztest|-DCONFIG_WOLFPSA_THREAD_SAFE=n
psa_concurrency|${WOLFPSA_ROOT}/zephyr/tests/psa_concurrency|ztest
psa_entropy|${WOLFPSA_ROOT}/zephyr/tests/psa_entropy|ztest
psa_transform|${WOLFPSA_ROOT}/zephyr/tests/psa_transform|ztest
psa_purge|${WOLFPSA_ROOT}/zephyr/tests/psa_purge|ztest
psa_secure_storage|${WOLFPSA_ROOT}/zephyr/tests/psa_secure_storage|ztest
psa_store_unavailable|${WOLFPSA_ROOT}/zephyr/tests/psa_store_unavailable|ztest
psa_tls_coexist|${WOLFPSA_ROOT}/zephyr/tests/psa_tls_coexist|ztest
psa_its|${WOLFPSA_ROOT}/zephyr/tests/psa_its|sample
psa_persistent_key|${WOLFPSA_ROOT}/zephyr/tests/psa_persistent_key|sample
"

mkdir -p "${BUILD_ROOT}"

rc=0
printf '%-16s %-8s %s\n' "TARGET" "BUILD" "RESULT"
printf '%-16s %-8s %s\n' "------" "-----" "------"

while IFS='|' read -r name app mode extra; do
    [ -z "${name}" ] && continue
    bdir="${BUILD_ROOT}/${name}"
    if ! west build -p always -b "${BOARD}" -d "${bdir}" "${app}" \
            -- ${EXTRA_MODULE_ARG} ${extra} \
            > "${bdir}.build.log" 2>&1; then
        printf '%-16s %-8s %s\n' "${name}" "FAIL" "(build failed; see ${bdir}.build.log)"
        rc=1
        continue
    fi
    # native_sim block-buffers piped stdout; stdbuf forces line buffering so the
    # (kernel-idle-looping) sample still flushes before the timeout kill.
    timeout 120 stdbuf -oL -eL "${bdir}/zephyr/zephyr.exe" > "${bdir}.run.log" 2>&1
    if [ "${mode}" = ztest ]; then
        if grep -q "PROJECT EXECUTION SUCCESSFUL" "${bdir}.run.log" && \
           ! grep -q "PROJECT EXECUTION FAILED" "${bdir}.run.log"; then
            printf '%-16s %-8s %s\n' "${name}" "ok" "PASS"
        else
            printf '%-16s %-8s %s\n' "${name}" "ok" "FAIL (see ${bdir}.run.log)"
            rc=1
        fi
    else
        if grep -q "ALL PSA SMOKE TESTS PASSED" "${bdir}.run.log" || \
           grep -q "Sample finished successfully." "${bdir}.run.log"; then
            printf '%-16s %-8s %s\n' "${name}" "ok" "PASS"
        else
            printf '%-16s %-8s %s\n' "${name}" "ok" "FAIL (see ${bdir}.run.log)"
            rc=1
        fi
    fi
done <<EOF
${TARGETS}
EOF

echo ""
[ "${rc}" -eq 0 ] && echo "ALL wolfPSA ZEPHYR TARGETS PASSED" || echo "SOME wolfPSA ZEPHYR TARGETS FAILED"
exit "${rc}"
