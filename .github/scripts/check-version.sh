#!/usr/bin/env bash
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Check that the release version strings match wolfpsa/wolfpsa_version.h.
# Run from anywhere; exits non-zero if any of them disagrees.

set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0

err() {
    echo "error: $*" >&2
    fail=1
}

ver=$(sed -nE 's/^#define LIBWOLFPSA_VERSION_STRING "([^"]*)".*/\1/p' \
    wolfpsa/wolfpsa_version.h)
hex=$(sed -nE 's/^#define LIBWOLFPSA_VERSION_HEX (0x[0-9A-Fa-f]+).*/\1/p' \
    wolfpsa/wolfpsa_version.h)

num='(0|[1-9][0-9]*)'
if ! [[ "$ver" =~ ^$num\.$num\.$num$ ]]; then
    echo "error: wolfpsa/wolfpsa_version.h: LIBWOLFPSA_VERSION_STRING" \
        "'$ver' is not X.Y.Z" >&2
    exit 1
fi
want_hex=$(printf '0x%02d%03d%03d' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
    "${BASH_REMATCH[3]}")
if [ "$(echo "$hex" | tr 'A-F' 'a-f')" != "$want_hex" ]; then
    err "wolfpsa/wolfpsa_version.h: LIBWOLFPSA_VERSION_HEX is '$hex'," \
        "expected $want_hex"
fi

echo "wolfPSA version: $ver"

delim='[:space:]`"'"'"'()<>,;'
tag="v[0-9][^$delim]*[^$delim.:]"

# check FILE DESCRIPTION PREFIX: each PREFIX<tag> in FILE must be PREFIXv$ver
check() {
    local file=$1 what=$2 prefix=$3 found m
    found=$(grep -oE "$prefix$tag" "$file" || true)
    if [ -z "$found" ]; then
        err "$file: no $what found"
        return
    fi
    while IFS= read -r m; do
        m=${m#"${m%%v[0-9]*}"}
        if [ "$m" != "v$ver" ]; then
            err "$file: $what is $m, expected v$ver"
        fi
    done <<< "$found"
}

latest=$(grep -E '^## ' CHANGELOG.md | grep -m1 -viE '^## \[?unreleased' \
    || true)
if [ "${latest%% (*}" != "## v$ver" ]; then
    err "CHANGELOG.md: latest release heading is '$latest', expected v$ver"
fi
check zephyr/module.yml "PURL" \
    '^[[:space:]]*- ["'"'"']?pkg:github/wolfssl/wolfpsa@'
check README.md "wolfPSA version" 'wolfPSA '

if [ "${GITHUB_REF_TYPE:-}" = "tag" ] && [ "${GITHUB_REF_NAME:-}" != "v$ver" ]
then
    err "tag ${GITHUB_REF_NAME:-} does not match version v$ver"
fi

exit $fail
