#!/usr/bin/env python3
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Generate wolfpsa/psa/crypto_config_zephyr.h from the ACTUAL compiled wolfCrypt
# configuration, by preprocessing psa_want_probe.c with the same flags as the
# rest of the build. The result is the consumer-visible PSA_WANT_ surface:
# exactly the algorithm families wolfCrypt has enabled AND wolfPSA implements.
#
# Python (not shell) to fit the Zephyr build ecosystem, invoked via CMake's
# PYTHON_EXECUTABLE from wolfPSA's zephyr/CMakeLists.txt.
#
# Usage:
#   gen-crypto-config.py <out-header> <cc> <probe.c> [preprocessor flags...]
#
# The preprocessor flags must reproduce the build's wolfCrypt config -- at
# minimum -DWOLFSSL_USER_SETTINGS -DWOLFSSL_ZEPHYR, the wolfssl/wolfpsa include
# dirs, any -DWOLFSSL_SETTINGS_FILE, and -imacros <autoconf.h>.

import re
import subprocess
import sys

HEADER = """\
/* crypto_config_zephyr.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * GENERATED at build time by zephyr/gen/gen-crypto-config.py from the compiled
 * wolfCrypt configuration -- DO NOT EDIT and do not check in. It defines the
 * consumer-visible PSA_WANT_ surface (what wolfPSA exposes as the PSA API),
 * derived from the wolfCrypt features actually enabled in this build intersected
 * with what wolfPSA implements. wolfpsa/psa/crypto.h -> crypto_config.h includes
 * it under CONFIG_WOLFPSA, so PSA sizing macros (crypto_sizes.h) and consumer
 * PSA_WANT_-gated code track the real build.
 */

#ifndef WOLFPSA_CRYPTO_CONFIG_ZEPHYR_H
#define WOLFPSA_CRYPTO_CONFIG_ZEPHYR_H

"""

FOOTER = "\n#endif /* WOLFPSA_CRYPTO_CONFIG_ZEPHYR_H */\n"

EMIT_TAG = "__WPSA_EMIT__"
WANT_RE = re.compile(r"PSA_WANT_[A-Z0-9_]+")


def main(argv):
    if len(argv) < 4:
        sys.stderr.write(
            "usage: gen-crypto-config.py <out> <cc> <probe.c> [flags...]\n")
        return 2

    out_path, cc, probe = argv[1], argv[2], argv[3]
    flags = argv[4:]

    try:
        preprocessed = subprocess.run(
            [cc, "-E", "-P", *flags, probe],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True).stdout
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or "")
        sys.stderr.write("gen-crypto-config.py: preprocessing the probe failed\n")
        return 1

    # Collect PSA_WANT_ symbols from the surviving __WPSA_EMIT__ lines only.
    wants = sorted({
        match.group(0)
        for line in preprocessed.splitlines() if EMIT_TAG in line
        for match in WANT_RE.finditer(line)
    })

    if not wants:
        sys.stderr.write(
            "gen-crypto-config.py: probe produced no PSA_WANT symbols\n")
        return 1

    with open(out_path, "w") as out_file:
        out_file.write(HEADER)
        for want in wants:
            out_file.write("#define {} 1\n".format(want))
        out_file.write(FOOTER)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
