#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Reads cases.txt, for select.py and check.py.

import collections
import sys

EXPECT = ('pass', 'fail', 'notrun')

Case = collections.namedtuple('Case', 'group expect waits function')


def read(path):
    """Return {description: Case} from cases.txt, in file order."""
    cases = {}
    with open(path, encoding='ascii') as f:
        for num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split(None, 4)
            if len(fields) != 5 or fields[1] not in EXPECT:
                sys.exit('%s:%d: bad line' % (path, num))
            if fields[4] in cases:
                sys.exit('%s:%d: case listed twice' % (path, num))
            cases[fields[4]] = Case(*fields[:4])
    return cases
