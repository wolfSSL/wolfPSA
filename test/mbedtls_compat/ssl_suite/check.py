#!/usr/bin/env python3
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Prints what passes per group and what the rest waits on, then each case
# whose outcome differs from cases.txt, and exits 1 if there is one.
#
# Usage: check.py CASES OUTCOME

import collections
import sys

GROUPS = ('target', 'api', 'mock')


def main():
    if len(sys.argv) != 3:
        sys.exit('Usage: check.py CASES OUTCOME')
    cases_path, outcome_path = sys.argv[1:]

    cases = {}
    with open(cases_path, encoding='ascii') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                group, expect, waits, desc = line.split(None, 3)
                cases[desc.strip()] = (group, expect, waits)

    results = {}
    try:
        with open(outcome_path, encoding='latin-1') as f:
            for line in f:
                fields = line.rstrip('\n').split(';', 5)
                results[fields[3]] = (fields[4], fields[5])
    except FileNotFoundError:
        pass

    bad = []
    for desc, (result, reason) in results.items():
        if desc not in cases:
            bad.append('not in cases.txt: ' + desc)
        elif cases[desc][1] == 'notrun':
            bad.append('run, but marked notrun: ' + desc)
    for desc, (group, expect, waits) in cases.items():
        if expect == 'notrun':
            continue
        if desc not in results:
            bad.append('not run: ' + desc)
            continue
        result, reason = results[desc]
        if expect == 'pass' and result != 'PASS':
            bad.append('%s, expected pass: %s (%s)' % (result, desc, reason))
        elif expect == 'fail' and result == 'PASS':
            bad.append('PASS, expected fail: ' + desc)

    for group in GROUPS:
        run = [(d, c) for d, c in cases.items()
               if c[0] == group and c[1] != 'notrun']
        passed = sum(results.get(d, ('',))[0] == 'PASS' for d, _ in run)
        notrun = sum(c[0] == group and c[1] == 'notrun'
                     for c in cases.values())
        line = '  %-7s %d of %d pass' % (group, passed, len(run))
        print(line + (', %d not run' % notrun if notrun else ''))
        waits = collections.Counter(c[2] for _, c in run if c[1] == 'fail')
        if waits:
            print('          not yet: ' + ', '.join(
                '%s %d' % w for w in waits.most_common()))

    if bad:
        print('Not as in cases.txt:')
        print('\n'.join('  ' + b for b in bad))
        sys.exit(1)


if __name__ == '__main__':
    main()
