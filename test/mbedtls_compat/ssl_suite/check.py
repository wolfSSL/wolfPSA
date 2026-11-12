#!/usr/bin/env python3
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Prints what passes per group and what the rest waits on, then each case
# whose outcome differs from cases.txt, and exits 1 if there is one.
# --all-pass: every case that runs must pass, as against Mbed TLS itself.
#
# Usage: check.py [--all-pass] CASES OUTCOME

import collections
import sys

import cases

GROUPS = ('target', 'api', 'mock')


def main():
    args = sys.argv[1:]
    all_pass = args[:1] == ['--all-pass']
    if all_pass:
        args = args[1:]
    if len(args) != 2:
        sys.exit('Usage: check.py [--all-pass] CASES OUTCOME')
    cases_path, outcome_path = args

    listed = cases.read(cases_path)
    if all_pass:
        listed = {desc: case._replace(expect='pass')
                  if case.expect == 'fail' else case
                  for desc, case in listed.items()}

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
        if desc not in listed:
            bad.append('not in cases.txt: ' + desc)
        elif listed[desc].expect == 'notrun':
            bad.append('run, but marked notrun: ' + desc)
    for desc, case in listed.items():
        if case.expect == 'notrun':
            continue
        if desc not in results:
            bad.append('not run: ' + desc)
            continue
        result, reason = results[desc]
        if case.expect == 'pass' and result != 'PASS':
            bad.append('%s, expected pass: %s (%s)' % (result, desc, reason))
        elif case.expect == 'fail' and result == 'PASS':
            bad.append('PASS, expected fail: ' + desc)

    for group in GROUPS:
        run = [(d, c) for d, c in listed.items()
               if c.group == group and c.expect != 'notrun']
        passed = sum(results.get(d, ('',))[0] == 'PASS' for d, _ in run)
        notrun = sum(c.group == group and c.expect == 'notrun'
                     for c in listed.values())
        line = '  %-7s %d of %d pass' % (group, passed, len(run))
        print(line + (', %d not run' % notrun if notrun else ''))
        waits = collections.Counter(c.waits for _, c in run
                                    if c.expect == 'fail')
        if waits:
            print('          not yet: ' + ', '.join(
                '%s %d' % w for w in waits.most_common()))

    if bad:
        print('Not as in cases.txt:')
        print('\n'.join('  ' + b for b in bad))
        sys.exit(1)


if __name__ == '__main__':
    main()
