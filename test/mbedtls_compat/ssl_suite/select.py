#!/usr/bin/env python3
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Writes test_suite_ssl_public.function and .data: the ssl suite's header, the
# test functions the cases in CASES need, and those cases, unchanged. Fails
# when CASES and Mbed TLS differ on the cases of those test functions, or on
# a case's test function.
#
# Usage: select.py CASES SUITES_DIR OUT_DIR (SUITES_DIR: the clone's
# tests/suites)

import os
import re
import sys

import cases

FUNCTION = 'test_suite_ssl.function'
DATA = ('test_suite_ssl.data', 'test_suite_ssl.tls-defrag.data')
OUT = 'test_suite_ssl_public'


def read_data(path):
    """Return [(description, function, text)] for each case in a .data."""
    out = []
    with open(path, encoding='latin-1') as f:
        blocks = re.split(r'\n\s*\n', f.read())
    for block in blocks:
        lines = [l for l in block.strip().split('\n')
                 if l.strip() and not l.startswith('#')]
        if len(lines) < 2:
            continue
        func = lines[-1].split(':', 1)[0]
        out.append((lines[0], func, '\n'.join(lines)))
    return out


def main():
    if len(sys.argv) != 4:
        sys.exit('Usage: select.py CASES SUITES_DIR OUT_DIR')
    cases_path, suites, out_dir = sys.argv[1:]
    listed = cases.read(cases_path)

    data = []
    for name in DATA:
        data += read_data(os.path.join(suites, name))
    with open(os.path.join(suites, FUNCTION), encoding='latin-1') as f:
        src = f.read()

    header = re.search(r'/\* BEGIN_HEADER \*/.*?/\* END_HEADER \*/\n',
                       src, re.S).group(0)
    deps = re.search(r'/\* BEGIN_DEPENDENCIES.*?END_DEPENDENCIES\n \*/\n',
                     src, re.S).group(0)
    bodies = {}
    for m in re.finditer(r'/\* BEGIN_CASE[^*]*\*/.*?/\* END_CASE \*/\n',
                         src, re.S):
        name = re.search(r'\nvoid\s+(\w+)\s*\(', m.group(0)).group(1)
        bodies[name] = m.group(0)

    upstream = {desc: func for desc, func, _ in data}
    listed_funcs = {func for desc, func, _ in data if desc in listed}
    errors = ['listed, not in Mbed TLS: ' + desc
              for desc in listed if desc not in upstream]
    errors += ['function is %s in Mbed TLS: %s' % (upstream[desc], desc)
               for desc, case in listed.items()
               if desc in upstream and case.function != upstream[desc]]
    errors += ['not listed: ' + desc for desc, func, _ in data
               if func in listed_funcs and desc not in listed]
    if errors:
        sys.exit('%s:\n  %s' % (cases_path, '\n  '.join(errors)))

    run = [(func, text) for desc, func, text in data
           if desc in listed and listed[desc].expect != 'notrun']
    funcs = {func for func, _ in run}
    todo = list(funcs)
    while todo:
        for called in re.findall(r'\btest_(\w+)\s*\(', bodies[todo.pop()]):
            if called in bodies and called not in funcs:
                funcs.add(called)
                todo.append(called)

    with open(os.path.join(out_dir, OUT + '.function'), 'w') as f:
        f.write(header + '\n' + deps)
        f.writelines('\n' + body for name, body in bodies.items()
                     if name in funcs)
    with open(os.path.join(out_dir, OUT + '.data'), 'w') as f:
        f.write('\n\n'.join(text for _, text in run) + '\n')


if __name__ == '__main__':
    main()
