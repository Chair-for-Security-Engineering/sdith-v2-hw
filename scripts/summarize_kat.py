#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng
"""Summarise sign_kat simulation logs.

Scans every *.log file in the given directory (default: results/kat), takes
the configuration from the file name (sec1_fast_hp0_...), and reports per
configuration the number of KAT entries that passed, the signing latency in
clock cycles and the cycles spent in each signing phase.

Usage:
  python3 scripts/summarize_kat.py [LOG_DIR]
"""

import glob
import os
import re
import statistics
import sys
from collections import defaultdict

CONFIGS = [f'sec{l}_{p}_hp{h}' for l in (1, 3, 5)
           for p in ('fast', 'short') for h in (0, 1)]

PHASES = [('DFS', 'Tree-cache population'), ('PHASE12', 'BLC h_aux'),
          ('HLINES', 'BLC h_lines'), ('PIOP', 'PIOP prover'),
          ('OPEN_RAND_EVAL', 'Open random evaluation')]

NAME_RE = re.compile(r'^s(?:ec)?([135])_(fast|short)_hp([01])')


def config_order(cfg):
    return CONFIGS.index(cfg) if cfg in CONFIGS else len(CONFIGS)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, 'results', 'kat')
    logs = sorted(glob.glob(os.path.join(log_dir, '*.log')))
    if not logs:
        sys.exit(f'no *.log files in {log_dir}')

    stats = defaultdict(lambda: {'run': set(), 'pass': set(), 'fail': set(),
                                 'cycles': [], 'phases': []})
    for path in logs:
        m = NAME_RE.match(os.path.basename(path))
        if not m:
            continue
        cfg = f'sec{m.group(1)}_{m.group(2)}_hp{m.group(3)}'
        s = stats[cfg]
        with open(path, errors='replace') as f:
            text = f.read()
        s['run'].update(int(k) for k in re.findall(r'KAT (\d+): seed=', text))
        s['pass'].update(int(k) for k in re.findall(r'KAT (\d+): PASS', text))
        s['fail'].update(int(k) for k in re.findall(r'KAT (\d+): FAIL', text))
        s['cycles'] += [int(c) for c in re.findall(r'sign COMPLETED in (\d+) cycles', text)]
        for line in re.findall(r'phase cycles: (.*)', text):
            s['phases'].append({k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', line)})

    if not stats:
        sys.exit(f'no logs named sec<L>_<fast|short>_hp<0|1>* in {log_dir}')

    print(f'Logs: {log_dir}\n')
    hdr = f'{"config":<15} {"KAT pass":>9} | {"Mcycles min":>11} {"mean":>7} {"max":>7}'
    print(hdr)
    print('-' * len(hdr))
    all_ok = True
    for cfg in sorted(stats, key=config_order):
        s = stats[cfg]
        n_run, n_pass = len(s['run']), len(s['pass'] - s['fail'])
        all_ok &= n_run > 0 and n_pass == n_run
        cyc = s['cycles']
        line = f'{cfg:<15} {n_pass:>4}/{n_run:<4} | '
        if cyc:
            line += (f'{min(cyc) / 1e6:>11.2f} {statistics.mean(cyc) / 1e6:>7.2f} '
                     f'{max(cyc) / 1e6:>7.2f}')
        elif not s['pass'] and not s['fail']:
            line += '(not finished)'
        else:
            line += '(no completed signature)'
        print(line)

    with_phases = [c for c in stats if stats[c]['phases']]
    if with_phases:
        print('\nCycles per signing phase (mean over the simulated signatures)\n')
        for cfg in sorted(with_phases, key=config_order):
            ph = stats[cfg]['phases']
            means = [statistics.mean(p.get(k, 0) for p in ph) for k, _ in PHASES]
            total = sum(means)
            print(f'{cfg} ({len(ph)} signature(s)):')
            for (_, label), mean in zip(PHASES, means):
                print(f'  {label:<24} {mean:>10.0f} {100 * mean / total:>6.1f} %')
            print()

    if not with_phases:
        print()
    print('All KAT entries passed.' if all_ok else
          'Some KAT entries FAILED or did not finish; see the logs.')
    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
