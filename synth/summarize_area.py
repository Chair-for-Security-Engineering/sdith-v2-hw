#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng
"""Summarise the Vivado utilisation reports of synth/run_synth.sh.

Reads <dir>/<config>/sign_top_utilization_hier_full.rpt for every config
directory under the given results directory (default: synth/results) and
prints the area of sign_top (LUT, FF, BRAM, DSP, estimated slices) and its
breakdown per submodule. Config directory names follow
sec<1|3|5>_<fast|short>_hp<0|1>.

Usage:
  python3 synth/summarize_area.py [RESULTS_DIR] [--csv FILE]
"""

import argparse
import csv
import math
import os
import re
import sys

CONFIG_RE = re.compile(r'^sec([135])_(fast|short)_hp([01])$')
REPORT = 'sign_top_utilization_hier_full.rpt'


class Node:
    def __init__(self, name, module, vals):
        self.name = name
        self.module = module
        self.vals = vals          # dict: lut, ff, ramb36, ramb18, dsp
        self.children = []

    def child(self, pred):
        for c in self.children:
            if pred(c):
                return c
        return None


def _col(header, *names):
    for i, h in enumerate(header):
        if h in names:
            return i
    raise ValueError(f'column {names} not found in report header {header}')


def parse_hier_report(path):
    """Parse a hierarchical report_utilization file into a tree of Nodes."""
    header = None
    rows = []
    with open(path) as f:
        for line in f:
            if not line.startswith('|'):
                continue
            cells = line.rstrip('\n').split('|')[1:-1]
            if header is None:
                if cells and cells[0].strip() == 'Instance':
                    header = [c.strip() for c in cells]
                continue
            rows.append(cells)
    if header is None:
        raise ValueError(f'{path}: no "Instance" table found')

    i_lut = _col(header, 'Total LUTs')
    i_ff = _col(header, 'FFs')
    i_36 = _col(header, 'RAMB36')
    i_18 = _col(header, 'RAMB18')
    i_dsp = _col(header, 'DSP Blocks', 'DSP48 Blocks')

    def num(s):
        s = s.strip()
        return float(s) if s else 0.0

    root = None
    stack = []                    # (indent, node)
    for cells in rows:
        raw = cells[0]
        name = raw.strip()
        if name.startswith('('):  # "(inst)" rows hold the cell's own logic
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        node = Node(name, cells[1].strip(), {
            'lut': num(cells[i_lut]), 'ff': num(cells[i_ff]),
            'ramb36': num(cells[i_36]), 'ramb18': num(cells[i_18]),
            'dsp': num(cells[i_dsp]),
        })
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            stack[-1][1].children.append(node)
        elif root is None:
            root = node
        stack.append((indent, node))

    # A report scoped with -cells lists the root twice; use the inner one.
    while (root is not None and len(root.children) == 1
           and root.children[0].name == root.name):
        root = root.children[0]
    return root


def bram(v):
    return v['ramb36'] + v['ramb18'] / 2


def slices(v):
    """Slice estimate of Karl et al.: max(LUT/4, FF/8) + 212 BRAM + 135 DSP."""
    return (max(math.ceil(v['lut'] / 4), math.ceil(v['ff'] / 8))
            + 212 * bram(v) + 135 * v['dsp'])


def vsum(nodes):
    out = {'lut': 0, 'ff': 0, 'ramb36': 0, 'ramb18': 0, 'dsp': 0}
    for n in nodes:
        if n is None:
            continue
        for k in out:
            out[k] += n.vals[k]
    return out


def vsub(a, *bs):
    out = dict(a)
    for b in bs:
        for k in out:
            out[k] -= b[k]
    return out


def breakdown(root):
    """Group the hierarchy into the main submodules of the design."""
    kids = root.children
    aes = vsum([c for c in kids if c.name.startswith('gen_aes')])
    shake = vsum([c for c in kids if c.name.startswith('gen_shake')])
    mem = vsum([c for c in kids if c.name.startswith('md_')])
    dp_node = root.child(lambda c: c.name == 'u_blc_commit')
    dp = vsum([dp_node])
    leaf = vsum([dp_node.child(lambda c: c.module.startswith('get_leaf'))])
    piop_node = dp_node.child(lambda c: c.name == 'u_piop')
    piop = vsum([piop_node])
    proc_node = piop_node.child(lambda c: c.name == 'u_proc_pwit')
    proc = vsum([proc_node])
    mul = vsum([proc_node.child(lambda c: c.name == 'u_mul')])
    ore = vsum([dp_node.child(lambda c: c.name == 'u_ore')])
    blc = vsub(dp, leaf, piop, ore)
    wit = vsub(piop, proc)
    total = vsum([])
    for part in (aes, shake, mem, dp):
        for k in total:
            total[k] += part[k]
    return [
        ('Dual AES / Rijndael', aes),
        ('SHAKE / Keccak', shake),
        ('Memory Management', mem),
        ('Signing Datapath', dp),
        ('  GGM Tree Traversal', leaf),
        ('  BLC Commit', blc),
        ('  PIOP Prover', piop),
        ('    Witness Generation', wit),
        ('    PIOP Processing', proc),
        ('      GF(2^lambda) Multiplier', mul),
        ('  Open Random Evaluation', ore),
        ('Total (sum of rows)', total),
    ]


def config_key(name):
    m = CONFIG_RE.match(name)
    return (int(m.group(1)), m.group(2) == 'short', int(m.group(3)))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('results_dir', nargs='?',
                    default=os.path.join(here, 'results'))
    ap.add_argument('--csv', help='also write the main table to this CSV file')
    args = ap.parse_args()

    if not os.path.isdir(args.results_dir):
        sys.exit(f'no results directory: {args.results_dir}')

    configs = sorted((d for d in os.listdir(args.results_dir)
                      if CONFIG_RE.match(d)
                      and os.path.isfile(os.path.join(args.results_dir, d, REPORT))),
                     key=config_key)
    if not configs:
        sys.exit(f'no {REPORT} found under {args.results_dir}/sec*_*_hp*/')

    roots = {c: parse_hier_report(os.path.join(args.results_dir, c, REPORT))
             for c in configs}

    print(f'Results: {args.results_dir}\n')
    print('Area of sign_top (BRAM in RAMB36 equivalents)\n')
    hdr = (f'{"config":<15} {"LUT":>7} {"FF":>7} {"BRAM":>5} {"DSP":>4} '
           f'{"Slices":>7}')
    print(hdr)
    print('-' * len(hdr))
    rows = []
    for c in configs:
        v = roots[c].vals
        row = (int(v['lut']), int(v['ff']), bram(v), int(v['dsp']), int(slices(v)))
        print(f'{c:<15} {row[0]:>7} {row[1]:>7} {row[2]:>5g} {row[3]:>4} {row[4]:>7}')
        rows.append((c,) + row)

    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['config', 'lut', 'ff', 'bram', 'dsp', 'slices'])
            w.writerows(rows)
        print(f'\nCSV written to {args.csv}')

    print('\nArea per submodule\n')
    for c in configs:
        print(f'{c}:')
        print(f'  {"submodule":<30} {"LUT":>7} {"FF":>7} {"BRAM":>5} {"DSP":>4}')
        for label, v in breakdown(roots[c]):
            print(f'  {label:<30} {int(v["lut"]):>7} {int(v["ff"]):>7} '
                  f'{bram(v):>5g} {int(v["dsp"]):>4}')
        print()


if __name__ == '__main__':
    main()
