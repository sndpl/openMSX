#!/usr/bin/env python3
"""Fit the openMSX command-engine timing model to the 2026 logic-analyzer set.

Usage:
    2026-measurement-check.py <path-to-vdp-timing-measurements>/part2/5.slots

Reads the annotated access traces from
<https://github.com/m9710797/vdp-timing-measurements> and, for every
command-engine step (e.g. HMMM's write -> next read), reports which values of
the openMSX 'Delta' would reproduce *every* observed access.

The model under test is exactly the one openMSX implements:

    next access = the first VRAM access slot at or after (previous access +
                  delta), where delta = 'command engine work' + 'request
                  arbitration latency'

For a single observed pair (previous access at p, next access at n) that model
is satisfied by every delta in [prevSlot(n) - p + 1, n - p]; intersecting those
intervals over all observations of one step gives its admissible band.

See 2026-measurement-analysis.md for the conclusions.
"""
from __future__ import annotations

import argparse
import collections
import glob
import os
import re
import sys

TICKS = 1368                # VDP cycles per display line
DUMMY_CODE, DUMMY_ADDR = 'R..', 0x1FFFF   # the VDP's dummy read
CPU_CODES = ('R.r', 'W.w')  # CPU read / write
VRAM_LINE = 128             # bytes per VRAM line in screen 5

# --------------------------------------------------------------------------
# Access slot tables.
#
# Same tables as src/video/VDPAccessSlots.cc, but in the measurement's cycle
# numbering, which is openMSX + 1.  Two slots per table differ from the values
# derived from the 2013 measurements (see part2/README.md of the measurement
# repository): dispOff 1325 -> 1326 and 1335 -> 1336, sprOff 1323 -> 1324 and
# 1333 -> 1334.  With those corrections the tables reproduce the measured slot
# histograms exactly (154 / 88 / 31 slots).
# --------------------------------------------------------------------------
SLOTS_DISP_OFF = [
       1,    9,   17,   25,   33,   41,   49,   57,   65,   73,
      81,   89,   97,  105,  113,  121,  165,  173,  181,  189,
     197,  205,  213,  221,  229,  237,  245,  253,  261,  269,
     277,  293,  301,  309,  317,  325,  333,  341,  349,  357,
     365,  373,  381,  389,  397,  405,  421,  429,  437,  445,
     453,  461,  469,  477,  485,  493,  501,  509,  517,  525,
     533,  549,  557,  565,  573,  581,  589,  597,  605,  613,
     621,  629,  637,  645,  653,  661,  677,  685,  693,  701,
     709,  717,  725,  733,  741,  749,  757,  765,  773,  781,
     789,  805,  813,  821,  829,  837,  845,  853,  861,  869,
     877,  885,  893,  901,  909,  917,  933,  941,  949,  957,
     965,  973,  981,  989,  997, 1005, 1013, 1021, 1029, 1037,
    1045, 1061, 1069, 1077, 1085, 1093, 1101, 1109, 1117, 1125,
    1133, 1141, 1149, 1157, 1165, 1173, 1189, 1197, 1205, 1213,
    1221, 1229, 1269, 1277, 1285, 1293, 1301, 1309, 1317, 1326,
    1336, 1345, 1353, 1361,
]
SLOTS_SPR_OFF = [
       7,   15,   23,   31,   39,   47,   55,   63,   71,   79,
      87,   95,  103,  111,  119,  163,  171,  183,  189,  215,
     221,  247,  253,  279,  311,  317,  343,  349,  375,  381,
     407,  439,  445,  471,  477,  503,  509,  535,  567,  573,
     599,  605,  631,  637,  663,  695,  701,  727,  733,  759,
     765,  791,  823,  829,  855,  861,  887,  893,  919,  951,
     957,  983,  989, 1015, 1021, 1047, 1079, 1085, 1111, 1117,
    1143, 1149, 1175, 1207, 1213, 1267, 1275, 1283, 1291, 1299,
    1307, 1315, 1324, 1334, 1343, 1351, 1359, 1367,
]
SLOTS_SPR_ON = [
      29,   93,  163,  171,  189,  221,  253,  317,  349,  381,
     445,  477,  509,  573,  605,  637,  701,  733,  765,  829,
     861,  893,  957,  989, 1021, 1085, 1117, 1149, 1213, 1265,
    1331,
]
TABLES = {'dispOff': SLOTS_DISP_OFF, 'sprOff': SLOTS_SPR_OFF,
          'sprOn': SLOTS_SPR_ON}

# VRAM accesses per pixel/byte step, and the role of each
ROLES = {
    'hmmv': ('W',),
    'lmmv': ('R', 'W'),
    'ymmm': ('R', 'W'),
    'hmmm': ('R', 'W'),
    'line': ('R', 'W'),
    'lmmm': ('Rs', 'Rd', 'W'),
}

# 'noCpu' traces that do contain CPU accesses, i.e. the filename does not match
# what was measured.  They are the only source of the mid-line inconsistencies,
# so they are excluded from the no-CPU fit.
MISLABELLED = {
    'scr5-dispOff-hmmv-noCpu-nx2-6d.txt',
    'scr5-dispOff-lmmv-noCpu-nx2-3d.txt',
    'scr5-dispOff-ymmm-noCpu-nx12-1d.txt',
    'scr5-sprOff-lmmm-noCpu-nx2-3d.txt',
    'scr5-sprOff-lmmv-noCpu-nx8-5d.txt',
}

# The values openMSX uses, for comparison
OPENMSX = {
    ('hmmv', 'W->W'): 48,  ('hmmv', 'newline'): 104,
    ('lmmv', 'R->W'): 24,  ('lmmv', 'W->R'): 72,  ('lmmv', 'newline'): 134,
    ('ymmm', 'R->W'): 24,  ('ymmm', 'W->R'): 38,  ('ymmm', 'newline'): 104,
    ('hmmm', 'R->W'): 24,  ('hmmm', 'W->R'): 64,  ('hmmm', 'newline'): 128,
    ('lmmm', 'Rd->W'): 24, ('lmmm', 'Rs->Rd'): 32, ('lmmm', 'W->Rs'): 64,
    ('lmmm', 'newline'): 128,
    ('line', 'R->W'): 24,  ('line', 'W->R'): 88,  ('line', 'newline'): 120,
}
OPENMSX_SPR_ON = {   # sprites-on specific values
    ('lmmm', 'Rs->Rd'): 48,
    ('hmmm', 'newline'): 134,
    ('lmmm', 'newline'): 134,
}


def parse(path):
    """Return [(absolute_time, code, address)], ordered in time.

    The files are laid out with one row per cycle-within-a-line and one column
    per display line, so absolute time is 1368 * column + row.
    """
    items = []
    with open(path) as f:
        for ln in f:
            if ':' not in ln:
                continue
            row, rest = ln.rstrip('\n').split(':', 1)
            t = int(row)
            col = 0
            while rest:
                cell = rest[2:13]
                if cell.strip():
                    items.append((TICKS * col + t, cell[0:3], int(cell[6:11], 16)))
                rest = rest[13:]
                col += 1
    items.sort()
    return items


def meta(path):
    m = re.match(r'scr5-(\w+)-(\w+)-(\w+?)(?:-nx\d+)?-\d+[a-z]?\.txt$',
                 os.path.basename(path))
    if not m:
        return None
    return {'mode': m[1], 'cmd': m[2], 'cpu': m[3],
            'name': os.path.basename(path)}


def transitions(path):
    """Yield (step_name, prev_time, next_time) for one trace."""
    info = meta(path)
    if info is None or info['cmd'] not in ROLES:
        return
    roles = ROLES[info['cmd']]
    acc = [a for a in parse(path) if a[1] not in CPU_CODES]
    # The VDP's dummy read shows up as an unclassified read of 0x1ffff. A few
    # traces happen to have a command source pointer walking through the top of
    # VRAM, so only treat 0x1ffff as a dummy when no other command access in
    # the trace is anywhere near it.
    real = any(a[2] != DUMMY_ADDR and abs(a[2] - DUMMY_ADDR) < 0x400
               for a in acc)
    eng = [a for a in acc
           if real or (a[1], a[2]) != (DUMMY_CODE, DUMMY_ADDR)]
    writes = [i for i, a in enumerate(eng) if a[1][0] == 'W']
    groups = []
    for a, b in zip(writes, writes[1:]):
        grp = eng[a + 1:b + 1]
        if len(grp) == len(roles) and \
                tuple(x[1][0] for x in grp) == tuple(r[0] for r in roles):
            groups.append(grp)
    for gi, grp in enumerate(groups):
        for i in range(len(grp) - 1):
            yield f'{roles[i]}->{roles[i + 1]}', grp[i][0], grp[i + 1][0]
        if gi + 1 < len(groups):
            nxt = groups[gi + 1]
            if (nxt[-1][2] // VRAM_LINE) == (grp[-1][2] // VRAM_LINE):
                yield f'{roles[-1]}->{roles[0]}', grp[-1][0], nxt[0][0]
            elif 0 < nxt[-1][2] - grp[-1][2] <= 2 * VRAM_LINE:
                yield 'newline', grp[-1][0], nxt[0][0]
            # else: the command restarted, no useful constraint


def next_slot(table, t, delta):
    """First access slot at or after t + delta."""
    line, off = divmod(t + delta, TICKS)
    for s in table:
        if s >= off:
            return line * TICKS + s
    return (line + 1) * TICKS + table[0]


def prev_slot(table, t):
    """Largest access slot strictly before t."""
    line, off = divmod(t, TICKS)
    best = [s for s in table if s < off]
    return line * TICKS + best[-1] if best else (line - 1) * TICKS + table[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('slots_dir', help='part2/5.slots of the measurement repo')
    ap.add_argument('--cpu', action='store_true',
                    help='use the rdCpu/wrCpu traces and test the arbitration')
    args = ap.parse_args()

    pattern = '*Cpu-*.txt' if args.cpu else '*-noCpu*.txt'
    files = sorted(glob.glob(os.path.join(args.slots_dir, 'scr5-' + pattern)))
    if not files:
        sys.exit(f'no traces found in {args.slots_dir}')

    if args.cpu:
        check_arbitration(files)
        return

    obs = collections.defaultdict(list)
    for f in files:
        info = meta(f)
        if info['name'] in MISLABELLED:
            continue
        for step, p, n in transitions(f):
            obs[(info['cmd'], step, info['mode'])].append((p, n))

    print(f'{len(files)} traces, {sum(len(v) for v in obs.values())} '
          f'engine-to-engine transitions\n')
    print(f'{"cmd":5} {"step":9} {"mode":8} {"n":>6}  {"admissible delta":18} '
          f'{"openMSX":>7} {"misses":>7}')
    print('-' * 72)
    combined = collections.defaultdict(dict)
    total_miss = [0]
    for key in sorted(obs, key=lambda k: (k[0], k[1], k[2])):
        cmd, step, mode = key
        table = TABLES[mode]
        lo, hi = 1, 400
        for p, n in obs[key]:
            lo = max(lo, prev_slot(table, n) - p + 1)
            hi = min(hi, n - p)
        combined[(cmd, step)][mode] = (lo, hi)
        d = OPENMSX_SPR_ON.get((cmd, step)) if mode == 'sprOn' else None
        d = d or OPENMSX[(cmd, step)]
        miss = sum(1 for p, n in obs[key] if next_slot(table, p, d) != n)
        band = f'[{lo},{hi}]' + ('  inconsistent' if lo > hi else '')
        print(f'{cmd:5} {step:9} {mode:8} {len(obs[key]):6}  {band:18} '
              f'{d:7} {miss:7}')
        total_miss[0] += miss
    n = sum(len(v) for v in obs.values())
    print(f'\nopenMSX mispredicts {total_miss[0]} of {n} transitions '
          f'({100.0 * total_miss[0] / n:.2f}%)')
    print('\nvalues that work in all three modes:')
    for key in sorted(combined):
        v = combined[key]
        lo = max(x[0] for x in v.values())
        hi = min(x[1] for x in v.values())
        nlo = max(v[m][0] for m in ('dispOff', 'sprOff'))
        nhi = min(v[m][1] for m in ('dispOff', 'sprOff'))
        slo, shi = v['sprOn']
        if lo <= hi:
            note = ''
        elif nlo <= nhi and slo <= shi:
            note = f'   sprites-on needs [{slo},{shi}], the others [{nlo},{nhi}]'
        else:
            note = '   no single value; see the per-mode rows above'
        print(f'  {key[0]:5} {key[1]:9} [{lo},{hi}]{note}')


def check_arbitration(files):
    """Does the engine take the first slot at/after its minimum that the CPU
    did not take?  That is what openMSX's stealAccessSlot() implements."""
    total = contended = wrong = late = 0
    for f in files:
        info = meta(f)
        if info is None or info['cmd'] not in ROLES:
            continue
        table = TABLES[info['mode']]
        cpu = {a[0] for a in parse(f) if a[1] in CPU_CODES}
        for step, p, n in transitions(f):
            key = (info['cmd'], step)
            d = (OPENMSX_SPR_ON.get(key) if info['mode'] == 'sprOn' else None) \
                or OPENMSX[key]
            first = next_slot(table, p, d)
            t = first
            while t in cpu:
                t = next_slot(table, t, 1)
            total += 1
            contended += (t != first)
            if t != n:
                wrong += 1
                late += (n > t)
    print(f'{len(files)} traces with CPU activity, {total} engine transitions')
    print(f'  the CPU took the slot the engine wanted: {contended} '
          f'({100.0 * contended / total:.1f}%)')
    print(f'  mispredicted by openMSX\'s arbitration:  {wrong} '
          f'({100.0 * wrong / total:.2f}%)   [{late} of them: engine later '
          f'than modelled]')


if __name__ == '__main__':
    main()
