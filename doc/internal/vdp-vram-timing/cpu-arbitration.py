#!/usr/bin/env python3
"""Measure the CPU side of the VDP's VRAM arbitration from the raw captures.

Usage:
    cpu-arbitration.py <measurement-repo>/part2

The .vcd captures include the /CSR and /CSW pins, so the CPU's port accesses --
its *requests* -- can be read off directly instead of being modelled from the
Z80 instruction timing.  This reports, per capture:

  * the /CSR or /CSW pulse width,
  * the interval between requests inside a burst of IN instructions, and the
    gap at the end of the burst,
  * the arbitration lead L that best explains which slot each request was
    served in, by running the state machine
        - one request buffer, overwritten (and the old request lost) by a new
          request,
        - L cycles before a slot the VDP gives it to the CPU if a request is
          pending, else to the command engine, else nobody,
    against the display-off captures with no command running, where the CPU is
    the only thing accessing VRAM.

The cycle scale comes from vcd-slot-grid.py's /RAS fit; as a check it also
prints the measured refresh interval, which must be exactly 128.
"""
from __future__ import annotations

import collections
import glob
import importlib.util
import os
import statistics
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'grid', os.path.join(_here, 'vcd-slot-grid.py'))
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)

TICKS = G.TICKS


def decode(path):
    """(mode, cycle-of, requests, cpu accesses, refresh interval)."""
    trace = G.parse_vcd(path)
    edges = G.ras_edges(trace)
    g = G.geometry(edges)
    if g is None:
        return None
    period, _ = g
    cyc = TICKS / period
    acc = G.accesses(trace)
    anchor, ref = G.refresh_chain_start(acc, cyc)
    if anchor is None:
        return None

    def cycle(t):
        return (t - anchor) * cyc + G.REFRESH_CYCLE

    req, prev = [], {'CSR': None, 'CSW': None}
    width = []
    down = {}
    for t, s in trace:
        for sig in ('CSR', 'CSW'):
            if prev[sig] == 1 and s[sig] == 0:
                down[sig] = t
            if prev[sig] == 0 and s[sig] == 1:
                req.append(cycle(t))
                if sig in down:
                    width.append((t - down[sig]) * cyc)
            prev[sig] = s[sig]
    # CPU VRAM accesses: single-/CAS, not refresh, not the dummy read, and part
    # of a run of consecutive addresses (the test program walks VRAM)
    by = collections.defaultdict(list)
    for cas, ras, addr, rd in acc:
        by[ras].append((cas, addr))
    cand = [(cycle(r), cl[0][1]) for r, cl in sorted(by.items())
            if len(cl) == 1 and r not in ref and cl[0][1] != 0x1FFFF]
    cpu = [c for i, c in enumerate(cand)
           if any(abs(o[1] - c[1]) == abs(i - j) and o[1] != c[1]
                  for j, o in enumerate(cand) if 0 < abs(i - j) <= 2)]
    r = sorted(cycle(t) for t in ref)
    rint = [b - a for a, b in zip(r, r[1:]) if b - a < 200]
    mode = os.path.basename(path).split('-')[1]
    return (mode, sorted(req), sorted(x[0] for x in cpu), width,
            statistics.fmean(rint) if rint else None)


def simulate(mode, requests, lo, hi, lead):
    """(served slots, lost requests) for a CPU-only capture."""
    tab = G.OPENMSX[mode]
    slots = []
    line = int(lo // TICKS) - 1
    while line * TICKS <= hi + 200:
        for s in tab:
            t = line * TICKS + s
            if lo - 200 <= t <= hi + 200:
                slots.append(t)
        line += 1
    ev = [(r, 0, r) for r in requests] + [(s - lead, 1, s) for s in sorted(slots)]
    ev.sort(key=lambda x: (x[0], x[1]))
    pending, served, lost = None, [], 0
    for t, kind, val in ev:
        if kind == 0:
            if pending is not None:
                lost += 1
            pending = val
        elif pending is not None:
            served.append(val)
            pending = None
    return served, lost


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    vcd = os.path.join(sys.argv[1], '1.vcd')
    widths, intra, tail, leads = [], collections.Counter(), [], collections.Counter()
    print(f'{"capture":30} {"req":>4} {"acc":>4} {"lead":>5} {"matched":>9} '
          f'{"lost":>5} {"refresh":>8}')
    for path in sorted(glob.glob(os.path.join(vcd, 'scr5-*-stop-*Cpu-*.vcd'))):
        name = os.path.basename(path)[:-4]
        if 'noCpu' in name:
            continue
        d = decode(path)
        if d is None:
            continue
        mode, req, cpu, width, rint = d
        widths += width
        gaps = [b - a for a, b in zip(req, req[1:])]
        for g in gaps:
            if g > 150:
                tail.append(g)
            else:
                intra[round(g)] += 1
        if len(cpu) < 20:
            continue
        best = None
        for l2 in range(30, 90):
            lead = l2 / 2
            served, lost = simulate(mode, req, cpu[0] - 100, cpu[-1] + 100, lead)
            hit = len({round(x) for x in cpu} & {round(x) for x in served})
            if best is None or hit > best[0]:
                best = (hit, lead, lost)
        hit, lead, lost = best
        leads[lead] += 1
        print(f'{name:30} {len(req):4} {len(cpu):4} {lead:5} '
              f'{hit:4}/{len(cpu):<4} {lost:5} {rint:8.3f}')
    print()
    if widths:
        print(f'/CSR + /CSW pulse width: {statistics.fmean(widths):.2f} '
              f'+- {statistics.stdev(widths):.2f} cycles (n={len(widths)})')
    tot = sum(intra.values())
    mean = sum(k * v for k, v in intra.items()) / tot if tot else 0
    print(f'request interval inside a burst: {mean:.2f} cycles, '
          f'histogram {sorted(intra.items())}')
    if tail:
        print(f'gap at the end of a burst: {statistics.fmean(tail):.2f} '
              f'(n={len(tail)})')
    print(f'best arbitration lead per capture: {sorted(leads.items())}')
    print('\nFor reference: 40 x IN A,(#98) at 12 T-states with a Z80 clock of '
          'exactly VDP/6\nwould give 72 cycles between requests and 252 at the '
          'end of the burst.')


if __name__ == '__main__':
    main()
