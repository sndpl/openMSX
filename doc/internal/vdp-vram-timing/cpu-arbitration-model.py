#!/usr/bin/env python3
"""A model of how the V9938 hands VRAM access slots to the CPU, and its fit.

Usage:
    cpu-arbitration-model.py <measurement-repo>            # both sets
    cpu-arbitration-model.py <measurement-repo> --2013     # only the old set
    cpu-arbitration-model.py <measurement-repo> --2026     # only the new set

The model (all times in VDP cycles):

  1. The CPU's request register is one deep.  It is loaded by a port access to
     #98 and stays occupied until the VRAM access has taken place -- not until
     the slot has been granted.  A port access that arrives while the register
     is occupied is lost: no VRAM access happens for it (and the VDP's VRAM
     pointer does not advance, so the CPU sees the previous byte again).

  2. LEAD cycles before every access slot, the VDP decides who gets it.  A
     pending CPU request wins; otherwise the command engine gets it if it has a
     request ready; otherwise the slot goes unused.  LEAD is counted in the
     VDP's *memory cycles*: the two memory cycles per line that are stretched by
     two cycles each in the horizontal blanking region do not count towards it,
     exactly as for the command engine's delays.

  3. A slot that has another slot only 6 cycles before it cannot carry a CPU
     access.  Such slots exist only in the sprites-off table (25 of the 88), and
     when the CPU's request wins one, the VDP spends that memory cycle on a dummy
     read of 0x1FFFF and the CPU's access happens in the next slot.  The decision
     point of these slots is two cycles earlier than the uniform rule.

What the two measurement sets contribute:

  * 2013 (Philips NMS8250): the CPU clock is exactly VDP/6, so the port accesses
    sit on an exact grid -- 40 of them 72 cycles apart, then 252 cycles for the
    loop overhead.  The phase of that grid relative to the VDP is unknown and is
    fitted per capture; a constant delay between the port access and the
    arbitration is indistinguishable from it.
  * 2026 (Philips NMS8280): the two clocks are asynchronous, but /CSR and /CSW
    were recorded, so the port accesses are known individually.  What is fitted
    per capture is then only the constant offset, and LEAD becomes measurable:
    26 cycles from the rising edge of /CSx.

Both sets are scored in both directions: accesses that happened but are not
predicted, and accesses that are predicted but did not happen.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import glob
import importlib.util
import os
import re
import statistics
import sys

TICKS = 1368
LEAD = 26                # memory cycles, from the rising edge of /CSx
PAIR_EXTRA_LEAD = 2      # extra lead of a slot 6 cycles after another slot
FREE_BEFORE = [0]        # the register frees this many cycles before the access
PERIOD_2013 = 3060       # 39 * 72 + 252
IN_PERIOD = 72
BURST = 40

_here = os.path.dirname(os.path.abspath(__file__))


def _load(name, mod):
    spec = importlib.util.spec_from_file_location(mod,
                                                  os.path.join(_here, name))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


C = _load('2026-measurement-check.py', 'check')
G = _load('vcd-slot-grid.py', 'grid')

TABLES = C.TABLES
PAIR = {m: {s for s in TABLES[m] if (s - 6) in set(TABLES[m])} for m in TABLES}


# --------------------------------------------------------------------------
# the model
# --------------------------------------------------------------------------
def V(mode, t):
    """Memory-cycle time: real time minus the blanking stretch seen so far."""
    line, c = divmod(int(t) if t == int(t) else t // 1, TICKS)
    line, c = divmod(t, TICKS)
    a, b = C.STRETCH[mode]
    return t - (4 * line + (0 if c < a else 2 if c < b else 4))


def decision(mode, s):
    """Real time at which slot s is handed out."""
    lead = LEAD + (PAIR_EXTRA_LEAD if (s % TICKS) in PAIR[mode] else 0)
    want = V(mode, s) - lead
    t = s - lead
    while V(mode, t) > want:
        t -= 1
    while V(mode, t + 1) <= want:
        t += 1
    return t


def slots(mode, lo, hi):
    tab = TABLES[mode]
    out = []
    line = lo // TICKS - 1
    while line * TICKS <= hi:
        out += [line * TICKS + s for s in tab if lo <= line * TICKS + s <= hi]
        line += 1
    return sorted(out)


def simulate(mode, requests, lo, hi, drop=True):
    """(cpu accesses, dummy reads, lost requests).

    'drop' selects what happens when a port access arrives while the register is
    still occupied: True loses the new one (what the measurements show), False
    overwrites and loses the old one (what openMSX assumes).
    """
    ss = slots(mode, lo - 200, hi + 200)
    nxt = {s: n for s, n in zip(ss, ss[1:])}
    # 0 = access completes, 1 = slot is handed out, 2 = port access
    ev = ([(s - FREE_BEFORE[0], 0, s) for s in ss]
          + [(decision(mode, s), 1, s) for s in ss]
          + [(r, 2, r) for r in requests])
    ev.sort()
    busy = False            # register holds a request that has not been served
    pending = False         # ... and it has not been given a slot yet
    at = None               # slot in which its access will happen
    cpu, dummy, lost = [], [], 0
    for t, kind, val in ev:
        if kind == 2:
            if busy:
                lost += 1
                if not drop:
                    pending, at = True, None
            else:
                busy, pending, at = True, True, None
        elif kind == 1:
            if pending and at is None:
                if (val % TICKS) in PAIR[mode]:
                    dummy.append(val)
                    at = nxt.get(val)
                else:
                    at = val
                pending = False
        elif at == val:
            cpu.append(val)
            busy, at = False, None
        elif at is None and not pending:
            pass
    return cpu, dummy, lost


# --------------------------------------------------------------------------
# the 2013 set: exact request grid, unknown phase
# --------------------------------------------------------------------------
CMDS = ('HMMM', 'HMMV', 'LMMM', 'LMMV', 'YMMM', 'HYMM', 'LINE')


def meta13(path):
    b = os.path.basename(path)[:-4]
    if not b.startswith('screen') or 'wrong' in b:
        return None
    scr = re.match(r'screen(\d+)', b)
    if scr is None or scr[1] not in ('5', '6', '7', '8'):
        return None
    mode = ('dispOff' if 'screenoff' in b else
            'sprOff' if 'nosprites' in b else
            'sprOn' if 'sprite' in b else None)
    cpu = ('rd' if 'cpuread' in b else 'wr' if 'cpuwrite' in b else None)
    if mode is None or cpu is None:
        return None
    return {'mode': mode, 'name': b,
            'cmd': next((c for c in CMDS if c in b), None)}


def parse13(path, mode):
    rel = C.RELABEL[mode]
    out = []
    with open(path) as f:
        for ln in f:
            if ':' not in ln:
                continue
            row, rest = ln.rstrip('\n').split(':', 1)
            t, col = int(row), 0
            while rest:
                cell = rest[2:13]
                if cell.strip():
                    line, c = divmod(TICKS * col + t - 1, TICKS)
                    out.append((line * TICKS + rel.get(c, c), cell[0:3],
                                int(cell[6:11], 16)))
                rest = rest[13:]
                col += 1
    return sorted(out)


def requests13(phase, lo, hi):
    out = []
    n = (lo - phase) // PERIOD_2013 - 1
    while phase + n * PERIOD_2013 <= hi:
        base = phase + n * PERIOD_2013
        out += [base + j * IN_PERIOD for j in range(BURST)
                if lo <= base + j * IN_PERIOD <= hi]
        n += 1
    return sorted(out)


def run2013(repo, drop=True):
    print('=== 2013, Philips NMS8250: CPU clock exactly VDP/6 ===')
    print(f'{"capture":42} {"mode":8} {"n":>4} {"missed":>7} {"spurious":>9} '
          f'{"lost":>5} {"phases":>7}')
    tot = collections.Counter()
    for path in sorted(glob.glob(os.path.join(repo, '8.final-analysis',
                                              'screen*.txt'))):
        m = meta13(path)
        if m is None:
            continue
        acc = parse13(path, m['mode'])
        obs = sorted(t for t, code, a in acc if code in ('R.c', 'W.c'))
        if len(obs) < 10:
            continue
        lo, hi = obs[0] - 100, obs[-1] + 100
        best = None
        for phase in range(PERIOD_2013):
            cpu, dummy, lost = simulate(m['mode'], requests13(phase, lo, hi),
                                        lo, hi, drop)
            p = {x for x in cpu if obs[0] <= x <= obs[-1]}
            miss, extra = len(set(obs) - p), len(p - set(obs))
            score = (miss + extra, )
            if best is None or score < best[0]:
                best = (score, miss, extra, lost, [phase])
            elif score == best[0]:
                best[4].append(phase)
        _, miss, extra, lost, phases = best
        tot['n'] += len(obs)
        tot['miss'] += miss
        tot['extra'] += extra
        print(f'{m["name"]:42} {m["mode"]:8} {len(obs):4} {miss:7} {extra:9} '
              f'{lost:5} {len(phases):7}')
    print(f'\n{tot["n"]} CPU accesses: {tot["miss"]} not predicted '
          f'({100.0 * tot["miss"] / tot["n"]:.2f}%), {tot["extra"]} predicted '
          f'but absent\n')


# --------------------------------------------------------------------------
# the 2026 set: /CSx recorded, asynchronous clock
# --------------------------------------------------------------------------
def timebase(ref, cyc, anchor):
    """Anchors from the refresh chain, which is exactly 128 cycles apart."""
    out = []
    for t in sorted(ref):
        c = (t - anchor) * cyc + G.REFRESH_CYCLE
        line, off = divmod(c, TICKS)
        k = round((off - G.REFRESH_CYCLE) / 128)
        if 0 <= k <= 7:
            exact = line * TICKS + G.REFRESH_CYCLE + 128 * k
            if abs(exact - c) <= 3:
                out.append((t, exact))
    return out


def decode26(vcd, rng):
    trace = G.parse_vcd(vcd)
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
    fixed = timebase(ref, cyc, anchor)
    if len(fixed) < 4:
        return None
    xs = [t for t, _ in fixed]
    ys = [c for _, c in fixed]

    def cycle(t):
        i = bisect.bisect_left(xs, t)
        if i == 0:
            return ys[0] + (t - xs[0]) * cyc
        if i >= len(xs):
            return ys[-1] + (t - xs[-1]) * cyc
        f = (t - xs[i - 1]) / (xs[i] - xs[i - 1])
        return ys[i - 1] + f * (ys[i] - ys[i - 1])

    req, prev = [], {'CSR': None, 'CSW': None}
    for t, s in trace:
        for sig in ('CSR', 'CSW'):
            if prev[sig] == 0 and s[sig] == 1:
                req.append(cycle(t))
            prev[sig] = s[sig]
    by = collections.defaultdict(list)
    for cas, ras, addr, rd in acc:
        by[ras].append(addr)
    cpu, dummy = [], []
    for ras, addrs in sorted(by.items()):
        if len(addrs) != 1 or ras in ref:
            continue
        if addrs[0] == 0x1FFFF:
            dummy.append(cycle(ras))
        elif rng[0] <= addrs[0] <= rng[1]:
            cpu.append(cycle(ras))
    return sorted(req), sorted(cpu), sorted(dummy)


def snap(mode, t):
    line, off = divmod(t, TICKS)
    return min(((line + k) * TICKS + s for k in (-1, 0, 1)
                for s in TABLES[mode]), key=lambda v: abs(v - t))


def run2026(repo, drop=True):
    print('=== 2026, Philips NMS8280: CPU clock asynchronous to the VDP ===')
    vcd_dir = os.path.join(repo, 'part2', '1.vcd')
    txt_dir = os.path.join(repo, 'part2', '5.slots')
    agg = collections.defaultdict(collections.Counter)
    offs = collections.defaultdict(list)
    for vcd in sorted(glob.glob(os.path.join(vcd_dir, 'scr5-*.vcd'))):
        name = os.path.basename(vcd)[:-4]
        if 'noCpu' in name:
            continue
        txt = os.path.join(txt_dir, name + '.txt')
        if not os.path.exists(txt) or C.meta(txt) is None:
            continue
        mode = C.meta(txt)['mode']
        v = [a for t, code, a in C.parse(txt) if code in C.CPU_CODES]
        if not v:
            continue
        d = decode26(vcd, (min(v), max(v)))
        if d is None:
            continue
        req, cpu, dummy = d
        obs = sorted({snap(mode, t) for t in cpu})
        if len(obs) < 10:
            continue
        obsd = {snap(mode, t) for t in dummy
                if (snap(mode, t) % TICKS) in PAIR[mode]}
        lo, hi = obs[0] - 100, obs[-1] + 100
        rq = [r for r in req if lo - 120 < r < hi]
        best = None
        for o2 in range(-20, 40):
            off = o2 / 2
            p, pd, lost = simulate(mode, [r + off for r in rq], lo, hi, drop)
            ps = {x for x in p if obs[0] <= x <= obs[-1]}
            pds = {x for x in pd if obs[0] <= x <= obs[-1]}
            score = (len(set(obs) - ps) + len(ps - set(obs))
                     + len(obsd - pds) + len(pds - obsd))
            if best is None or score < best[0]:
                best = (score, off, ps, pds, lost)
        _, off, ps, pds, lost = best
        k = agg[mode]
        k['n'] += len(obs)
        k['miss'] += len(set(obs) - ps)
        k['extra'] += len(ps - set(obs))
        k['dn'] += len(obsd)
        k['dmiss'] += len(obsd - pds)
        k['dextra'] += len(pds - obsd)
        k['lost'] += lost
        k['req'] += len(rq)
        k['cap'] += 1
        offs[mode].append(off)
    print(f'{"mode":8} {"cap":>4} {"accesses":>9} {"missed":>7} '
          f'{"spurious":>9} {"dummy":>6} {"d-miss":>7} {"lost/req":>10} '
          f'{"lead":>12}')
    for mode in ('dispOff', 'sprOff', 'sprOn'):
        k = agg[mode]
        if not k['n']:
            continue
        lead = LEAD + statistics.fmean(offs[mode])
        sd = statistics.stdev(offs[mode]) if len(offs[mode]) > 1 else 0.0
        print(f'{mode:8} {k["cap"]:4} {k["n"]:9} {k["miss"]:7} {k["extra"]:9} '
              f'{k["dn"]:6} {k["dmiss"]:7} '
              f'{k["lost"]:5}/{k["req"]:<5} {lead:6.2f} +-{sd:5.2f}')
    n = sum(agg[m]['n'] for m in agg)
    miss = sum(agg[m]['miss'] for m in agg)
    print(f'\n{n} CPU accesses: {miss} not predicted '
          f'({100.0 * miss / n:.2f}%)')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('repo')
    ap.add_argument('--2013', dest='only13', action='store_true')
    ap.add_argument('--2026', dest='only26', action='store_true')
    ap.add_argument('--overwrite', action='store_true',
                    help='a new request overwrites an unserved one, as openMSX '
                         'assumes, instead of being lost')
    args = ap.parse_args()
    if not args.only26:
        run2013(args.repo, not args.overwrite)
    if not args.only13:
        run2026(args.repo, not args.overwrite)


if __name__ == '__main__':
    main()
