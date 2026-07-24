#!/usr/bin/env python3
import re, sys, glob

def parse(fn):
    """Return list of (abs_time, R/W, addr) for command-engine accesses."""
    events = []
    for line in open(fn, encoding='utf-8', errors='replace'):
        m = re.match(r'\s*(\d+):(.*)$', line)
        if not m: continue
        cyc = int(m.group(1)); rest = m.group(2)
        # columns are successive lines; find all access tokens with their column
        for cm in re.finditer(r'([RW])\.(\w) (0x[0-9a-f]+)', rest):
            col = cm.start() // 13   # column width heuristic
            if cm.group(2) == 'e':
                events.append((col, cyc, cm.group(1), int(cm.group(3), 16)))
    # absolute time = col*1368 + cyc
    ev = sorted((c*1368 + t, rw, a) for c, t, rw, a in events)
    return ev

for fn in sorted(glob.glob('8.final-analysis/*YMMM*.txt')):
    ev = parse(fn)
    if not ev: print(fn, 'no engine events'); continue
    print(f'\n=== {fn}: {len(ev)} engine accesses ===')
    rw_gaps, wr_gaps, trans = {}, {}, []
    for i in range(1, len(ev)):
        t0, rw0, a0 = ev[i-1]; t1, rw1, a1 = ev[i]
        gap = t1 - t0
        if rw0 == 'R' and rw1 == 'W':
            rw_gaps[gap] = rw_gaps.get(gap, 0) + 1
        elif rw0 == 'W' and rw1 == 'R':
            wr_gaps[gap] = wr_gaps.get(gap, 0) + 1
            # line transition in the rect = read addr not prev read addr+1
            if i >= 2:
                prev_r = ev[i-2][2] if ev[i-2][1] == 'R' else None
                if prev_r is not None and a1 != prev_r + 1:
                    trans.append((gap, prev_r, a1))
    print('R->W gaps:', dict(sorted(rw_gaps.items())))
    print('W->R gaps:', dict(sorted(wr_gaps.items())))
    print('W->R gaps at rect line transitions (addr jump):',
          trans if trans else 'none captured')
