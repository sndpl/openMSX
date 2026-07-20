#!/usr/bin/env python3
"""Simulate openMSX's VDP command engine slot model (VDPCmdEngine.cc +
VDPAccessSlots.cc) and compare with vdpcmdx measurements (issue #2057).

Model: each VRAM access happens on an access slot. After an access at time t,
the next access happens at the first slot >= t + delta (delta from Grauw's
measurements). Line length = 1368 VDP ticks.
"""
import bisect

LINE = 1368

SLOTS_SPRITES_ON = [28, 92, 162, 170, 188, 220, 252, 316, 348, 380,
                    444, 476, 508, 572, 604, 636, 700, 732, 764, 828,
                    860, 892, 956, 988, 1020, 1084, 1116, 1148, 1212, 1264,
                    1330]

SLOTS_SPRITES_OFF = [6, 14, 22, 30, 38, 46, 54, 62, 70, 78,
                     86, 94, 102, 110, 118, 162, 170, 182, 188, 214,
                     220, 246, 252, 278, 310, 316, 342, 348, 374, 380,
                     406, 438, 444, 470, 476, 502, 508, 534, 566, 572,
                     598, 604, 630, 636, 662, 694, 700, 726, 732, 758,
                     764, 790, 822, 828, 854, 860, 886, 892, 918, 950,
                     956, 982, 988, 1014, 1020, 1046, 1078, 1084, 1110, 1116,
                     1142, 1148, 1174, 1206, 1212, 1266, 1274, 1282, 1290, 1298,
                     1306, 1314, 1322, 1332, 1342, 1350, 1358, 1366]

SLOTS_SCREEN_OFF = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72,
                    80, 88, 96, 104, 112, 120, 164, 172, 180, 188,
                    196, 204, 212, 220, 228, 236, 244, 252, 260, 268,
                    276, 292, 300, 308, 316, 324, 332, 340, 348, 356,
                    364, 372, 380, 388, 396, 404, 420, 428, 436, 444,
                    452, 460, 468, 476, 484, 492, 500, 508, 516, 524,
                    532, 548, 556, 564, 572, 580, 588, 596, 604, 612,
                    620, 628, 636, 644, 652, 660, 676, 684, 692, 700,
                    708, 716, 724, 732, 740, 748, 756, 764, 772, 780,
                    788, 804, 812, 820, 828, 836, 844, 852, 860, 868,
                    876, 884, 892, 900, 908, 916, 932, 940, 948, 956,
                    964, 972, 980, 988, 996, 1004, 1012, 1020, 1028, 1036,
                    1044, 1060, 1068, 1076, 1084, 1092, 1100, 1108, 1116, 1124,
                    1132, 1140, 1148, 1156, 1164, 1172, 1188, 1196, 1204, 1212,
                    1220, 1228, 1268, 1276, 1284, 1292, 1300, 1308, 1316, 1324,
                    1334, 1344, 1352, 1360]

def next_slot(slots, t, delta):
    """First slot at time >= t + delta (openMSX greedy model)."""
    t2 = t + delta
    line, pos = divmod(t2, LINE)
    i = bisect.bisect_left(slots, pos)
    if i == len(slots):
        return (line + 1) * LINE + slots[0]
    return line * LINE + slots[i]

# Command access patterns: list of deltas *after* each access of one pixel.
# The last delta gets 'wrap_extra' added at end-of-row (every nx pixels).
# LMMM: srcRead -32-> dstRead -24-> write -64-> (wrap +64)
COMMANDS = {
    'HMMM': dict(deltas=[24, 64],     wrap_extra=64),
    'LMMM': dict(deltas=[32, 24, 64], wrap_extra=64),
    'YMMM': dict(deltas=[24, 40],     wrap_extra=0),
    'HMMV': dict(deltas=[48],         wrap_extra=56),
    'LMMV': dict(deltas=[24, 72],     wrap_extra=64),
}

def simulate(slots, cmd, nx, window, start=0, next_slot_fn=next_slot):
    """Count pixels whose *write* completes before 'window' ticks."""
    spec = COMMANDS[cmd]
    deltas, wrap_extra = spec['deltas'], spec['wrap_extra']
    t = next_slot_fn(slots, start, 0)   # startXxxx: nextAccessSlot(time)
    count = 0
    col = 0
    while True:
        # all accesses of one pixel; write is the last access
        for j, d in enumerate(deltas):
            if t >= window:
                return count
            if j == len(deltas) - 1:
                count += 1          # write happened at time t
                col += 1
                dd = d + (wrap_extra if col == nx else 0)
                if col == nx:
                    col = 0
                t = next_slot_fn(slots, t, dd)
            else:
                t = next_slot_fn(slots, t, d)

TABLES = {'NORMAL': SLOTS_SPRITES_ON, 'NO_SPR': SLOTS_SPRITES_OFF,
          'NO_SCR': SLOTS_SCREEN_OFF}

# vdpcmdx geometry (screen 8): landscape 256x40 @x=0, portrait 40x256 @x=216
# YMMM copies DX..right edge: landscape 256 wide, portrait 40 wide.
GEOM = {'land': 256, 'port': 40}

ACTIVE_WINDOW = 192 * LINE
VBLANK_WINDOW_PAL = (313 - 192) * LINE

# Measured values (PAL): (openMSX 21 'THIS' from our run, real HW 'REAL')
MEASURED_ACTIVE = {
    # cmd, orient: (openMSX, real)
    ('HMMM', 'land'): (1915, 1915), ('HMMM', 'port'): (1915, 1916),
    ('LMMM', 'land'): (1717, 1339), ('LMMM', 'port'): (1699, 1332),
    ('YMMM', 'land'): (2111, 2111), ('YMMM', 'port'): (2111, 2095),
    ('HMMV', 'land'): (4003, 4005), ('HMMV', 'port'): (3920, 3922),
    ('LMMV', 'land'): (1907, 1908), ('LMMV', 'port'): (1868, 1869),
}
MEASURED_ACTIVE_NOSPR = {
    ('HMMM', 'land'): (2668, 2673), ('HMMM', 'port'): (2636, 2659),
    ('LMMM', 'land'): (1970, 1971), ('LMMM', 'port'): (1954, 1955),
    ('YMMM', 'land'): (2870, 3797), ('YMMM', 'port'): (2871, 3689),
    ('HMMV', 'land'): (4194, 4195), ('HMMV', 'port'): (4122, 4120),
    ('LMMV', 'land'): (2104, 2106), ('LMMV', 'port'): (2104, 2106),
}
MEASURED_ACTIVE_NOSCR = {
    ('HMMM', 'land'): (2853, 2854), ('HMMM', 'port'): (2795, 2796),
    ('LMMM', 'land'): (2003, 2004), ('LMMM', 'port'): (1992, 1993),
    ('YMMM', 'land'): (4009, 3996), ('YMMM', 'port'): (4012, 3914),
    ('HMMV', 'land'): (5311, 5313), ('HMMV', 'port'): (5093, 5094),
    ('LMMV', 'land'): (2666, 2668), ('LMMV', 'port'): (2627, 2627),
}

def report(title, table, measured, start=0, next_slot_fn=next_slot):
    print(f'--- {title} (start offset {start}) ---')
    print(f"{'cmd':6} {'or':4} {'sim':>6} {'openMSX':>8} {'real':>6}")
    for (cmd, orient), (omsx, real) in measured.items():
        nx = GEOM[orient]
        sim = simulate(table, cmd, nx, ACTIVE_WINDOW, start, next_slot_fn)
        print(f'{cmd:6} {orient:4} {sim:6d} {omsx:8d} {real:6d}')
    print()

if __name__ == '__main__':
    for start in (0, 300):
        report('ACTIVE NORMAL (sprites on, 31 slots)', SLOTS_SPRITES_ON,
               MEASURED_ACTIVE, start)
    report('ACTIVE NO_SPR (sprites off, 88 slots)', SLOTS_SPRITES_OFF,
           MEASURED_ACTIVE_NOSPR, 300)
    report('ACTIVE NO_SCR (screen off, 154 slots)', SLOTS_SCREEN_OFF,
           MEASURED_ACTIVE_NOSCR, 300)

# ---------------------------------------------------------------------------
# Hypothesis testing: rule variants for LMMM
# ---------------------------------------------------------------------------
def next_slot_skip(slots, t, delta, skip):
    """First slot >= t+delta AND at least 'skip+1' slot positions after t."""
    t2 = t + delta
    line, pos = divmod(t2, LINE)
    i = bisect.bisect_left(slots, pos)
    # index of the slot the previous access used (t is always on a slot)
    tline, tpos = divmod(t, LINE)
    ti = bisect.bisect_left(slots, tpos)
    min_index_abs = (tline * len(slots)) + ti + 1 + skip
    cand_abs = line * len(slots) + (i if i < len(slots) else len(slots))
    idx = max(cand_abs, min_index_abs)
    l2, i2 = divmod(idx, len(slots))
    return l2 * LINE + slots[i2]

def simulate_lmmm_variant(slots, nx, window, start, variant):
    """LMMM with a modified rule for the src-read -> dst-read gap."""
    t = next_slot(slots, start, 0)
    count = 0
    col = 0
    while True:
        # t = src read time
        if variant == 'base':
            t = next_slot(slots, t, 32)          # dst read
        elif variant == 'skip1':
            t = next_slot_skip(slots, t, 32, 1)  # dst read: skip one slot
        elif variant == 'd48':
            t = next_slot(slots, t, 48)
        elif variant == 'd64':
            t = next_slot(slots, t, 64)
        if t >= window: return count
        t = next_slot(slots, t, 24)              # write
        if t >= window: return count
        count += 1; col += 1
        d = 64 + (64 if col == nx else 0)
        if col == nx: col = 0
        t = next_slot(slots, t, d)               # next src read
        if t >= window: return count

REAL_LMMM = {('NORMAL','land'):1339, ('NORMAL','port'):1332,
             ('NO_SPR','land'):1971, ('NO_SPR','port'):1955,
             ('NO_SCR','land'):2004, ('NO_SCR','port'):1993}
OMSX_LMMM = {('NORMAL','land'):1717, ('NORMAL','port'):1699,
             ('NO_SPR','land'):1970, ('NO_SPR','port'):1954,
             ('NO_SCR','land'):2003, ('NO_SCR','port'):1992}

print('LMMM rule variants (sim, start offset 300):')
print(f"{'table':8}{'or':6}{'base':>7}{'skip1':>7}{'d48':>7}{'d64':>7}{'openMSX':>9}{'real':>7}")
for tname, slots in TABLES.items():
    for orient, nx in GEOM.items():
        row = [simulate_lmmm_variant(slots, nx, ACTIVE_WINDOW, 300, v)
               for v in ('base','skip1','d48','d64')]
        print(f"{tname:8}{orient:6}" + ''.join(f'{r:7d}' for r in row)
              + f"{OMSX_LMMM[(tname,orient)]:9d}{REAL_LMMM[(tname,orient)]:7d}")

# ---------------------------------------------------------------------------
# Final verification: candidate rule = "in sprites-on mode, LMMM's dst read
# happens at the first slot >= srcRead + 48 (instead of +32)". All other
# commands/modes unchanged. Also verify VBLANK windows (screen-off table).
# ---------------------------------------------------------------------------
def sim_cmd(slots, cmd, nx, window, start, lmmm_rr):
    spec = COMMANDS[cmd]
    deltas = list(spec['deltas'])
    if cmd == 'LMMM':
        deltas[0] = lmmm_rr
    wrap_extra = spec['wrap_extra']
    t = next_slot(slots, start, 0)
    count = 0; col = 0
    while True:
        for j, d in enumerate(deltas):
            if t >= window: return count
            if j == len(deltas) - 1:
                count += 1; col += 1
                dd = d + (wrap_extra if col == nx else 0)
                if col == nx: col = 0
                t = next_slot(slots, t, dd)
            else:
                t = next_slot(slots, t, d)

print('FINAL: all commands, rule = LMMM R->R 48 in sprites-on only')
print(f"{'cond':8}{'cmd':6}{'or':6}{'sim-old':>8}{'sim-new':>8}{'openMSX':>8}{'real':>7}")
ALL = [('NORMAL', MEASURED_ACTIVE), ('NO_SPR', MEASURED_ACTIVE_NOSPR),
       ('NO_SCR', MEASURED_ACTIVE_NOSCR)]
for cond, meas in ALL:
    slots = TABLES[cond]
    for (cmd, orient), (omsx, real) in meas.items():
        nx = GEOM[orient]
        old = sim_cmd(slots, cmd, nx, ACTIVE_WINDOW, 300, 32)
        rr = 48 if cond == 'NORMAL' else 32
        new = sim_cmd(slots, cmd, nx, ACTIVE_WINDOW, 300, rr)
        mark = ' <-- ' if abs(new-real) > 25 else ''
        print(f'{cond:8}{cmd:6}{orient:6}{old:8d}{new:8d}{omsx:8d}{real:7d}{mark}')

# VBLANK (screen-off table, PAL: 121 lines), THIS/REAL from run:
VB = {('HMMM','land'):(1808,1801), ('LMMM','land'):(1273,1265),
      ('YMMM','land'):(2532,2512), ('HMMV','land'):(3367,3360),
      ('LMMV','land'):(1689,1684),
      ('HMMM','port'):(1771,1765), ('LMMM','port'):(1266,1258),
      ('YMMM','port'):(2531,2461), ('HMMV','port'):(3236,3229),
      ('LMMV','port'):(1664,1659)}
print('\nVBLANK PAL (121 lines, screen-off table):')
print(f"{'cmd':6}{'or':6}{'sim':>7}{'openMSX':>8}{'real':>7}")
for (cmd, orient), (omsx, real) in VB.items():
    sim = sim_cmd(SLOTS_SCREEN_OFF, cmd, GEOM[orient], VBLANK_WINDOW_PAL, 300, 32)
    print(f'{cmd:6}{orient:6}{sim:7d}{omsx:8d}{real:7d}')
