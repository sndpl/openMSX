# V9938 command timing: why LMMM is too fast and YMMM (no sprites) too slow

> **Note (2026).** The two fixes argued for here have since landed in openMSX, but in a
> different form than proposed below: a sprites-on specific delay for LMMM's
> destination read rather than the `work + 14` / "not immediate" rule of section 5, and
> a plain 36/104 for YMMM. A second set of logic-analyzer measurements has since become
> available and pins every command timing directly, superseding the parts of this
> document that reason from the aggregate `vdpcmdx` frame counts. See
> `2026-measurement-analysis.md`.


Analysis of [openMSX issue #2057](https://github.com/openMSX/openMSX/issues/2057).

This document argues from two sources:

* `vdp-timing.html` / `vdp-timing-2.html` in this directory, and the underlying raw
  data in <https://github.com/m9710797/vdp-timing-measurements> (2013 logic-analyzer
  captures of the V9938-VRAM bus). References below of the form `8.final-analysis/...`
  are files in that repository.
* [bengalack/vdpcmdx](https://github.com/bengalack/vdpcmdx), which measures how many
  pixels the command engine completes per frame on real hardware and in an emulator.

It describes the root cause of both deviations, the change made to fix them, the
measured result, and what still needs measuring to turn the LMMM rule from fitted into
derived.

## 1. What the tool measures

`vdpcmdx` runs in **screen 8** (1 byte = 1 pixel), 192-line mode, and counts pixels
completed by the command engine, separately for the time the raster beam is in VBLANK
and in the ACTIVE area. At 50 Hz that is 121 blank lines and 192 active lines, i.e.
`192 * 1368 = 262656` VDP cycles for the ACTIVE block. Two rectangle shapes are used:
**landscape** `NX=256, NY=40` and **portrait** `NX=40, NY=256`. Five conditions:
`NORMAL` (screen + sprites on), `NO SPR`, `NO SCR`, and two variants with the CPU
simultaneously hammering port `#98`.

Reference ("REAL") values are from a Sony HB-F1XD. Of the 30 non-CPU cells in the
ACTIVE block, 28 agree with openMSX 21 to within ~1%. The two that do not:

| command | condition | openMSX | real | error |
|---|---|---|---|---|
| LMMM | `NORMAL` | 1718 / 1700 | 1339 / 1332 | **+28.8% / +28.2%** — too fast |
| YMMM | `NO SPR` | 2873 / 2871 | 3797 / 3689 | **-24.2% / -21.9%** — too slow |

(landscape / portrait.) In the VBLANK block both commands are correct, which is the
first hint: the deviations are specific to the access-slot pattern of an *active*
display line, not to the command timing as such.

Converted to cycles per pixel/byte in the ACTIVE block:

| command | screen off | sprites off | sprites on |
|---|---|---|---|
| LMMM, openMSX | 128 | 128 | **128** |
| LMMM, real | 128 | 128 | **192** |
| YMMM, openMSX | 64 | **96** | 128 |
| YMMM, real | 64 | **64** | 128 |

## 2. How openMSX models command timing

Since commit `618ccb5cb` (2013) openMSX uses the VRAM access-slot model:

* `src/video/VDPAccessSlots.cc:14`, `:38`, `:55` — the slot position tables for
  screen-off / sprites-off / sprites-on, taken verbatim from
  `8.final-analysis/slots2.txt`.
* `src/video/VDPAccessSlots.cc:198` `getTab()` — picks the table from
  `isDisplayEnabled()` and `spritesEnabledRegister()`.
* `src/video/VDPAccessSlots.cc:156` `CycleTable` — precomputes, for every tick `i` in a
  line and every `Delta` step, the wait until the first slot at least `step` cycles
  after `i`.
* `src/video/VDPAccessSlots.hh:76` `Calculator::next(Delta)` — the inner-loop step.
* `src/video/VDPCmdEngine.cc` — each command's per-pixel sequence of `Delta`s, e.g.
  LMMM at `:1125-1161` (`D32` src-read → dst-read, `D24` dst-read → write, `D64`
  write → next src-read, `D128` at a rectangle-line boundary) and YMMM at
  `:1611-1660` (`D24` read → write, `D40` write → next read, no per-line extra).

The per-command minimum gaps come from `8.final-analysis/slots4.txt` (the number
follows the access it *precedes*):

```
HMMV: W48                 .. +56 per rectangle line
YMMM: R40 W24             .. +0
HMMM: R64 W24             .. +64
LMMV: R72 W24             .. +64
LMMM: R64 R32 W24         .. +64
LINE: R88 W24             .. +32 per Bresenham minor step
```

`slots4.txt` reads each gap as `work + 16`, with `work` a multiple of 8 (the command
engine runs at VDP_clock/8) and 16 the latency before a pending request can be granted.

**The critical caveat**: every one of those gaps was measured in screen-off mode only —
`slots4.txt`: *"All the results below were derived from looking at tables for
screen-off/&lt;command&gt;/no-cpu"*. In screen-off the access slots are 8 cycles apart, so
each gap is only determined **modulo 8**: the true minimum lies in `(gap-8, gap]`.
openMSX consistently took the upper bound. In screen-off that choice is invisible. In
the active area, where slots are 26/32/38/64 cycles apart, it is not.

## 3. The active-area slot structure

Reading `slotsSpritesOn` and `slotsSpritesOff` as two interleaved 32-cycle grids makes
the rest of the argument easy:

* **A-grid** — `188 + 32k`. Present with sprites on *and* off. One slot per 128 cycles
  is consumed by DRAM refresh (`284 + 128k`), which is why the sprites-on list reads
  `188, 220, 252, 316, 348, 380, 444, …` (a 64-cycle gap every fourth step).
* **B-grid** — `214 + 32k`, i.e. **26 cycles after** the A slot. Free only when sprites
  are disabled; with sprites on these are the sprite fetches.
* **Horizontal blanking** — a dense 8-cycle grid with sprites off
  (`6, 14, … 118` and `1266 … 1366`); with sprites on almost nothing
  (`1212, 1264, 1330, 28, 92, 162, 170`).

So the two grid-to-grid distances that matter are:

```
A -> B (same 32-cycle cell):   26 cycles
B -> A (next cell but one):    38 cycles
A -> A / B -> B:               32 cycles (64 across a refresh slot)
```

Per 128 cycles the active area offers **3 usable slots with sprites on** and **7 with
sprites off**.

## 4. Why YMMM is too slow with sprites off

YMMM needs 24 cycles from read to write, and 40 from the write to the next read. Hold
those against the grid distances:

* `24 <= 26` → the write lands on the B slot of the same cell. Good.
* `40 > 38` → the following read **misses** the next A slot and has to fall through to
  the next B slot, 58 cycles later.

openMSX therefore settles into a 96-cycle-per-byte rhythm. Real hardware does the
obvious thing instead — `A -> B -> A -> B …`, which is exactly `24 + 40 = 64` cycles per
byte:

```
R 188(A)  W 214(B)  R 252(A)  W 278(B)  R 316(A)  W 342(B)  R 380(A)  ...
    +26       +38       +26       +38       +26       +38
```

The whole 24% deviation is that single 2-cycle overshoot. `40` is the *upper* bound of
the range `(32, 40]` that the screen-off trace permits; the sprites-off data now pins
the true value to `(32, 38]`.

Expressed in the `work + latency` decomposition, YMMM's write→read step is 3 engine
ticks, so any **latency of 9..14** instead of 16 reproduces every screen-off trace
byte-for-byte (`8k + L` rounds up to `8k + 16` on an 8-cycle slot grid) while unlocking
the alternation. Simulation across all 40 measured cells (section 6) puts the best fit
at **L = 13 or 14**; L <= 12 starts to distort LMMV and HMMM with sprites off.

A numerically identical alternative reading: the B-grid really sits at `212 + 32k`
rather than `214 + 32k`, which would make the measured `24` and `40` land exactly on the
grid. That is appealing, but the slot positions were captured at 1-cycle resolution
whereas the command gaps were not, so re-reading the latency is the better-supported
of the two.

Cross-check against the raw trace (`8.final-analysis/screen5screenoffYMMM.txt`), which
confirms YMMM's 24/40 in screen-off and, incidentally, that the "40" is a genuine
minimum rather than a slot artefact — where refresh takes the slot at 285, the read
still appears exactly 40 cycles after the write at 253:

```
  33: R.e 0x1bc24     253: W.e 0x1fc27
  57: W.e 0x1fc24     285: R.r  <- refresh
  97: R.e 0x1bc25     293: R.e 0x1bc28   (253 + 40)
 121: W.e 0x1fc25     317: W.e 0x1fc28
```

## 5. Why LMMM is too fast with sprites on

### 5.1 No per-step delay can explain it

Let LMMM's three gaps be `a = W -> R_src`, `b = R_src -> R_dst`, `c = R_dst -> W`. The raw
screen-off traces pin them tightly. From
`8.final-analysis/screen8screenoffLMMM.txt` (column 2; `0x018xx` = source region,
`0x058xx` = destination region):

```
  25: R.e 0x018d3     (source read)
  57: R.e 0x058d3     (+32, destination read)
  81: W.e 0x058d3     (+24, destination write)
 165: R.e 0x018d4     (next source read; 121..165 is a gap in the slot table)
 197: R.e 0x058d4     (+32)
 221: W.e 0x058d4     (+24)
 285: R.r             (refresh takes this slot)
 293: R.e 0x018d5     (+72 = 64 minimum, pushed by the refresh)
```

`8.final-analysis/screen5screenoffLMMM.txt` shows the same 32/24 and a clean +64
(`W 165 -> R_src 229`). With slots 8 cycles apart this gives
`a in (56,64]`, `b in (24,32]`, `c in (16,24]`.

Now run that against the sprites-on A-grid, starting from `R_src` at 188:

* `b <= 32` ⇒ `R_dst` is **forced** onto slot 220 (`= 188 + 32`),
* `c <= 24` ⇒ `W` is **forced** onto 252,
* `a <= 64` ⇒ the next `R_src` is **forced** onto 316.

That is **128 cycles per pixel = 9 pixels per line**, no matter which values inside
those ranges are chosen. Real hardware does **192 cycles per pixel = 7 pixels per
line** (`1339 / 192 = 6.97`). So the deviation is not a mis-set delay — **a constraint
is missing from the model.**

Note also that `R_src -> R_dst` at +32 demonstrably *does* work elsewhere: with sprites
off, LMMM matches real hardware exactly, and it gets there by using slot 220 (32 cycles
after 188). And a *write* 32 cycles after a read is fine even with sprites on — HMMM and
LMMV both do exactly that and both match real hardware. Whatever the rule is, it is
narrow.

### 5.2 The rule that fits

> The command engine cannot use the **immediately-following** access slot unless that
> slot is at least one extra engine tick (8 cycles) beyond the step's minimum gap.

Applied to LMMM's `R_src -> R_dst` step (minimum 32, so the immediately-following slot
must be >= 40 away), this is silent in every case openMSX already gets right and bites
only in the failing one:

| situation | next slot after `R_src` | effect |
|---|---|---|
| screen off | +8 | already excluded by the 32-cycle minimum — no change |
| sprites off | B slot at +26; 220 is the **second** slot | no change, LMMM stays at 128 c/px |
| sprites on, active | 220 **is** the next slot, only +32 | rejected → `R_dst` at 252 → 192 c/px |
| sprites on, H-blank | slots ~64 apart | margin never binds — no spurious penalty |

The last row is what distinguishes this from the cruder "always skip one slot"
formulation: in the sparse sprites-on H-blank, skipping a slot costs ~128 cycles and
overshoots to -6.9%. The +8 margin does not.

Physically this is consistent with a request that has to be pending for a whole engine
tick before the arbiter latches it: the dst-read request appears 2 ticks (16 cycles)
after the src read, and a slot arriving only 16 cycles later than that just misses the
window. That is a plausible story, not a proven one — see section 8.

### 5.3 The simple alternative, and why it is worse

Making `R_src -> R_dst` three engine ticks instead of two (32 → 38) is a one-value change
and fixes `NORMAL` just as well, because in screen-off the refresh slot already forces
128 cycles/pixel so the rate there does not move. But it pushes LMMM with sprites off
from 220 to 246 and makes that cell 2.6% too slow, and it contradicts the raw trace,
which shows 32. The slot-structure rule keeps all three LMMM columns within 0.5%.

## 6. Numerical validation

The access-slot model was re-implemented as a standalone simulator over the real slot
tables and the tool's actual geometry (screen 8, 256x40 and 40x256, 192 active lines /
121 blank lines at 50 Hz). Baseline it reproduces openMSX 21's own reported numbers for
all 30 ACTIVE cells and all 10 VBLANK cells to within 0.6%, which qualifies it as a
faithful stand-in. Results, ACTIVE block, with **L = 14 plus the
immediately-following-slot rule on LMMM's dst read**:

| command | cond. | REAL (L/P) | openMSX now | with change |
|---|---|---|---|---|
| LMMM | NORMAL | 1339 / 1332 | 1725 / 1707 (+28.8% / +28.2%) | **1343 / 1335 (+0.3% / +0.2%)** |
| LMMM | NO SPR | 1971 / 1955 | 1981 / 1965 (+0.5%) | 1981 / 1965 (+0.5%) |
| LMMM | NO SCR | 2004 / 1993 | 2014 / 2003 (+0.5%) | 2014 / 2003 (+0.5%) |
| YMMM | NORMAL | 2111 / 2095 | 2112 / 2112 (+0.0% / +0.8%) | 2112 / 2112 (+0.0% / +0.8%) |
| YMMM | NO SPR | 3797 / 3689 | 2880 / 2880 (-24.2% / -21.9%) | **3840 / 3840 (+1.1% / +4.1%)** |
| YMMM | NO SCR | 3996 / 3914 | 4032 / 4032 (+0.9% / +3.0%) | 4032 / 4032 (+0.9% / +3.0%) |
| HMMM | all | — | +0.3% .. +0.5% | +0.3% .. +0.5% |
| HMMV | all | — | +0.3% .. +0.6% | +0.3% .. +1.7% |
| LMMV | all | — | +0.3% .. +0.5% | +0.3% .. +0.5% |

Worst absolute error over all 40 cells drops from **28.8% to 4.1%**, and the only
remaining cells above 2% are YMMM *portrait*, which is already +3.0% today with the
screen off — a separate, pre-existing issue (section 7).

Sensitivity: `L = 13` and `L = 14` are equivalent here; `L = 15` or `16` leaves the YMMM
deviation untouched; `L = 12` or below introduces new errors of up to 9% in LMMV and
HMMM with sprites off. Moving the B-grid to `212` while keeping `L = 16` gives exactly
the same fit as `L = 14`.

## 7. The change

* **`src/video/VDPAccessSlots.hh` / `.cc`** — re-base the command-engine deltas from
  `work + 16` to `work + 14`:
  `D24 -> D22`, `D32 -> D30`, `D40 -> D38`, `D48 -> D46`, `D64 -> D62`, `D72 -> D70`,
  `D88 -> D86`, `D104 -> D102`, `D120 -> D118`, `D128 -> D126`, `D136 -> D134`.
  Leave `D0`, `D1`, `D16` (V99x8 CPU) and `D28` (TMS99x8 CPU) alone — the CPU path has
  its own tuning and its own evidence in `8.final-analysis/slots3.txt`.
* One delta, `D30_NI`, carries the rule from section 5.2: *"if the chosen slot is the
  first slot after `i`, require `slots[p] - i >= step + 8`"*. It fits the existing
  lookup-table design because the rule depends only on the current tick, which in the
  command engine is always the previous access slot, so `CycleTable` can precompute it
  like any other delta. `NUM_DELTAS` stays 15: the plain `D32` had exactly one user
  (LMMM's destination read) and `D30_NI` replaces it.
* **`src/video/VDPCmdEngine.cc`** — update the 20 `Delta::Dxx` uses
  (`rg -n 'Delta::D' src/video/VDPCmdEngine.cc`) and, for consistency, the
  `calcFinishTime()` `ticksPerPixel` arguments (`24 + 40`, `64 + 32 + 24`, `48`, …).
  Those only feed `statusChangeTime`, which is documented as a lower bound.
* The `Delta` enum carries a comment explaining that the values are
  `work + 14`, that the original measurements only determined them modulo 8, and what
  `D30_NI` means.

## 8. Measured result

Built and run on a Philips NMS 8255 (PAL) with `vdpcmdx.dsk`. ACTIVE block, the three
conditions without CPU contention:

| # | command | NORMAL THIS/REAL | NO SPR THIS/REAL | NO SCR THIS/REAL |
|---|---|---|---|---|
| 1 | HMMM (landscape) | 1915 / 1915 | 2668 / 2673 | 2853 / 2854 |
| 2 | **LMMM** (landscape) | **1340 / 1339** | 1970 / 1971 | 2003 / 2004 |
| 3 | **YMMM** (landscape) | 2111 / 2111 | **3819 / 3797** | 4009 / 3996 |
| 4 | HMMV (landscape) | 4002 / 4005 | 4203 / 4195 | 5311 / 5313 |
| 5 | LMMV (landscape) | 1906 / 1908 | 2104 / 2106 | 2666 / 2668 |
| 6 | HMMM (portrait) | 1915 / 1916 | 2636 / 2659 | 2795 / 2796 |
| 7 | **LMMM** (portrait) | **1333 / 1332** | 1954 / 1955 | 1993 / 1993 |
| 8 | **YMMM** (portrait) | 2111 / 2095 | **3819 / 3689** | 4009 / 3914 |
| 9 | HMMV (portrait) | 3920 / 3922 | 4172 / 4120 | 5093 / 5094 |
| 10 | LMMV (portrait) | 1867 / 1869 | 2105 / 2106 | 2627 / 2627 |

The two target cells:

| | before | after | real |
|---|---|---|---|
| LMMM `NORMAL`, landscape | 1718 (+28.8%) | **1340 (+0.1%)** | 1339 |
| LMMM `NORMAL`, portrait | 1700 (+28.2%) | **1333 (+0.1%)** | 1332 |
| YMMM `NO SPR`, landscape | 2873 (-24.2%) | **3819 (+0.6%)** | 3797 |
| YMMM `NO SPR`, portrait | 2871 (-21.9%) | **3819 (+3.5%)** | 3689 |

Everything else stays within ~1.3%, except the YMMM portrait column, which keeps its
pre-existing +2.4..+3.5% (see section 10). The VBLANK block is unchanged. The
simulator of section 6 predicted 1343 / 1335 / 3840, so it was accurate to within 0.6%.

**Side effect on the CPU-contention columns.** Those were already wrong by -16%..+7%
before this change (section 10) and moving the deltas reshuffles which slot the engine
competes for, so several cells moved — three notably closer (`NORMAL+CPU` HMMM
landscape -8.3% -> -0.3%, YMMM landscape -8.1% -> 0.0%, HMMV landscape -16.1% -> -8.1%),
four notably further (HMMM portrait -1.3% -> -16.4%, HMMV portrait -7.7% -> -15.2%, LMMM
landscape 0.0% -> -12.3%, HMMM portrait `NO SCR+CPU` 0.0% -> -4.3%). Mean absolute error
in those columns goes from 7.0% to 8.1% (`NORMAL+CPU`) and 1.2% to 1.9% (`NO SCR+CPU`).
Note that LMMM `NORMAL+CPU` is now -12.3% for *both* orientations where before landscape
happened to land on 774 exactly while portrait was already at -12.1% — i.e. openMSX is
now internally consistent there, like the hardware, but consistently too slow. This is
the separate arbitration bug, not something the command deltas can fix.

## 9. What would confirm the mechanism

The 2013 measurement set contains **no command-engine capture with the display
enabled** — every command timing was derived from screen-off traces. That is precisely
the gap this analysis has to fit around. New captures that would settle it:

1. **LMMM, screen on, sprites on.** Is the destination read really 64 cycles after the
   source read (A-grid slot `+64`) rather than 32? This is the single measurement that
   turns section 5.2 from a fitted rule into a derived one.
2. **YMMM, screen on, sprites off.** Does the read/write pair really alternate
   `A -> B -> A -> B` at 64 cycles per byte?
3. **The exact B-grid offset** (212 vs 214) and the true pending latency, e.g. by
   varying the command engine's request phase against a known slot position.
4. **LMMM, screen on, sprites off** — confirm the destination read *does* use the A slot
   at +32 there, which is what keeps that column correct today.

Until (1) exists, the LMMM rule should be labelled for what it is: a constraint fitted
to two data points that leaves 28 other cells undisturbed, not a mechanism read off the
hardware.

## 10. Out of scope

* **YMMM portrait** is ~3% fast in openMSX even with the screen off (4032 vs 3914),
  independent of both findings above. openMSX ignores NX for YMMM
  (`clipNX_1_byte<Mode>(DX, 512, ARG)`, `src/video/VDPCmdEngine.cc:1614`), matching the
  datasheet, while real hardware appears to have a small per-rectangle-line cost that
  `slots4.txt`'s `+0` denies. Deserves its own measurement.
* **CPU contention is a different bug**, unaffected in kind by this change (see the
  side-effect note in section 8). With screen + sprites on and the CPU busy, openMSX is
  8-16% *slow*: HMMV 2123 vs 2310, LMMV portrait 968 vs 1158, HMMM portrait 970 vs 1160,
  LMMM 679 vs 774. openMSX gives the CPU absolute priority and makes the
  engine take the very next slot (`stealAccessSlot()`,
  `src/video/VDPCmdEngine.hh:63`, `Delta::D1`), whereas `slots3.txt` documents cases
  where real hardware prefers a command access over a CPU request that has already been
  pending for up to ~16 cycles. Separate issue.
* Character and text mode (`slotsChar`, `slotsText`) are untested by `vdpcmdx`; the
  delta re-basing applies to them too but no reference data exists.
