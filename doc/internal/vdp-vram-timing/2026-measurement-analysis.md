# V9938 command timing against the 2026 logic-analyzer measurements

In 2026 a second set of logic-analyzer captures of the V9938-VRAM bus was made, on a
Philips NMS 8280, and published in the `part2` subdirectory of
<https://github.com/m9710797/vdp-timing-measurements>. Unlike the 2013 set, it covers
all three access-slot patterns (display off, display on with sprites off, display on
with sprites on) with roughly equal weight, and it includes captures with the CPU
accessing VRAM at the same time.

This document fits openMSX's command-engine timing model to that data. It replaces the
earlier reasoning from the 2013 set plus aggregate `vdpcmdx` frame counts, discussed in
<https://github.com/openMSX/openMSX/issues/2057> and
<https://github.com/sndpl/openMSX/pull/5>; the fixes that came out of that discussion
are commits 592ce968c and 7dde62b3f, and the numbers below are measured against that
implementation.

Two scripts in this directory produce every number here:

```
vcd-slot-grid.py <measurement-repo>/part2                  # where the slots are
2026-measurement-check.py <repo>/part2/5.slots             # command timing
2026-measurement-check.py <repo>/part2/5.slots --cpu       # CPU arbitration
2026-measurement-check.py <repo>/part2/5.slots --plain     # without section 4's rules
```

Cycle numbers throughout are openMSX's, which are based on /RAS. The `.txt` analyses in
the measurement repository are based on /CAS and are one higher.

## 1. The model under test

openMSX implements exactly the model Wouter derived in 2013 (`slots3.txt`):

* VRAM access slots are at fixed positions in a display line; which positions depends
  on the screen mode and on whether display and sprites are enabled
  (`VDPAccessSlots.cc`).
* A slot is allocated ~16 cycles in advance. If a CPU request is pending at that
  moment the CPU gets the slot; otherwise the command engine gets it if it has a
  request pending; otherwise the slot goes unused.
* The engine posts its request for access *k+1* a fixed number of cycles after access
  *k* completed. That number depends on the command and on which step of the command
  it is.

openMSX folds the arbitration latency into the per-step number, so one `Delta` value
per command step covers both:

> next access = the first access slot at or after (previous access + delta)

For a single observed pair of consecutive engine accesses (at *p* and *n*), that model
holds for every delta in `[prevSlot(n) - p + 1, n - p]`. Intersecting those intervals
over every observation of one step gives the step's admissible band. An empty band
means no single value can reproduce the data — the interesting case.

## 2. The access slot tables are confirmed, measured from /RAS

`part2/README.md` proposes moving two slots per table one cycle later (in openMSX's
numbering, `slotsScreenOff` 1324 → 1325 and 1334 → 1335, `slotsSpritesOff` 1322 → 1323
and 1332 → 1333). That correction is **wrong**, and openMSX's existing tables are right.

The published `.txt` analyses derive access times by interpolating between the eight
DRAM refresh accesses of a line, which is only eight anchors per line. `/RAS` is a much
better time base: it pulses once per potential access slot whether or not the VDP uses
the slot, and its pattern repeats every display line. `vcd-slot-grid.py` in this
directory measures the grid directly from the raw `part2/1.vcd` captures:

* **Line period.** Exactly one gap per line is larger than all the others, so the sample
  distance between successive occurrences of it is the line period. Fitted per capture
  this gives 5131.13 to 5131.18 samples, very stable. (Taken literally that makes a VDP
  cycle 46.89 ns where 21.477 MHz is 46.57 ns, so the analyser runs about 0.7 % above
  its nominal 80 MHz, or the machine's crystal is off by that much. It cancels, because
  everything is normalised by the measured period.)
* **Numbering.** The refresh accesses are 128 cycles apart with the row address
  incrementing by one and the bank alternating, and between the last of one line and the
  first of the next there are 472 cycles, so the chain has a unique start. That one is
  at cycle 284 — the slot openMSX omits between 276 and 292.
* **Precision.** Over 40 captures each slot is averaged over at least 249 RAS edges with
  a standard deviation of at most 0.31 cycles, so each mean is good to ±0.02.

Result:

| mode | slots per line | gap structure | worst deviation of an openMSX slot |
|---|---|---|---|
| display off | 166 | 163 × 8 + 2 × 10 + 1 × 44 = 1368 | 0.013 cycles |
| sprites off | 132 | 6 × 66 + 8 × 29 + 10 × 2 + 12 + 20 × 32 + 24 + 44 = 1368 | 0.025 cycles |
| sprites on | 126 | irregular (sprite fetches) | 0.055 cycles |

All 154 / 88 / 31 openMSX slots are confirmed. Two further checks that the numbering is
not off by one: openMSX's display-off table is *exactly* the measured 166-slot grid minus
the eight refresh slots (284 + 128k) and the four dummy-read slots (1236, 1244, 1252,
1260), and shifting the anchor by one cycle makes both of those holes stop lining up.

Finally, of the 104 211 accesses in the published `5.slots` files, only 1 108 (1.06 %)
sit at a cycle that is not a measured slot, and they are exactly the two slots of the
proposed correction:

| mode | published position | measured slot | count |
|---|---|---|---|
| display off | CAS 1336 | CAS 1335 | 423 |
| display off | CAS 1326 | CAS 1325 | 236 |
| sprites off | CAS 1334 | CAS 1333 | 295 |
| sprites off | CAS 1324 | CAS 1323 | 154 |
| sprites on | — | — | 0 |

So the retiming is otherwise correct to the cycle, including across the 1181 → 285
stretch where there are no refresh accesses to interpolate between. `2026-measurement-
check.py` moves those accesses back to the measured slot before fitting anything.

## 3. Results

508 traces without CPU activity yield 76 766 engine-to-engine transitions. Under the
plain model — the delay counted in VDP cycles — six steps have no value that fits, and
the three sprites-on steps in bold are disjoint from the other two modes:

| command | step | display off | sprites off | sprites on |
|---|---|---|---|---|
| HMMV | W → W        | [45,48]  | [45,48]  | [33,52]  |
| HMMV | newline      | [101,104]| [103,104]| [97,116] |
| LMMV | R → W        | [20,24]  | [21,24]  | [19,26]  |
| LMMV | W → R        | [69,72]  | [71,72]  | [71,78]  |
| LMMV | newline      | [133,132]! | [133,132]! | [133,148] |
| YMMM | R → W        | [20,24]  | [21,24]  | [9,26]   |
| YMMM | W → R        | [37,40]  | [34,38]  | [33,52]  |
| YMMM | newline      | [101,104]| [103,104]| [97,118] |
| HMMM | R → W        | [20,24]  | [21,24]  | [9,26]   |
| HMMM | W → R        | [61,60]! | [61,60]! | [59,64]  |
| HMMM | newline      | [125,128]| [129,128]! | **[133,134]** |
| LMMM | Rsrc → Rdst  | [29,32]  | [28,32]  | **[33,52]** |
| LMMM | Rdst → W     | [20,24]  | [21,24]  | [9,26]   |
| LMMM | W → Rsrc     | [61,60]! | [61,60]! | [59,64]  |
| LMMM | newline      | [125,128]| [129,128]! | **[131,148]** |
| LINE | R → W        | [18,24]  | [21,24]  | [9,26]   |
| LINE | W → R        | [85,84]! | [85,84]! | [79,90]  |
| LINE | newline      | [117,120]| [119,122]| [117,128]|

`!` marks a band that is empty by one cycle. `newline` is the step from the last write
of one line of the rectangle to the first read of the next. Section 5 shows that all of
the `!` cases and all three of the bold ones come from two mechanisms, not from noise,
and that fixing the first collapses the second.

## 4. What the model needs

Two refinements to the plain model account for everything but 32 of the 76 766
transitions.

### 4.1 The delay is counted in memory cycles, not VDP cycles

The measured display-off grid is 8-cycle regular except for two gaps of 10 in the
blanking region — `... 1316 1324 1334 1344 ...` — i.e. **two memory cycles per line are
stretched by two cycles each**. Every one of the six `!` bands in section 3 is a pair of
observations that straddle that stretch differently. The clearest case, HMMM's write →
read, decoded straight from `scr5-dispOff-hmmm-noCpu-1.vcd` with no interpolation:

```
  80 R 1bd55    104 W 1fd55    164 R 1bd56      W -> R = +60
1268 R 1bd62   1292 W 1fd62   1360 R 1bd63      W -> R = +68
```

From 1292 there *is* a slot at +60 (1352) and the engine skipped it; from 104 the slot at
+60 (164) was taken. The difference is that 1292 → 1352 crosses both stretched memory
cycles and 104 → 164 crosses neither.

> If the engine's delay counter does not see the stretch — i.e. it counts memory cycles
> rather than VDP cycles — the conflict disappears. 1292 → 1352 is then 56 engine cycles,
> so a minimum of 57..60 skips it and takes 1360 (64), while 104 → 164 is 60 either way.

The 44-cycle gap is *not* a stretch: it is five memory cycles that offer no slot, and it
counts in full, which is what HMMV needs (from 120 a 45..48 minimum skips 164 at +44 and
takes 172 at +52).

Note the counter has to be read as restarted at every access: the correction loses four
cycles per line, so it is well defined for an interval but not as a periodic remapping of
the line. That is exactly how the engine behaves — it is a delay from the previous
access, not a position in the line.

### 4.2 With sprites on, every delay is one cycle longer

With 4.1 in place, every step becomes internally consistent in every mode, and the three
steps that still need a sprites-on distinction all need *exactly one cycle more*:

| step | display off / sprites off | sprites on |
|---|---|---|
| LMMM Rsrc → Rdst | [27,32] | [33,52] |
| HMMM newline | [125,128] | [129,134] |
| LMMM newline | [125,128] | [129,148] |

So one rule replaces the three per-command special cases: **with sprite rendering active
every command-engine delay is effectively one cycle longer.** It gives the same 32
mispredictions, and it *forces* LMMM's source→destination read to 32 and the line
transition to 128 — the values the other two modes already wanted. It reads like the
arbitration decision for a slot being taken one cycle earlier while the sprite fetch
logic is active. It cannot be a slot-position effect: shifting the sprites-on slots would
leave intervals within that mode unchanged.

### 4.3 The resulting values

| command | step | admissible | openMSX today |
|---|---|---|---|
| HMMM, LMMM (dst), LMMV, YMMM, LINE | R → W | 21..24 | 24 |
| HMMM, LMMM | W → R(src) | **59..60** | 64 |
| LMMM | R(src) → R(dst) | 27..**32** | 32, and 48 with sprites on |
| HMMV | W → W | 45..48 | 48 |
| LMMV | W → R | 71..72 | 72 |
| YMMM | W → R | 33..38 | 38 |
| LINE | W → R | **81..84** | 88 |
| HMMV | newline | 103..104 | 104 |
| YMMM | newline | 103..104 | 104 |
| LINE | newline | 119..120 | 120 |
| HMMM, LMMM | newline | 125..**128** | 128, and 134 with sprites on |
| LMMV | newline | 129..**132** | 134 |

| model | mispredicted of 76 766 |
|---|---|
| openMSX today | 456 (0.594 %) |
| 4.1 + 4.2, with the deltas above | **32 (0.042 %)** |

The two go together: the deltas above *without* 4.1 give 1970 (2.6 %). The remaining 32
are the single sprites-off outlier of section 6.

Both rules are free at run time. They only change how `VDPAccessSlots.cc` builds its
per-cycle lookup tables — the stretch as a correction inside the table generator, the
sprites-on cycle as a per-table offset — and they would remove the mode conditionals from
the command implementations entirely. **Not implemented yet**: this is a change to the
shape of the model rather than a parameter fix, so it is waiting on agreement in
[sndpl/openMSX#5](https://github.com/sndpl/openMSX/pull/5).

## 5. What is currently in openMSX

Two of openMSX's values were outside the admissible band of the plain model and are
corrected on this branch:

| step | was | now | plain-model band |
|---|---|---|---|
| YMMM `W → R` | 36 | 38 | [37,38] |
| LMMV newline | 136 (= 72 + 64) | 134 (= 72 + 62) | [133,134] |

and the sprites-on deviation known from LMMM's destination read applies to the
line-transition step of both HMMM and LMMM as well, so that step uses 134 instead of 128
when sprite rendering is active. Under section 4 those three become consequences of one
rule rather than separate facts, but they are the right values for the model openMSX has
today.

`vdpcmdx` barely notices, as expected. Measured on a Philips NMS 8255, the ACTIVE block,
non-CPU columns, before → after:

| cell | master | patched | real |
|---|---|---|---|
| LMMM landscape `NORMAL` | 1340 | **1339** | 1339 |
| LMMM portrait `NORMAL`  | 1333 | 1331 | 1332 |
| HMMV landscape `NORMAL` | 4003 | 4002 | 4005 |
| YMMM portrait `NORMAL`  | 2093 | **2094** | 2095 |

and every other non-CPU cell is unchanged. The line-transition step happens once per
rectangle line, so it is worth well under a pixel per frame; and shifting the engine by
one 32-cycle slot at a line transition mostly just moves it to another phase of the same
128-cycle pattern, at the same throughput. An offline simulation of openMSX's own model
over the 192-line active window gives the same answer: HMMM ±0, LMMM landscape −1. The
HMMV and YMMM cells above cannot be affected by any of the three changes, so those two
±1 differences are cross-talk: `vdpcmdx` runs its tests back to back, so a change in one
test shifts the phase at which the next one starts. Two runs of the same binary are
bit-identical, so this is not emulator non-determinism.

The `NORMAL+CPU` column moves by up to 190 pixels in one cell for the same reason,
amplified: with the CPU taking a slot every 72 cycles the engine's slot selection is
chaotically sensitive to its starting phase. That column cannot judge this change (nor,
as Wouter has pointed out, can its hardcoded `REAL` values judge anything at the
few-percent level).

So the justification for these changes is the bus captures, not the aggregate frame
counts.

## 6. The one remaining outlier

In the sprites-off table, HMMM's and LMMM's line-transition step uses the slot exactly
128 cycles later in every observed case except one: starting from cycle 188 the slot at
+128 is skipped and +154 is used. That is 32 of the 835 observations of that step, all
from the same starting cycle.

The sprites-off display area has its slots in pairs 6 cycles apart, at offsets
{0, 6, 32, 38, 64, 70, 96} of every 128 cycles. Cycle 188 is the second slot of a pair,
and so is its +128 target; every observation that *does* use the +128 slot starts from
one of the offsets 0, 32, 64 or 96. So the one candidate rule the data offers is that the
engine cannot use a slot that follows only 6 cycles after another slot when its request
became pending in that window. But there is exactly one starting position in the data
that tests this, so it is a single coincidence away from being noise. openMSX does not
model it.

## 7. Five traces were mislabelled

`scr5-dispOff-hmmv-noCpu-nx2-6d`, `scr5-dispOff-lmmv-noCpu-nx2-3d`,
`scr5-dispOff-ymmm-noCpu-nx12-1d`, `scr5-sprOff-lmmm-noCpu-nx2-3d` and
`scr5-sprOff-lmmv-noCpu-nx8-5d` were named `noCpu` but contained CPU accesses. Before
excluding them they were the *only* source of inconsistency in the middle of a display
line — every other anomaly is at the blanking boundary or is the sprites-on effect of
section 4.2. They have since been fixed or renamed to `scr5-wrong-*` in the measurement
repository, and the `d` sets have been relabelled.

One labelling subtlety remains, which is not a mistake: the unclassified read of
`0x1ffff` is the VDP's dummy read in most traces, but in a few YMMM captures the
command's own source pointer walks through the top of VRAM and produces genuine command
accesses at that address. The check script distinguishes the two by looking at the rest
of the trace.

## 8. CPU contention: openMSX's arbitration is confirmed

The `rdCpu` / `wrCpu` traces give 12 302 engine transitions with CPU accesses 64 to 72
cycles apart — the same rate as the `OUT (#98),A` loop of `vdpcmdx`'s `+CPU` tests — and
the CPU takes the slot the engine wanted in **29.9 %** of them. Applying openMSX's rule

> the engine takes the first slot at or after its minimum that the CPU did not take
> (`VDPCmdEngine::stealAccessSlot`)

to the observed CPU access times:

| | wrong |
|---|---|
| openMSX today | 125 (1.016 %) |
| the model of section 4 | **99 (0.805 %)** |
| section 4, but the loser re-arms its full delay instead of taking the next slot | 3086 (25.1 %) |

Two consequences:

* The `stealAccessSlot` model is right, including the detail that a command engine which
  loses a slot takes the *next* slot rather than re-arming its full delay.
* The hypothesis floated earlier in
  [sndpl/openMSX#5](https://github.com/sndpl/openMSX/pull/5) — that under contention real
  hardware uses slots closer together than the command's own minimum spacing — is
  refuted. Outside the blanking-boundary cases the engine never accesses VRAM earlier
  than its uncontended minimum allows.

So whatever is left of the `+CPU` disagreement in `vdpcmdx` is not in the arbitration
model. Given that the tool's `REAL` column is a single run on one machine and that
hardware itself varies by several percent between runs, that column is not a useful
calibration target; a CPU-loop-period sweep would be.

## 9. What would help next

* **The sprites-on cycle.** Section 4.2 is a uniform rule fitted to three steps. A
  software-only test that would strengthen it: time HMMM's line transition (a rectangle
  one byte wide and many lines tall, so the transition dominates the whole command) in
  sprites-on mode against LMMV's `W → R` and HMMV's `W → W` in the same mode, and check
  that the one-cycle difference shows up where the model says it should.
* **The blanking stretch.** Section 4.1 predicts that a command started at a phase where
  its next access would land just after the stretch behaves four cycles differently from
  one that does not cross it. A phase-resolved completion-time measurement — sync to the
  line interrupt, burn a programmable number of cycles, start a one- or two-pixel
  command, then poll S#2 once — resolves a single command's finish time to about six
  cycles and would test that directly.
* **Command startup cost.** Still never measured. It is invisible to `vdpcmdx` (one
  command per frame of 10240 pixels). `part2` contains three `*-start-*` captures that
  reach step 4 but not `5.slots`; without knowing what the capture was triggered on they
  cannot be turned into a number, but if that is recoverable they would be the first
  direct measurement of it. Otherwise the same small-command rig would expose it as an
  offset in the completion-time distribution.
