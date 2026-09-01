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
are commits 592ce968c and 7dde62b3f. Everything section 4 and section 6 describe is
implemented, in commit 5b0327eaf; the "openMSX today" rows below are measured against
the state before it.

Two scripts in this directory produce every number here:

```
vcd-slot-grid.py <measurement-repo>/part2                  # where the slots are
2026-measurement-check.py <repo>/part2/5.slots             # command timing
2026-measurement-check.py <repo>/part2/5.slots --cpu       # under CPU contention
2026-measurement-check.py <repo>/part2/5.slots --plain     # without section 4's rules
cpu-arbitration-model.py <measurement-repo>                # the CPU's own slots
```

Cycle numbers throughout are openMSX's, which are based on /RAS. The `.txt` analyses in
the measurement repository are based on /CAS, which normally follows /RAS by one cycle —
but not for two slots per table, see section 2.

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

`part2/README.md` proposes moving two slots per table one cycle later. openMSX's tables
need no change, and the apparent disagreement is a difference of convention, not an
error on either side — see the end of this section.

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

Of the 104 211 accesses in the published `5.slots` files, only 1 108 (1.06 %) sit at a
cycle that is not a /RAS slot, and they are exactly the two slots of the proposed
correction (display off CAS 1326 and 1336, sprites off CAS 1324 and 1334; sprites on has
none). So the retiming is otherwise correct to the cycle, including across the
1181 → 285 stretch where there are no refresh accesses to interpolate between.

**Why the two conventions disagree there.** /CAS normally follows /RAS by one cycle. For
exactly those slots it follows by two:

| mode | single-/CAS accesses | with a 1-cycle /RAS → /CAS delay | with 2 cycles |
|---|---|---|---|
| display off | 4 862 | 4 839 | 23, all at RAS 1324 and 1334 |
| sprites off | 4 382 | 4 336 | 46, all at RAS 1322 and 1332 |
| sprites on | 8 036 | 8 036 | none |

(Burst accesses — one /RAS with several /CAS — are excluded; those are the display
fetches.) So openMSX's /RAS-based 1324 / 1334 and the measurement repository's /CAS-based
1326 / 1336 describe the same two slots, and the only wrong assumption was that the
conversion between them is a uniform one cycle. `2026-measurement-check.py` subtracts two
rather than one for those slots.

That the extra /CAS delay lands on exactly the two slots that start the 10-cycle gaps is
not a coincidence: they are the stretched memory cycles of section 4.1.

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
transitions; the third, in section 6, accounts for those.

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

### 4.2 With sprites on, every delay is two cycles longer

With 4.1 in place, every step becomes internally consistent in every mode, and the steps
that still need a sprites-on distinction all need the *same* extra amount. So one rule
replaces the three per-command special cases: **with sprite rendering active every
command-engine delay is two cycles longer.** It reads like the arbitration decision for a
slot being taken two cycles earlier while the sprite fetch logic is active — the CPU
arbitration wants a similar amount (section 8.2). It cannot be a slot-position effect:
shifting the sprites-on slots would leave intervals within that mode unchanged.

The size of this depends on how much padding sprites-on mode has in the blanking region,
which is why section 4.4 had to be settled first: with the padding measured directly the
answer is two cycles, and LMMM's source→destination read and the line transition come out
at the round 32 and 128 that the other two modes already want.

### 4.3 The resulting values

| command | step | admissible | chosen | openMSX before |
|---|---|---|---|---|
| HMMM, LMMM (dst), LMMV, YMMM, LINE | R → W | 21..24 | 24 | 24 |
| HMMM, LMMM | W → R(src) | 59..60 | **60** | 64 |
| LMMM | R(src) → R(dst) | 27..32 | **32** | 32, and 48 with sprites on |
| HMMV | W → W | 45..48 | **46** | 48 |
| LMMV | W → R | 71..72 | **72** | 72 |
| YMMM | W → R | 33..38 | **36** | 38 |
| LINE | W → R | 81..84 | **84** | 88 |
| HMMV | newline | 103..104 | **104** | 104 |
| YMMM | newline | 103..104 | **104** | 104 |
| LINE | newline | 119..120 | **120** | 120 |
| HMMM, LMMM | newline | 125..128 | **128** | 128, and 134 with sprites on |
| LMMV | newline | 129..132 | **130** | 134 |

The values in the `chosen` column are Wouter's, picked so that each command has one
per-line overhead that all of its steps share: HMMV 46 + 58 and 104 = 46 + 58, LMMV
24 + 72 + 58, YMMM 24 + 36 + 68, HMMM 24 + 60 + 68, LMMM 32 + 24 + 60 + 68, LINE
24 + 84 + 36. Those constraints have almost no freedom left in them: a shared *even*
overhead for the two fills forces 58 and with it HMMV 46 and LMMV 72, a shared even
overhead for the three copies forces 68 and with it YMMM 36 and HMMM/LMMM 60. Only
R → W ∈ {22, 24} and LINE ∈ {84 + 36, 82 + 38} are left, and both are settled by
preferring the multiple of 4. The fills and the copies cannot share one overhead --
[57,59] and [68,69] are disjoint -- and no assignment makes every value a multiple of 8.

| model | mispredicted of 76 766 |
|---|---|
| openMSX today | 456 (0.594 %) |
| 4.1 + 4.2, with the deltas above | 32 (0.042 %) |
| and section 6 | **0** |

The rules go together: the deltas above *without* 4.1 give 1970 (2.6 %). The same model
gets the 2013 set right as well -- 3965 transitions, 0 wrong -- once the truncation of
`screen5screenoffHMMVnocpu.txt` is taken into account.

Both rules are free at run time: they only change how `VDPAccessSlots.cc` builds its
per-cycle lookup tables — the stretch as a correction inside the table generator, the
sprites-on cycle as a per-table offset — and they remove the mode conditionals from the
command implementations entirely. See the `Timing` struct in `VDPAccessSlots.cc`. The character, text and MSX1 tables are left alone, having never
been measured this way.

`vdpcmdx` improves as well, which it did not have to, since none of this was fitted to
it. Active area, non-CPU columns, before → after (real hardware in brackets):

| cell | before | after | real |
|---|---|---|---|
| HMMM portrait `NO SPR`  | 2636 | **2658** | 2659 |
| HMMM landscape `NO SPR` | 2668 | **2672** | 2673 |
| LMMM landscape `NO SPR` | 1970 | **1971** | 1971 |
| LMMM portrait `NO SPR`  | 1954 | **1955** | 1955 |
| YMMM landscape `NO SPR` | 3796 | **3797** | 3797 |
| YMMM landscape `NO SCR` | 3994 | 3995 | 3996 |

Every non-CPU cell is now within 3 pixels of the reference. Nothing else in the non-CPU
columns changed.

### 4.4 Where the padding is, per mode

The stretch of 4.1 is the VDP padding its line out to 1368 cycles. Measured from /RAS over
the whole blanking region, not just the slots the command engine can use, the three
bitmap modes do it differently:

| mode | ordinary spacing there | padded cycles | total |
|---|---|---|---|
| display off | 8 | two of 10, at 1324→1334→1344 | +4 |
| sprites off | 8 | two of 10, at 1322→1332→1342 | +4 |
| sprites on | 13, 6, 10 repeating | three of 15, 7, 11, at 1315→1330→1337→1348 | +3 |

The sprites-on row was guesswork until the `s16`/`s32`/`s48` captures arrived, because in
that mode the padded cycles are sprite fetches rather than command slots. Section 10 shows
how those captures settle it.

Getting it right matters: with the sprites-on padding assumed to be +4 like the other two
modes, the sprites-on cost of 4.2 comes out as one cycle instead of two, and the fit is
equally good. Both were consistent with the command traces; the direct measurement is what
separates them.

## 5. History: the parameter-only fix

Superseded by section 4, kept because the `vdpcmdx` comparison below is the only
end-to-end check of the whole chain. Two of openMSX's values were outside the admissible
band of the plain model and were corrected first:

| step | was | now | plain-model band |
|---|---|---|---|
| YMMM `W → R` | 36 | 38 | [37,38] |
| LMMV newline | 136 (= 72 + 64) | 134 (= 72 + 62) | [133,134] |

and the sprites-on deviation known from LMMM's destination read applies to the
line-transition step of both HMMM and LMMM as well, so that step used 134 instead of 128
when sprite rendering was active. Under section 4 all three become consequences of the
two table properties rather than separate facts.

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

## 6. Slots that follow another slot after only 6 cycles

The sprites-off display area has its slots in pairs 6 cycles apart, at offsets
{0, 6, 32, 38, 64, 70, 96} of every 128 cycles. Reading the raw captures, the pair is
the *freed sprite fetch* and the memory cycle that is spare in both modes: with sprites
on, the cycle at 182 + 32k fetches sprite data and the one at 188 + 32k is free; with
sprites off, both are free. 25 of the 88 sprites-off slots are the second of such a
pair. Neither the display-off nor the sprites-on table has any.

Two independent effects follow from that, and both are needed:

**The command engine pays one cycle.** A step whose *previous* access was in one of
those 25 slots takes one cycle longer, as if that memory cycle -- squeezed against its
predecessor -- had finished one cycle late. 1778 transitions in the 2026 set start from
such a slot: 32 of them (HMMM's and LMMM's line transition from cycle 188) need the extra
cycle, and 1281 of them rule out a third cycle. So the band is exactly [1, 2]; openMSX
adds 1. Without it those 32 are the only mispredictions left in the whole set.

**The CPU never gets one.** Of 4550 CPU accesses in the sprites-off captures of both
measurement sets, **zero** are in one of those 25 slots, while all 63 other slots are
used. That is not a coincidence of the request phase: with the requests arriving 71.5
cycles apart against a 32-cycle slot pattern, an unconstrained model puts 11 % of them
there.

What happens instead is visible in the traces. Every unclassified read of `0x1ffff`
outside the four-slot dummy-read block of a normal line -- 335 of them, in the
sprites-off CPU captures and nowhere else -- sits in one of those 25 slots and is
followed by a CPU access in the next slot (322 at +26, 10 at +54). So the VDP *does* give
the slot to the CPU; it just cannot carry a CPU access, spends the memory cycle on a
dummy read, and does the access one slot later.

That also explains the last of the engine mispredictions in the CPU captures: the engine
was not skipping a free slot, the slot was occupied by that dummy read.

## 7. Traces that were mislabelled

`scr5-dispOff-hmmv-noCpu-nx2-6d`, `scr5-dispOff-lmmv-noCpu-nx2-3d`,
`scr5-dispOff-ymmm-noCpu-nx12-1d`, `scr5-sprOff-lmmm-noCpu-nx2-3d` and
`scr5-sprOff-lmmv-noCpu-nx8-5d` were named `noCpu` but contained CPU accesses. Before
excluding them they were the *only* source of inconsistency in the middle of a display
line -- every other anomaly is at the blanking boundary or is the sprites-on effect of
section 4.2. They have since been fixed or renamed to `scr5-wrong-*` in the measurement
repository, and the `d` sets have been relabelled.

Two accesses in the CPU captures still carry the wrong code, and they are the only
remaining mispredictions of the engine model there:

* `scr5-sprOn-hmmm-rdCpu-1.txt` has no `R.r` at all: the CPU's reads (0x1849a upwards)
  are coded `R.s`, together with the command's own source reads (0x1a1c2 upwards).
* `scr5-sprOn-hmmv-wrCpu-3.txt` has one `R.s 19e91` at cycle 4452 which belongs to the
  CPU's write sequence (…19e90, 19e91, 19e92…) -- HMMV has no source read.

One labelling subtlety is not a mistake: the unclassified read of `0x1ffff` is the VDP's
dummy read in most traces, but in a few YMMM captures the command's own source pointer
walks through the top of VRAM and produces genuine command accesses at that address. The
check script distinguishes the two by looking at the rest of the trace.

## 8. The CPU side

### 8.1 The engine model under contention

The `rdCpu` / `wrCpu` traces give 12 302 engine transitions with CPU accesses about 71.5
cycles apart, and the CPU takes the slot the engine wanted in **30 %** of them. Applying
openMSX's rule

> the engine takes the first slot at or after its minimum that the CPU did not take
> (`VDPCmdEngine::stealAccessSlot`)

to the observed CPU access times:

| | wrong |
|---|---|
| openMSX today | 90 (0.732 %) |
| the model of sections 4 and 6 | **3 (0.024 %)** |
| the same, but the loser re-arms its full delay instead of taking the next slot | 3086 (25.1 %) |

and the remaining 3 are the two mislabelled accesses of section 7. So `stealAccessSlot`
is right, including the detail that a command engine which loses a slot takes the *next*
slot rather than re-arming its full delay. The hypothesis floated earlier in
[sndpl/openMSX#5](https://github.com/sndpl/openMSX/pull/5) -- that under contention real
hardware uses slots closer together than the command's own minimum spacing -- is
refuted.

### 8.2 The CPU's own model

`cpu-arbitration-model.py` fits the other half: which slot a CPU port access ends up in.
The two measurement sets are complementary. The 2013 machine (NMS 8250) has a single
clock, so the port accesses sit on an exact grid with one unknown phase per capture. The
2026 machine (NMS 8280) has separate CPU and VDP clocks, but /CSR and /CSW were recorded,
so the pace of the port accesses is measurable.

The model:

1. **A constant delay** between the port access and the moment the arbiter sees the
   request. This is wall-clock time -- it is a pin-to-register delay, not something the
   memory sequencer counts -- and it is not separable from the fitted phase, so it is
   simply absorbed into it.
2. **A lookahead of 16 memory cycles at the arbiter.** The CPU gets the first eligible
   slot at least that far away, counted in the VDP's memory cycles with exactly the same
   padding subtraction as the command engine's delays.
3. **One request register.** A port access arriving while it is occupied is lost -- no
   VRAM access happens for it, and the VDP's VRAM pointer does not advance, so the CPU
   sees the previous byte again. It stays occupied until 2 cycles after the access.
   openMSX models this (`VDP::scheduleCpuVramAccess`, `tooFastCallback`); what the
   measurements add is that the *old* request wins, which is also what openMSX does.
4. A slot that follows another slot after 6 cycles is decided 2 cycles earlier than the
   rest, and carries the dummy read of section 6 instead of the CPU's access.

The 2013 set constrains the lookahead and the dead window only through their sum: any
(lookahead, dead window) with lookahead + dead = 18 and lookahead ≤ 16 fits it exactly.
16 + 2 is the top of that band and matches the 16 cycles openMSX already uses
(`Delta::CPU_16`).

Fit:

| set | CPU accesses | not predicted | predicted but absent |
|---|---|---|---|
| 2013, exact grid, one phase per capture | 1141 | **0** | **0** |
| 2026, fitted pace, one offset per capture | 14766 | 121 (0.82 %) | 116 |

For the 2026 set the requests are not taken from the individual /CSx edges but from a
straight line fitted through the whole capture: the Z80's own crystal makes the port
accesses a perfectly regular sequence in Z80 time, and one line through ~115 of them has
a residual of 0.15 cycles, well under the analyzer's 0.27-cycle sampling step. The fitted
rate is **5.96113 ± 0.00004 VDP cycles per Z80 T-state**, where a single-clock machine
would give exactly 6 -- the Z80 of that NMS 8280 runs 0.65 % fast relative to its VDP.
Two different test programs (40 port accesses 12 T-states apart, and 20 of them 37
T-states apart) give the same rate to 1 part in 10^5.

The VDP can only act on an asynchronous /CSx at one of its own clock edges, so the
request times are rounded up to whole VDP cycles. That is worth something: 143
mispredictions with the rounding, 165 without, 168 if the rounding is to 2 cycles and 833
if it is to 4 (measured before the model was changed to the split form above, but the
ordering is what matters). So the VDP samples /CSx on a 1-cycle grid.

Per pace and mode, with the constant of point 1 fitted per capture:

| pace | mode | accesses | not predicted | lost requests | constant |
|---|---|---|---|---|---|
| 72 | display off | 4793 | 43 (0.90 %) | 0 of 4848 | 9.85 ± 0.12 |
| 72 | sprites off | 4346 | 16 (0.37 %) | 12 of 4385 | 9.84 ± 0.11 |
| 72 | sprites on | 3703 | 59 (1.59 %) | 304 of 4022 | 12.10 ± 2.01 |
| 222 | display off | 675 | 1 (0.15 %) | 0 of 685 | 9.75 ± 0.22 |
| 222 | sprites off | 608 | **0** | 0 of 610 | 9.72 ± 0.30 |
| 222 | sprites on | 641 | 2 (0.31 %) | 0 of 646 | 10.61 ± 1.18 |

The 222-cycle captures are the ones with a slow CPU loop, made specifically to remove the
lost requests, and they do: 3 of 1924 accesses mispredicted, and one whole mode exact.
The constant repeats to ±0.01 cycles between display-off and sprites-off and to ±0.15
between the two paces, which is a good check on the whole chain -- the analyzer time
base, the slot grid, the pace fit and the model. Sprites-on wants 1 to 2 cycles more, in
the same direction as the command engine's two extra cycles in that mode, but with a much
larger scatter because that mode has the fewest slots per line.

Of the 121 that are left, 21 are the *first* access of their capture, which is 15 times
the rate the remaining positions show. That is the one thing the model cannot know: a
capture starts at an arbitrary point in the test program, so there may already be a
request in flight. 107 of the other 112 are isolated single slots.

## 9. What would help next

* **Command startup cost.** Still never measured. It is invisible to `vdpcmdx` (one
  command per frame of 10240 pixels). `part2` contains three `*-start-*` captures that
  reach step 4 but not `5.slots`; without knowing what the capture was triggered on they
  cannot be turned into a number, but if that is recoverable they would be the first
  direct measurement of it. Otherwise: sync to the line interrupt, burn a programmable
  number of cycles, start a one- or two-pixel command, poll S#2 once. The same rig would
  test section 4.1 directly, since it predicts that a command whose next access lands
  just after the padding behaves differently from one that does not cross it.
* **Alternating read and write.** Nothing in either set can tell whether a read and a
  write reach the arbiter with the same delay: each capture is all reads or all writes,
  so any difference disappears into the fitted constant. A loop that alternates them
  would separate the two.
* **Sprites-on with a slow loop and more slots.** The sprites-on constant of section 8.2
  is still the loosest number in the model (±1.2 cycles even at the slow pace), simply
  because that mode has 31 slots per line. Splitting the lookahead from the constant
  delay -- the two are only separable where the padding falls inside the lookahead window
  -- would need captures with requests deliberately placed near cycle 1330.
* **The 1365-cycle modes.** Section 10 measures the line length and where the padding
  goes, but openMSX does not implement those modes at all. If it ever does, the
  prediction is that the command engine needs no padding correction there.

## 10. Where the padding comes from: R#9 S1/S0, measured

The V9938 data book documents bits S1 and S0 of R#9 as selecting one of three "cycle
modes", and gives 1368 cycles per horizontal line for S1,S0 = 0,0 but 1365 for the other
two settings (section 5 "Cycle mode" and section 7-1 "Horizontal display parameters").
The `scr5-sprOn-hmmv-noCpu-s{0,16,32,48}-*e.vcd` captures test that directly. Taking the
line period and the refresh interval both in analyzer samples, so that nothing has to be
assumed about either, the line comes out as 128 x period / refresh:

| R#9 | line length |
|---|---|
| s = 0 | 1368.01 ± 0.04 |
| s = 16 | 1364.94 ± 0.12 |
| s = 32 | 1364.94 ± 0.09 |
| s = 48 | 1365.01 ± 0.10 |

So 1368 and 1365 exactly, as documented. And the three cycles come off precisely where
section 4.1 says the padding is: in sprites-on mode the blanking region runs

```
S1,S0 = 0,0 :  ... 13   6  10   6  10   6  13  [15   7  11]  6  10   6  13  13   6 ...
otherwise   :  ... 13   6  10   6  10   6  13  [14   6  10]  6  10   6  13  13   6 ...
```

— the same grid with three memory cycles one cycle shorter, which is the 1365-cycle line
plus the padding. Everything else in the line is unchanged, and the horizontal
set-adjust captures (`adjust0` … `adjust15`) leave the line at 1368.02 ± 0.03 in all five
settings, as expected.

That confirms the mechanism behind section 4.1: the padding is real, it sits in the
blanking region, and the command engine's delay counter does not see it. It also fixes
the amount per mode, which section 4.4 could not do from the command traces alone.

Data book: <https://www.mirrorservice.org/sites/www.bitsavers.org/pdf/yamaha/Yamaha_V9938_MSX-Video_Technical_Data_Book_Aug85.pdf>,
transcription: <https://map.grauw.nl/resources/video/v9938/v9938.xhtml>.
