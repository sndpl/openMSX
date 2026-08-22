# V9938 command timing against the 2026 logic-analyzer measurements

In 2026 a second set of logic-analyzer captures of the V9938-VRAM bus was made, on a
Philips NMS 8280, and published in the `part2` subdirectory of
<https://github.com/m9710797/vdp-timing-measurements>. Unlike the 2013 set, it covers
all three access-slot patterns (display off, display on with sprites off, display on
with sprites on) with roughly equal weight, and it includes captures with the CPU
accessing VRAM at the same time.

This document fits openMSX's command-engine timing model to that data. It supersedes
`issue-2057-analysis.md`, which argued from the 2013 set plus aggregate `vdpcmdx`
frame counts; the fixes discussed there have since landed in openMSX in a different
form (commits 592ce968c and 7dde62b3f), and the numbers below are measured against
that implementation.

The script that produces every number here is `2026-measurement-check.py` in this
directory:

```
2026-measurement-check.py <measurement-repo>/part2/5.slots          # command timing
2026-measurement-check.py <measurement-repo>/part2/5.slots --cpu    # CPU arbitration
```

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

## 2. The access slot tables are confirmed

The measured slot histograms (`part2/5.slots/histogram-*`) match openMSX's three
V99x8 bitmap tables **exactly** — 154, 88 and 31 slots — once two slots per table are
corrected by one cycle, as noted in the measurement repo's `part2/README.md`. In
openMSX's numbering (the measurements are openMSX + 1):

| table | correction |
|---|---|
| `slotsScreenOff` | 1324 → 1325, 1334 → 1335 |
| `slotsSpritesOff` | 1322 → 1323, 1332 → 1333 |
| `slotsSpritesOn` | none |

Every slot in all three tables is hit at least 17 times in the data, so the tables are
well sampled, not extrapolated. **These two corrections per table are not applied in
openMSX yet** — see section 6, where the same region turns out to be the source of
every remaining discrepancy; correcting the slots without resolving that is likely to
make things worse rather than better.

## 3. Results

511 traces without CPU activity yield 76542 engine-to-engine transitions. Admissible
band per command step and mode, next to the value openMSX uses and the number of
transitions it gets wrong:

| command | step | display off | sprites off | sprites on | openMSX | wrong |
|---|---|---|---|---|---|---|
| HMMV | W → W        | [45,48]  | [45,48]  | [33,52]  | 48  | 0 |
| HMMV | W → R newline| [101,104]| [103,104]| [97,116] | 104 | 0 |
| LMMV | R → W        | [20,24]  | [21,24]  | [19,26]  | 24  | 0 |
| LMMV | W → R        | [69,72]  | [71,72]  | [71,78]  | 72  | 0 |
| LMMV | W → R newline| [133,132]! | [133,132]! | [133,148] | 134 | 42 |
| YMMM | R → W        | [20,24]  | [21,24]  | [9,26]   | 24  | 0 |
| YMMM | W → R        | [37,40]  | [34,38]  | [33,52]  | 38  | 0 |
| YMMM | W → R newline| [101,104]| [103,104]| [97,118] | 104 | 0 |
| HMMM | R → W        | [20,24]  | [21,24]  | [9,26]   | 24  | 0 |
| HMMM | W → R        | [61,60]! | [61,60]! | [59,64]  | 64  | 291 |
| HMMM | W → R newline| [125,128]| [129,128]! | **[133,134]** | 128 / 134 | 18 |
| LMMM | Rsrc → Rdst  | [29,32]  | [28,32]  | **[33,52]** | 32 / 48 | 0 |
| LMMM | Rdst → W     | [20,24]  | [21,24]  | [9,26]   | 24  | 0 |
| LMMM | W → Rsrc     | [61,60]! | [61,60]! | [59,64]  | 64  | 62 |
| LMMM | W → R newline| [125,128]| [129,128]! | **[131,148]** | 128 / 134 | 14 |
| LINE | R → W        | [18,24]  | [21,24]  | [9,26]   | 24  | 0 |
| LINE | W → R        | [85,84]! | [85,84]! | [79,90]  | 88  | 28 |
| LINE | W → R newline| [117,120]| [119,122]| [117,128]| 120 | 0 |

`!` marks a band that is empty by one cycle; bold marks a sprites-on band that is
disjoint from the other two modes. `newline` is the step from the last write of one
line of the rectangle to the first read of the next.

The five values that work in every mode, for the steps that have no anomaly, are:

```
HMMV                  : W 45..48  (+56..58 for the next line)
LMMV                  : R 21..24  W 71..72
YMMM                  : R 21..24  W 37..38  (+66 for the next line)
HMMM                  : R 21..24
LMMM                  :           Rdst 21..24
LINE                  : R 21..24  W 85..88  (+32..34 for the next line)
```

These agree with the values Wouter posted, with two exceptions:

* **LMMV's line overhead.** `R 24 W 72 (+58)` gives 130 for the newline step; the
  measurements need 133 or 134 (openMSX now uses 134).
* **HMMM/LMMM's `W → R`.** `62` sits in the display-off band but the sprites-off band
  is `[59,60]`; no value satisfies both, see section 6.

## 4. What changed in openMSX

Two of openMSX's values were outside the admissible band and are now corrected:

| step | was | now | band |
|---|---|---|---|
| YMMM `W → R` | 36 | 38 | [37,38] |
| LMMV newline | 136 (= 72 + 64) | 134 (= 72 + 62) | [133,134] |

and the sprites-on deviation known from LMMM's destination read turns out to apply to
the line-transition step of both HMMM and LMMM as well (section 5), so that step now
uses 134 instead of 128 when sprite rendering is active.

Together these take openMSX from 1211 mispredicted transitions (1.58%) to 455 (0.59%).

`vdpcmdx` barely notices, as expected. Measured on a Philips NMS 8255, the ACTIVE
block, non-CPU columns, before → after:

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
HMMV and YMMM cells above cannot be affected by any of the three changes (in
sprites-on mode all three select the same slot as before for those commands), so those
two ±1 differences are cross-talk: `vdpcmdx` runs its tests back to back, so a change in
one test shifts the phase at which the next one starts. Two runs of the same binary are
bit-identical, so this is not emulator non-determinism.

The `NORMAL+CPU` column moves by up to 190 pixels in one cell for the same reason,
amplified: with the CPU taking a slot every 72 cycles the engine's slot selection is
chaotically sensitive to its starting phase. That column cannot judge this change (nor,
as Wouter has pointed out, can its hardcoded `REAL` values judge anything at the
few-percent level).

So the justification for these changes is the bus captures, not the aggregate frame
counts.

## 5. Anomaly 1 — sprites-on needs more, for exactly the delays that are a multiple of 32

Three steps have a sprites-on band that is disjoint from the display-off and
sprites-off bands. In all three the engine skips the slot the other two modes would
have used and takes the next one:

| step | other modes | sprites on | what happens |
|---|---|---|---|
| LMMM Rsrc → Rdst | ≤ 32  | ≥ 33  | the slot at exactly +32 is not used, +64 is |
| HMMM newline     | ≤ 128 | ≥ 133 | the slot at exactly +128 is not used, +160 is |
| LMMM newline     | ≤ 128 | ≥ 131 | idem |

In the display area the sprites-on table has its free slots exactly 32 cycles apart
(three per 128 cycles, the fourth taken by the sprite fetch). So in every one of the
three cases the value that the other modes allow is **an exact multiple of the
sprites-on slot pitch**, and the engine behaves as if it needed one cycle more than
that. Of the fifteen other command steps, not one has a band whose upper limit is a
multiple of 32, and not one shows a sprites-on deviation. That is 3 out of 3 versus
15 out of 15.

This kills the explanation that was previously on the table — that LMMM is special
because it is the only command with two consecutive reads. HMMM has one read and one
write, and its line-transition step deviates in exactly the same way. What the three
cases have in common is not the command but the arithmetic: the delay lands exactly on
a slot.

It is worth being precise about what this does and does not establish:

* It is a complete characterisation of the anomaly *in this data set*, and it makes a
  falsifiable prediction: any command step whose delay is an exact multiple of 32 will
  show the deviation in sprites-on mode, and no other step will.
* It is **not** a mechanism, and it cannot be turned into one by changing the
  comparison from "at or after" to "strictly after". Any rule that depends only on the
  distance to the candidate slot is mode-independent by construction, and the data is
  not: display-off demonstrably *does* use the slot exactly 32 cycles after LMMM's
  source read. The mode dependence is real, so openMSX keeps a mode-dependent value.
* The natural reading is that in sprites-on mode the engine's request arrives one cycle
  too late for the allocation of that slot — e.g. because the sprite fetch logic holds
  the arbiter a cycle longer. But a uniform "+1 cycle of arbitration latency in
  sprites-on mode" does not fit: it would predict 129 for the line-transition step,
  where the data needs 131..134.

## 6. Anomaly 2 — transitions across the horizontal-blanking boundary

Every one of the 455 remaining mispredictions, and every one of the six bands that are
empty by one cycle, involves a transition that crosses one of the two large holes in
the slot table, i.e. the boundary between the dense burst of slots around the line
boundary (the horizontal blanking and border) and the slots in the display area.

The signature is uniform: hardware lands one slot away from the prediction, and the
disagreement is always about 4 cycles.

```
display off, HMMM W->R, from cycle 105:   slots at +8 +16 [+60] +68 ...
                                          openMSX picks +68, hardware +60
sprites off, HMMM W->R, from cycle 1291:  slots at +8 +16 +24 +32 +42 +52 [+60] +68
                                          openMSX picks +60, hardware +68
```

Both of those cannot be satisfied by one delta, and 4 cycles is precisely how much the
slot grid shifts phase at each of those two boundaries: in the display-off table the
slots run on an 8-cycle grid at phase 1 through the blanking burst and at phase 5
through the display area, and the two 4-cycle steps between them add up to one full
8-cycle period per line. The sprites-off table has the same structure.

That the residue is confined to exactly those two boundaries, and is exactly the size
of that phase step, points at the relative alignment of the two groups of slots rather
than at the command engine. The retiming step of the analysis anchors on the refresh
accesses, which occur every 128 cycles from cycle 285 to 1181 — i.e. only in the
display area. The blanking burst is extrapolated, so its position relative to the
display-area slots is the one degree of freedom the measurements do not pin down.

Allowing that alignment to float by a couple of cycles resolves it. Shifting the
blanking-burst slots 2 cycles earlier relative to the display-area slots (and the two
odd slots 1326/1336 by one) makes **every** band in the display-off table consistent,
and leaves the sprites-off table with only the single outlier of section 7 (a 2-cycle
shift of the same kind works there too). Under that alignment the steps of section 3
tighten to:

```
HMMM / LMMM  W -> R(src)  59..60      (openMSX uses 64; on an 8-cycle grid
                                       both pick the same slot except at the
                                       blanking boundary)
LINE         W -> R       83..86      (openMSX uses 88, same remark)
LMMV         newline      133..134    (openMSX uses 134)
```

and, with sprites off, LMMM's source-to-destination read tightens to [28,31], so under
this alignment even the display-off/sprites-off value for that step is no longer an
exact multiple of 32 — which weakens, without refuting, the characterisation of
section 5.

This is a fitted correction to somebody else's raw data, so it is offered as the most
likely explanation rather than as a conclusion. Two things would settle it:

* The alternative is that the engine really does behave differently across the
  blanking boundary. That would be visible as a ±4 cycle effect in a
  completion-time measurement (see section 9) with the command started at phases
  either side of the boundary.
* The 2013 set can be re-checked at those boundaries independently: it uses the same
  refresh-anchored retiming, so it should show the same 4-cycle offset — or not.

Note that this is also why openMSX should *not* simply apply the two one-cycle slot
corrections of section 2 in isolation: those slots sit in exactly the region whose
alignment is in question.

## 7. Anomaly 3 — one sprites-off outlier

In the sprites-off table, HMMM's and LMMM's line-transition step uses the slot exactly
128 cycles later in every observed case except one: starting from cycle 189 the slot at
+128 (cycle 317) is skipped and +154 (cycle 343) is used. This is 32 of the 835
observations of that step, all from the same starting cycle.

The sprites-off display area has its slots in pairs 6 cycles apart, at offsets
{0, 6, 32, 38, 64, 70, 96} of every 128 cycles. Cycle 189 is the second slot of a pair,
and so is its +128 target; every observation that *does* use the +128 slot starts from
one of the offsets 0, 32, 64 or 96. So the one candidate rule the data offers is that
the engine cannot use a slot that follows only 6 cycles after another slot when its
request became pending in that 6-cycle window. But there is exactly one starting
position in the data that tests this, so it is a single coincidence away from being
noise. It is worth 32 transitions out of 76542 and openMSX does not model it.

## 8. Five traces are mislabelled

`scr5-dispOff-hmmv-noCpu-nx2-6d`, `scr5-dispOff-lmmv-noCpu-nx2-3d`,
`scr5-dispOff-ymmm-noCpu-nx12-1d`, `scr5-sprOff-lmmm-noCpu-nx2-3d` and
`scr5-sprOff-lmmv-noCpu-nx8-5d` are named `noCpu` but contain CPU accesses
(`R.r` / `W.w`). They were, before exclusion, the *only* source of inconsistencies in
the middle of the display line — every other anomaly is at a line boundary or is the
sprites-on effect of section 5. So they are worth excluding, and their presence is
itself a small confirmation that the model is otherwise sound.

Separately, the unclassified read of `0x1ffff` is the VDP's dummy read in most traces,
but in a few YMMM traces the command's own source pointer walks through the top of
VRAM and produces genuine command accesses at that address; the check script
distinguishes the two by looking at the rest of the trace.

## 9. CPU contention: openMSX's arbitration is confirmed

627 traces have the CPU reading or writing VRAM while a command runs, with CPU accesses
64 to 72 cycles apart — the same rate as the `OUT (#98),A` loop of `vdpcmdx`'s `+CPU`
tests. Applying openMSX's rule

> the engine takes the first slot at or after its minimum delay that the CPU did not
> take (`VDPCmdEngine::stealAccessSlot`)

to the observed CPU access times predicts 88939 of 89526 engine accesses correctly
(**99.34%**). The CPU took the slot the engine wanted in 4.1% of the transitions, so
the arbitration is genuinely exercised. Of the 587 misses, 452 have the engine landing one slot *earlier* than
modelled — the blanking-boundary family of section 6, which occurs identically without
any CPU activity.

Two consequences:

* The `stealAccessSlot` model is right, including the detail that a command engine
  which loses a slot takes the *next* slot rather than re-arming its full delay.
  Modelling the loser as re-arming the full delay is six times worse (3.99% wrong).
* The hypothesis floated earlier in
  [sndpl/openMSX#5](https://github.com/sndpl/openMSX/pull/5) — that under contention
  real hardware uses slots closer together than the command's own minimum spacing — is
  refuted. Outside the blanking-boundary cases the engine never accesses VRAM earlier
  than its uncontended minimum allows.

So whatever is left of the `+CPU` disagreement in `vdpcmdx` is not in the arbitration
model. Given that the tool's `REAL` column is a single run on one machine and that
hardware itself varies by several percent between runs, that column is not a useful
calibration target; a CPU-loop-period sweep would be.

## 10. What would help next

* **Sprites-on, delay a multiple of 32.** The prediction of section 5 can be tested
  with software only: run LMMV (whose `W → R` is 71..72, so no deviation is expected)
  and HMMV (45..48, likewise) against HMMM's line transition, in sprites-on mode, and
  check that only the latter is 32 cycles slower than the model per rectangle line. A
  rectangle one pixel wide and many lines tall makes the line-transition step dominate
  the whole command.
* **The blanking boundary.** A phase-resolved completion-time measurement — sync to
  the line interrupt, burn a programmable number of cycles, start a one- or two-pixel
  command, then poll S#2 once — resolves a single command's finish time to ~6 cycles
  and would separate section 6's two explanations directly.
* **Command startup cost.** Still never measured. It is invisible to `vdpcmdx` (one
  command per frame of 10240 pixels), and the same small-command rig would expose it
  as an offset in the completion-time distribution.
