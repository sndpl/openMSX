# Analysis: VDP command timings differ from real HW (issue #2057)

Analysis of https://github.com/openMSX/openMSX/issues/2057, 2026-07-18.
Status: report only, no code changes made yet.
Update 2026-07-20: see "Addendum" at the bottom — new measurements narrow
the discrepancy to LMMM in the active area with sprites enabled.

## What the issue is

bengalack built a test ROM (https://github.com/bengalack/cmd_timings) that
colors the screen border while the V9938 command engine is busy (white) and
while the CPU pushes VRAM data (red). Comparing openMSX 21 against real
hardware (NMS-8245, FS-A1, HB-F1XDJ) shows openMSX completes VDP block
commands (LMMM/HMMM) too fast — both with concurrent CPU VRAM access and in
command-only cases with small copy blocks. Real hardware additionally shows
heavy jitter (up to ~14 scanlines / ~3200 cycles) when CPU and command engine
compete, which openMSX does not reproduce.

Maintainer assessment (m9710797): probably not a parameter to tweak but a
missing rule in the model, and a lot of measurement-driven work.

## How openMSX models command timing today

The model is directly derived from the VDP VRAM timing paper by Wouter
Vermaelen (m9710797, measurements together with Joost; hosted on
map.grauw.nl) (in-tree
copy: doc/internal/vdp-vram-timing/vdp-timing.html) and lives in:

- `src/video/VDPAccessSlots.cc` — tables of the real VRAM access-slot
  positions within the 1368-cycle scanline, per mode (154 slots screen-off,
  88 sprites-off, 31 sprites-on, etc.), precompiled into a "cycles until next
  slot at least N cycles away" lookup table.
- `src/video/VDPCmdEngine.cc` — each block command walks pixel by pixel;
  every VRAM access advances `engineTime` to the next real slot with the
  per-access minimum delays from the paper's measurements (LMMM = 64R/32R/24W per
  pixel + 64 per line, etc. — the constants match the paper exactly).
  Execution is lazy: the engine only advances when software observes it
  (status register S#2, VRAM access, register writes).
- CPU contention: a CPU VRAM access calls `stealAccessSlot()`
  (`src/video/VDPVRAM.hh` cpuRead/cpuWrite -> `VDPCmdEngine.hh`), which
  pushes the engine's next access to the following slot. CPU accesses
  themselves are scheduled ~16 cycles ahead at the next slot
  (`VDP.cc` scheduleCpuVramAccess).

This core has been essentially unchanged since 2013-2015.

## The gaps — what would need to be improved

Ranked by likelihood of explaining the reported discrepancy:

1. **No command-startup / first-line overhead.** Every `start*` function
   (e.g. `startLmmm`) begins the first pixel at the very next access slot
   with zero setup cost. The paper explicitly flags this as unmeasured
   and says it is logical to assume the per-line overhead (64 cycles for
   LMMM) also applies at command start, possibly plus a per-command
   constant. Best candidate for the command-only discrepancy the issue
   demonstrates with small blocks — a fixed missing startup cost matters
   most there.

2. **Simplified CPU vs command-engine contention.** In real hardware the VDP
   allocates slots 16 cycles in advance with CPU priority, and a slot can go
   unused entirely; openMSX just bumps the engine by one slot per CPU
   access. This under-penalizes commands under concurrent CPU load and
   cannot reproduce the large jitter seen on real hardware. Best candidate
   for the CMD+CPU discrepancy.

3. **CPU-transfer commands are knowingly wrong.** LMMC/HMMC/LMCM carry
   comments like "timing is inaccurate, this executes the read and write in
   the same access slot" and effectively skip slot accounting. Not what the
   issue measures (it uses LMMM/HMMM), but part of the same cleanup.

4. **Minor:** openMSX implements the paper's *minimum* measured delays; if real
   chips have systematic overhead above those minimums, everything runs
   slightly fast. Also SRCH/PSET deltas are marked `// TODO`, and the ImGui
   block-command overlay is approximate by design
   (`src/imgui/ImGuiBitmapViewer.cc` top comment) — which is the "overlay
   not 100% precise" remark in the issue thread.

## What a fix would involve

- Calibrate against the cmd_timings ROM: run it in openMSX, count CE-busy
  cycles per configuration, and compare with the line counts visible in the
  issue's real-hardware photos to estimate the missing constant(s) per
  command.
- Add a start-of-command overhead (likely = the per-line delta, possibly
  plus a constant) in each `start*` function — small, low-risk change once
  the value is known.
- Rework `stealAccessSlot` toward the paper's reserve-16-cycles-ahead,
  CPU-priority model — more invasive, touches the hot path, needs regression
  testing against timing-sensitive titles (the code cites a Chase HQ
  regression from a past tweak).
- Ideally new measurements on real hardware, since the paper's data does not
  cover startup latency at all.

## Key code anchors

- Per-pixel/per-line deltas and finish estimate:
  `src/video/VDPCmdEngine.cc` (`calcFinishTime`, `startLmmm`/`executeLmmm`)
- Slot tables and table selection: `src/video/VDPAccessSlots.cc`
- CPU/command contention: `src/video/VDPVRAM.hh` (cpuRead/cpuWrite),
  `VDPCmdEngine.hh` (`stealAccessSlot`), `VDP.cc` (`scheduleCpuVramAccess`)
- Accuracy settings: `src/video/RenderSettings.cc` (`cmdtiming`,
  `too_fast_vram_access`)

## Addendum 2026-07-20: vdpcmdx measurements narrow the problem

bengalack published a follow-up tool, vdpcmdx
(https://github.com/bengalack/vdpcmdx), which counts pixels the command
engine produces per frame (screen 8, 192 lines), separately for VBLANK and
the active area, across HMMM/LMMM/YMMM/HMMV/LMMV with sprites on
("NORMAL"), sprites off, screen off, and with/without concurrent CPU VRAM
access. "REAL" reference numbers come from a Sony HB-F1XD.

Reproduced locally (openMSX 21.0-77, Philips_NMS_8250, 50Hz, MSX-DOS,
vdpcmdx.com). Result matches the numbers posted in the issue:

- The ONLY significant deviation is **LMMM, active area, sprites enabled,
  no CPU access**: openMSX ~1717/1699 pixels per frame vs ~1339/1332 on
  real HW — about 28% too fast.
- Everything else is within ~1%: all VBLANK rows, all HMMM/HMMV/LMMV/YMMM
  rows, and — notably — LMMM active area with sprites OFF (1970 vs 1971)
  and screen OFF (2003 vs 2004), and even LMMM active + CPU (775 vs 774).
- Known secondary deviations also visible in both runs: YMMM active area
  with sprites off is too SLOW in openMSX (~2870 vs ~3797 real), and some
  +CPU cells differ in both directions — consistent with gap 2 (contention
  model) being separately imperfect.

Consequences for the ranking above:

- Gap 1 (startup overhead) is NOT the explanation for this measurement:
  vdpcmdx measures sustained throughput over a whole frame (startup cost is
  amortized), and the VBLANK numbers match. It may still matter for the
  original cmd_timings small-block cases, but it cannot produce a 28%
  active-area-only error.
- The failing case is exactly the sprites-enabled slot table (31 slots per
  line, `VDPAccessSlots.cc`). Since sprites-off (88 slots) and screen-off
  (154 slots) match perfectly, the per-access minimum deltas
  (64R/32R/24W for LMMM) are correct; what is wrong is how LMMM's
  3-accesses-per-pixel pattern interacts with the sparse sprites-on slot
  distribution. openMSX's "jump to next slot at least N cycles away" model
  is too optimistic there: real HW achieves ~7.0 px/line vs openMSX's
  ~8.9 px/line (theoretical min-delta cap is ~11.4). HMMM (1 access/pixel
  pair) and the fill commands are unaffected, so the missing rule is
  specific to multi-access-per-pixel commands on the 31-slot table —
  e.g. real HW may be unable to use closely spaced slot pairs
  back-to-back the way the greedy model assumes.
- Practical next step: instrument `executeLmmm` slot usage in the
  sprites-on mode and compare achieved slots/line (~21 real vs ~27
  openMSX) against the 31-slot table to find which slots real HW skips.

## Addendum 2026-07-20 (2): the missing rule, found and implemented

Method: an offline simulator of the openMSX slot model
(`vdp-cmd-timing-issue2057-sim.py`, same directory) replicates
`VDPAccessSlots.cc` + the per-command deltas and the exact vdpcmdx test
geometry (screen 8, landscape 256x40 / portrait 40x256, command window =
exactly the 192 active lines, per vdpcmdx `main.c`). It reproduces the
emulator's own results on all 30 non-CPU data points within ~0.5%, which
validates the simulator. Rule variants were then tested against the
real-hardware numbers.

Result — a single minimal rule reproduces real HW within +-2 pixels:

    LMMM's source-read -> destination-read spacing is >= 48 cycles
    (not >= 32) when sprite rendering is enabled. All other commands
    and all other modes keep the paper's published deltas.

Evidence and eliminated alternatives:

- LMMM is the only measured command with two back-to-back *reads*;
  every command whose transitions are read->write or write->read is
  timed correctly by the current model in every mode.
- A slot-index rule ("skip one slot") gives 1245 px/frame, too slow; the
  measured 1339 requires a time-based >=48 rule (an adjacent slot >=48
  cycles away IS used, e.g. slot 92 -> 162).
- Applying 48 globally (all modes) breaks sprites-off (1659 vs 1971)
  and screen-off (1851 vs 2004), so the +16 penalty only exists with
  the sprite-fetch pattern on the bus. The paper already hints at
  related unexplained behavior: the sprites-on slot at cycle 170 is
  "rarely actually used" on real HW even when the engine is starved.
  The physical mechanism (likely an interaction between the engine's
  request pipeline and sprite fetches) remains unknown; the 48 is a
  calibrated, verified description of the behavior.

Implementation: `VDPCmdEngine.cc` `executeLmmm` now selects
`Delta::D48` instead of `Delta::D32` for the destination read when the
current mode uses the sprites-on slot table (same predicate as
`VDPAccessSlots::getTab`: V99x8, bitmap mode, display enabled, sprites
enabled).

Verification (vdpcmdx in the patched build, Philips_NMS_8250, 50Hz):

- ACTIVE/NORMAL Copy LMMM: 1339 vs real 1339 (landscape),
  1333 vs 1332 (portrait). Before the fix: 1717 / 1699 (~28% too fast).
- All other rows unchanged, still matching real HW within ~1%
  (HMMM 1915/1915, YMMM 2111/2111, HMMV 4002/4005, LMMV 1907/1908, all
  VBLANK/NO-SPR/NO-SCR rows).

Known remaining deviations (pre-existing, out of scope for this fix):

- LMMM ACTIVE NORMAL+CPU landscape regressed from 774 (matching) to
  679 (real: 774); portrait was already off (681 vs 775, now 679).
  This column exercises the simplified CPU contention model (gap 2
  above): with CPU slot-stealing in play, the D48 rule overshoots. A
  proper fix needs the reserve-16-cycles-ahead CPU-priority model, at
  which point the LMMM rule may fall out of the same mechanism.
  ANALYZED AND EXPLAINED in addendum (3) below.
- YMMM with sprites off is ~25% too SLOW in openMSX (2870 vs real
  3797 landscape, 2871 vs 3689 portrait) — real HW is much faster than
  the paper's '40R 24W' deltas allow on the 88-slot table.
  ANALYZED AND FIXED in addendum (3) below.

## Addendum 2026-07-20 (3): both remaining deviations analyzed

### YMMM: the paper's deltas don't match — fixed

No (R->W, W->R) delta pair with zero line overhead fits the
measurements (best possible: 19% error). Extending the search with a
per-line overhead parameter finds that

    read -36-> write -24-> next read, +64 extra per line

fits ALL eight non-CPU YMMM measurements (sprites on/off, screen off,
vblank, both orientations) within 1.44%, where the current model
('24 R->W, 40 W->R, 0 per line', from the paper's table entry
'YMMM | 40 R 24 W | 0') is up to 24% off. In other words: the two
inter-access values in the published table are effectively swapped,
and YMMM does have a per-line overhead (~64 cycles, like the other
block commands) contrary to the paper's note. On the sprites-enabled
slot table both timings happen to produce the identical read cadence,
which is probably why the error was never noticed there. The odd value
36 (not a multiple of 8) is what the fit requires to use the
second-slot-of-a-pair positions (38 cycles apart) on the sprites-off
table; the true hardware rule behind it is unknown.

Implemented: new `Delta::D36` in `VDPAccessSlots.hh/.cc`, and
`executeYmmm` now does read -D36-> write -D24-> read (D88 = 24+64 at
line wrap). Verified with vdpcmdx (THIS vs REAL): NO-SPR 3804/3797
(was 2870) and 3725/3689 (was 2871); NORMAL 2107/2111, 2085/2095;
NO-SCR 3994/3996, 3912/3914 (portrait was 4012); VBLANK 2523/2512,
2470/2461 (portrait was 2531). YMMM NORMAL+CPU still matches
(1165/1167, 1166/1166).

### LMMM+CPU (and all +CPU columns): artifact of the contention model

The real-hardware +CPU numbers have a simple structure. The hammering
loop (`OUT (#98),A` = 12 Z80 = 72 VDP cycles) issues exactly 19 CPU
requests per 1368-cycle line. In sprites-on mode real HW then shows
*exact slot saturation*: every command gets the remaining
31 - 19 = 12 slots per line, i.e. 12/accesses-per-pixel pixels per
line — HMMM/LMMV/YMMM 6.0 px/line (real 1158..1167 per frame), LMMM
4.0 (774), HMMV 12.0 (2310). All five confirmed within 1%.

Simulating the paper's real allocation model (slot granted at its
allocation point 16 cycles ahead; CPU priority; engine stalls on a
pending request; see `paper_model` in the sim script) reproduces this:
in the starved-engine limit the engine request is always pending, so
it takes every CPU-free slot, phase-independently — and then it does
NOT matter whether LMMM's dst-read delta is 32 or 48 (both give 768 vs
real 774). Conclusions:

- The 774->679 regression from the LMMM D48 fix exists only in
  openMSX's simplified `stealAccessSlot` model; under the correct
  allocation model the D48 rule is harmless with CPU load.
- The current model is also phase-fragile: because 72 divides 19x into
  1368, the CPU pattern phase-locks to the line, and the same build
  produced e.g. 1156 vs 970 for HMMM NORMAL+CPU on two different runs
  (real HW: 1160, stable). The erratic +CPU cells across openMSX runs
  are this resonance.
- The proper fix for every +CPU cell is implementing the paper's
  allocation model (gap 2 in the original analysis): per-slot
  allocation 16 cycles ahead, separate CPU/engine request buffers, CPU
  priority, CPU request dropping. That is the invasive hot-path rework
  the maintainer warned about; it should replace `stealAccessSlot`.
  No code change made for this here.

## Addendum 2026-07-20 (4): answers to review questions (PR feedback)

Attribution correction: the VRAM timing paper and its measurements are by
Wouter Vermaelen (m9710797, together with Joost); map.grauw.nl only hosts
the document. Earlier revisions of this file said "Grauw's paper".

Three findings from re-testing the reviewer's alternative hypotheses in
the simulator:

1. "Always use D48 for LMMM?" — No: it breaks sprites-off (sim 1659 vs
   real 1971) and screen-off (1851 vs 2004). The 32-cycle spacing is
   definitely correct on the dense tables.

2. "Maybe the sprites-on slot table is wrong instead?" — This WORKS as an
   alternative explanation. Shifting only the middle slot of each
   32/32-triplet (cycles 220, 348, 476, 604, 732, 860, 988, 1116) 4 or 8
   cycles EARLIER reproduces all ten sprites-on measurements with the
   original unconditional deltas — no conditional D48 needed:
   LMMM 1341/1334 (real 1339/1332), HMMM 1918 (1915), YMMM 2109 (2111),
   HMMV 4013/3930 (4005/3922), LMMV 1911/1872 (1908/1869). The vdpcmdx
   data cannot distinguish "middle slots are 4-8 cycles earlier" from
   "LMMM's dst read needs >32 cycles"; only a bus-level measurement can.
   The key property either way: LMMV's write (>=24 after its read) must
   still reach the middle slot, while LMMM's dst read (>=32 after its
   read) must miss it.

3. The YMMM value 36 is not really "36": the measurements only pin the
   read->write threshold to the range 33..38 (<=32 is too fast on both
   the sprites-off and screen-off tables, >=39 too slow on sprites-off).
   That is exactly "strictly more than 32 cycles" — so the underlying
   value may well be the multiple-of-8 value 32 combined with an
   exclusive boundary in slot granting (e.g. a request posted exactly at
   an allocation point missing that slot), rather than a genuine
   non-multiple-of-8 delay. Possibly the same boundary phenomenon as the
   LMMM case (32 + something small), which would unify both fixes.

How to validate on real hardware:

- Bus-level capture (the original paper's logic-analyzer setup) of one
  LMMM in sprites-on mode directly decides between the two explanations
  in (2): either the middle slots sit at +28 (not +32), or the dst read
  skips them. Same for YMMM on the sprites-off table (write landing on
  the pair-second slots 38 cycles after the read).
- Software-only, out-of-sample tests with vdpcmdx variants (bengalack
  has NMS-8245, FS-A1, HB-F1XDJ): change the block sizes/widths, use
  212-line mode, screen 5 instead of 8, other logical ops, 60Hz. The
  simulator can publish predicted numbers BEFORE the hardware runs;
  matching predictions on cases not used for calibration is strong
  validation.
- More chips: V9958 machines and other V9938 batches, to see whether the
  behavior is uniform.

## Addendum 2026-07-22 (5): constraint bands, not point values; a pinning test

Review feedback (rightly) criticized presenting fitted point values as
conclusions. This section states what the measurements actually
constrain, corrects an overclaim in addendum (3), and proposes a new
hardware test that pins the values further.

### What the data actually pins down

LMMM, sprites-on destination read (under the conditional-delta
hypothesis): any effective minimum spacing in **33..65** cycles
reproduces the measurements (1341/1334 sim vs 1339/1332 real); 32 gives
1724/1706 and >=66 gives 1149/1144. The implemented `D48` is one
representative. The slot-table-shift hypothesis of addendum (4) remains
an equivalent alternative.

YMMM: exhaustive search at 1-cycle resolution finds exactly two
solution families within 2% of all 8 non-CPU measurements:

- family A: R->W in 33..38, W->R in 17..24, per-line 56..88
  (best member 1.44%) — the "swapped values" reading of addendum (3);
- family B: R->W in 17..24, W->R in 33..38, per-line 64..88
  (best member 0.64%).

The "swapped" claim in addendum (3) was too strong: family B keeps the
paper's R->W = 24 unchanged and only replaces the 40 with a value in
33..38 — it deviates less from the paper AND fits better. The
implementation now uses family B: read -D24-> write -D36-> next read,
D104 (= 36 + 68) at line wrap. Emulator verification (vdpcmdx, THIS vs
REAL): NORMAL 2109/2111 and 2093/2095, NO-SPR 3796/3797 and 3686/3689,
NO-SCR 3994/3996 and 3912/3914, VBLANK 2523/2512 and 2471/2461 — every
YMMM cell within 3 pixels.

Note both anomalies are consistent with a threshold "strictly more than
32" (LMMM band 33..65, YMMM band 33..38 both contain 33), which could
point at an exclusive boundary in slot granting rather than a new delay
value — but the YMMM band's upper limit 38 and the LMMM dense-table
behavior (exactly 32 works there) mean neither is a clean universal
rule yet.

### Proposed test: equivalent-time sampling of command completion

vdpcmdx measures whole-frame throughput, which cannot separate
solutions inside the bands above. The following software-only test can
(no logic analyzer needed):

1. HALT-sync to the line interrupt (deterministic Z80 interrupt
   latency), then burn a programmable number of cycles with a NOP sled.
2. Start a tiny command (e.g. YMMM of 4 pixels, or LMMM of 1 pixel) at
   that controlled phase within the scanline.
3. Read S#2 once at a second programmable delay and record the CE bit
   (busy/done — a single binary sample, no polling loop).
4. Sweep both delays in 1-Z80-cycle (6 VDP cycles) steps over many
   frames. The CE transition point as a function of start phase is a
   fingerprint of the engine's per-access slot usage.

Simulated discrimination power (completion-time difference >= 12 VDP
cycles, sweeping the 228 possible start phases):

- YMMM family A vs family B (4 px, sprites off): 212/228 phases differ,
  up to 58 cycles — trivially separable.
- LMMM conditional-D48 vs shifted-slot-table (1 px, sprites on): 32..38
  of 228 phases differ, up to 52 cycles — separable at specific phases.
- Within the YMMM 33..38 band: the 10-cycle slot gaps near the end of
  the sprites-off line make {33,34} vs {35,36} vs {37,38} separable
  (1-2 phases each); inside those pairs natural slot geometry offers no
  discriminating offsets, so the exact value needs a bus-level capture.

The same setup with NY=2 vs NY=1 measures the per-line overhead
directly, and with delay-0 it measures the command startup overhead —
i.e. it also addresses gap 1 of the original analysis, which no
existing test covers.
