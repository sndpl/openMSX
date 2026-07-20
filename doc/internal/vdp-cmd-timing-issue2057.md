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

The model is directly derived from Grauw's VDP VRAM timing paper (in-tree
copy: doc/internal/vdp-vram-timing/vdp-timing.html) and lives in:

- `src/video/VDPAccessSlots.cc` — tables of the real VRAM access-slot
  positions within the 1368-cycle scanline, per mode (154 slots screen-off,
  88 sprites-off, 31 sprites-on, etc.), precompiled into a "cycles until next
  slot at least N cycles away" lookup table.
- `src/video/VDPCmdEngine.cc` — each block command walks pixel by pixel;
  every VRAM access advances `engineTime` to the next real slot with the
  per-access minimum delays from Grauw's measurements (LMMM = 64R/32R/24W per
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
   with zero setup cost. Grauw's paper explicitly flags this as unmeasured
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

4. **Minor:** openMSX implements Grauw's *minimum* measured delays; if real
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
    and all other modes keep Grauw's published deltas.

Evidence and eliminated alternatives:

- LMMM is the only measured command with two back-to-back *reads*;
  every command whose transitions are read->write or write->read is
  timed correctly by the current model in every mode.
- A slot-index rule ("skip one slot") gives 1245 px/frame, too slow; the
  measured 1339 requires a time-based >=48 rule (an adjacent slot >=48
  cycles away IS used, e.g. slot 92 -> 162).
- Applying 48 globally (all modes) breaks sprites-off (1659 vs 1971)
  and screen-off (1851 vs 2004), so the +16 penalty only exists with
  the sprite-fetch pattern on the bus. Grauw's paper already hints at
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
- YMMM with sprites off is ~25% too SLOW in openMSX (2870 vs real
  3797 landscape, 2871 vs 3689 portrait) — real HW is much faster than
  Grauw's '40R 24W' deltas allow on the 88-slot table. Untouched here;
  deserves its own investigation and possibly re-measurement.
