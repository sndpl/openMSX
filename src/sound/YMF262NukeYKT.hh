/* Nuked OPL3
 * Copyright (C) 2013-2020 Nuke.YKT
 *
 * This file is part of Nuked OPL3.
 *
 * Nuked OPL3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1
 * of the License, or (at your option) any later version.
 *
 * Nuked OPL3 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Nuked OPL3. If not, see <https://www.gnu.org/licenses/>.
 *
 *  Nuked OPL3 emulator. Thanks: see opl3.cc / opl3.hh (the unmodified original).
 *  version: 1.8
 * -------------------------------------------------------------------
 *
 * Adapted for use in openMSX by porting the original Nuked-OPL3 C code
 * (see the unmodified src/sound/opl3.cc / opl3.hh) to C++. The unmodified
 * original is kept alongside as the reference for the bit-identical unit test
 * (see src/unittest/YMF262NukeYKT_test.cc).
 *
 * The most important changes with respect to the original opl3.cc are:
 *
 * - Adapt to the openMSX API (the 'YMF262Core' base-class): register writes
 *   are applied immediately (openMSX supplies sample-accurate timing by
 *   interleaving writeReg() and generateChannels() calls), and the output is
 *   produced per-channel and stereo-interleaved (see generateChannels()).
 *
 * - Index-based references instead of pointers. The original opl3_chip webs
 *   raw pointers between its sub-structs (slot->channel/chip, channel->pair,
 *   channel->out[4] into sibling slots, slot->mod, slot->trem). All of those
 *   are replaced by small integer indices / enums that are resolved through
 *   the owning YMF262 object. This makes the whole state trivially copyable
 *   and serializable (no pointer fix-ups). The fixed mappings that never
 *   change after reset (slot<->channel and the 4op channel pairing) are kept
 *   in constexpr tables instead of stored pointers. The DATA layout semantics
 *   and, crucially, the exact order in which slot/channel state is updated are
 *   preserved bit-for-bit.
 *
 * - Per-channel output. generateChannels() reproduces OPL3_Generate4Ch()'s
 *   accumulation exactly (including the interleaved two-phase mix and the
 *   one-sample right-channel delay of OPL_QUIRK_CHANNELSAMPLEDELAY, which is
 *   ON in the reference build because OPL_ENABLE_STEREOEXT==0), but captures
 *   each channel's left/right contribution separately so openMSX can mix (and
 *   in the future mute/visualise) channels individually. Summing all channel
 *   contributions and applying the original per-pin int16 clipping reproduces
 *   the original's output exactly; that is verified by the unit test via the
 *   test-only generate4ChTest() hook.
 *
 * - No writebuf. The original opl3_writebuf ring-buffer and the OPL3L
 *   resampler (OPL3_Generate*Resampled / rateratio / samplecnt / oldsamples)
 *   are dropped entirely: openMSX resamples via ResampledSoundDevice and
 *   provides its own timing.
 *
 * Only moderate optimizations are applied (constexpr tables, dropping the
 * pointer indirection). The per-sample structure of the original is kept as-is
 * (the original is already a per-sample implementation, so unlike the
 * YM2413NukeYKT port there is no pipeline to batch). Further optimization
 * (e.g. specializing for the common OPL2/2op case, skipping silent slots) is
 * possible but intentionally not attempted here; correctness comes first.
 */

#ifndef YMF262NUKEYKT_HH
#define YMF262NUKEYKT_HH

#include "YMF262Core.hh"

#include "serialize_meta.hh"

#include <array>
#include <cstdint>
#include <span>

namespace openmsx::YMF262NukeYKT {

class YMF262 final : public YMF262Core
{
public:
	YMF262();

	// YMF262Core
	void reset() override;
	void writeReg(unsigned reg, uint8_t value) override;
	[[nodiscard]] uint8_t peekReg(unsigned reg) const override;
	void generateChannels(std::span<float*, 18> bufs, unsigned num) override;
	[[nodiscard]] float getAmplificationFactor() const override;
	// setSpeed(): intentionally not overridden (see YMF262OriginalNukeYKT).

	/** Test-only hook. Generates exactly one native (49716Hz) sample and
	  * returns the four DAC output pins, computed bit-for-bit like the original
	  * OPL3_Generate4Ch(): out[0]=left(A), out[1]=right(B), out[2]=(C),
	  * out[3]=(D). Includes the per-pin int16 clipping and the one-sample
	  * right-channel delay. Used by the bit-identical validation test. */
	void generate4ChTest(std::span<int16_t, 4> out) { generateOne(out); }

	/** Test-only diagnostic: number of samples produced via the silent-chip
	  * fast path since construction. Used by the unit test to assert the fast
	  * path actually engaged. */
	[[nodiscard]] uint64_t getFastPathSampleCount() const { return fastPathSamples; }

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

private:
	// Channel types (opl3.cc: 'ch_2op' etc.).
	static constexpr uint8_t CH_2OP  = 0;
	static constexpr uint8_t CH_4OP  = 1;
	static constexpr uint8_t CH_4OP2 = 2;
	static constexpr uint8_t CH_DRUM = 3;

	// Envelope key types (opl3.cc: 'egk_norm'/'egk_drum').
	static constexpr uint8_t EGK_NORM = 0x01;
	static constexpr uint8_t EGK_DRUM = 0x02;

	// Envelope generator phase (opl3.cc: 'envelope_gen_num_*').
	static constexpr uint8_t EG_ATTACK  = 0;
	static constexpr uint8_t EG_DECAY   = 1;
	static constexpr uint8_t EG_SUSTAIN = 2;
	static constexpr uint8_t EG_RELEASE = 3;

	// Replacement for the original 'int16_t* mod' pointer: the modulation input
	// of a slot is always either a constant zero, some slot's 'fbmod' or some
	// slot's 'out'.
	static constexpr uint8_t MOD_ZERO  = 0; // constant 0 (was &chip->zeromod)
	static constexpr uint8_t MOD_FBMOD = 1; // slot[modSlot].fbmod
	static constexpr uint8_t MOD_OUT   = 2; // slot[modSlot].out

	// Sentinel for 'channel->out[i]' entries that were &chip->zeromod.
	static constexpr uint8_t NO_SLOT = 0xff;

	struct Slot {
		int16_t out = 0;
		int16_t fbmod = 0;
		int16_t prout = 0;
		uint16_t eg_rout = 0x1ff;
		uint16_t eg_out = 0x1ff;
		uint8_t eg_inc = 0;
		uint8_t eg_gen = EG_RELEASE;
		uint8_t eg_ksl = 0;
		uint8_t reg_vib = 0;
		uint8_t reg_type = 0;
		uint8_t reg_ksr = 0;
		uint8_t reg_mult = 0;
		uint8_t reg_ksl = 0;
		uint8_t reg_tl = 0;
		uint8_t reg_ar = 0;
		uint8_t reg_dr = 0;
		uint8_t reg_sl = 0;
		uint8_t reg_rr = 0;
		uint8_t reg_wf = 0;
		uint8_t key = 0;
		uint8_t pg_reset = 0;
		uint32_t pg_phase = 0;
		uint16_t pg_phase_out = 0;
		// pointer replacements:
		uint8_t modSrc = MOD_ZERO; // MOD_ZERO / MOD_FBMOD / MOD_OUT
		uint8_t modSlot = 0;       // referenced slot index (for FBMOD / OUT)
		uint8_t trem = 0;          // was 'uint8_t* trem': 1 -> use chip tremolo

		template<typename Archive>
		void serialize(Archive& ar, unsigned version);
	};

	struct Channel {
		std::array<uint8_t, 4> out = {NO_SLOT, NO_SLOT, NO_SLOT, NO_SLOT};
		uint8_t chType = CH_2OP;
		uint16_t f_num = 0;
		uint8_t block = 0;
		uint8_t fb = 0;
		uint8_t con = 0;
		uint8_t alg = 0;
		uint8_t ksv = 0;
		uint16_t cha = 0xffff;
		uint16_t chb = 0xffff;
		uint16_t chc = 0;
		uint16_t chd = 0;

		template<typename Archive>
		void serialize(Archive& ar, unsigned version);
	};

	// --- register writes (mirror opl3.cc OPL3_WriteReg and its helpers) ---
	void slotWrite20(uint8_t s, uint8_t data);
	void slotWrite40(uint8_t s, uint8_t data);
	void slotWrite60(uint8_t s, uint8_t data);
	void slotWrite80(uint8_t s, uint8_t data);
	void slotWriteE0(uint8_t s, uint8_t data);
	void channelWriteA0(uint8_t c, uint8_t data);
	void channelWriteB0(uint8_t c, uint8_t data);
	void channelWriteC0(uint8_t c, uint8_t data);
	void channelSet4Op(uint8_t data);
	void channelUpdateRhythm(uint8_t data);
	void channelSetupAlg(uint8_t c);
	void channelUpdateAlg(uint8_t c);
	void channelKeyOn(uint8_t c);
	void channelKeyOff(uint8_t c);
	void envelopeUpdateKSL(uint8_t s);

	// --- per-sample synthesis (mirror opl3.cc OPL3_Generate4Ch and helpers) ---
	// phaseGenerate/processSlot/generateSample are templated on whether rhythm
	// mode is active (rhy bit5). rhy cannot change during a single generate call
	// (register writes are interleaved *between* generateChannels() calls by the
	// wrapper), so the template is dispatched once per call, removing the
	// per-slot per-sample rhythm-enable test from the inner loop.
	void slotCalcFB(uint8_t s);
	void envelopeCalc(uint8_t s);
	template<bool RHYTHM> void phaseGenerate(uint8_t s);
	void slotGenerate(uint8_t s);
	template<bool RHYTHM> void processSlot(uint8_t s) {
		slotCalcFB(s);
		envelopeCalc(s);
		phaseGenerate<RHYTHM>(s);
		slotGenerate(s);
	}
	template<bool RHYTHM> void generateSample(std::span<int16_t, 4> pins);
	// End-of-sample global bookkeeping (LFO / timer / envelope-generator clock).
	// Shared verbatim by the full path and the silent fast path.
	void advanceState();

	// --- silent-chip fast path (see YMF262NukeYKT.cc for the exactness proof) ---
	[[nodiscard]] bool fullSilentScan() const;
	[[nodiscard]] bool checkIdle();
	void fastSilentAdvance();
	void generateOne(std::span<int16_t, 4> pins);
	[[nodiscard]] bool fastSilentBlock(unsigned num);

	[[nodiscard]] int16_t getModValue(const Slot& s) const {
		switch (s.modSrc) {
		case MOD_FBMOD: return slot[s.modSlot].fbmod;
		case MOD_OUT:   return slot[s.modSlot].out;
		default:        return 0;
		}
	}
	[[nodiscard]] int16_t chanOutVal(uint8_t enc) const {
		return (enc == NO_SLOT) ? int16_t(0) : slot[enc].out;
	}

private:
	std::array<Slot, 36> slot;
	std::array<Channel, 18> channel;

	// per-channel output capture (transient, filled every generateSample())
	std::array<int, 18> chLeftOut = {};  // cha contribution (pin A, left)
	std::array<int, 18> chRightOut = {}; // chb contribution (pin B, right)
	// one-sample right-channel delay for the per-channel float output
	std::array<int, 18> prevChanRight = {};

	// global chip state (mirror opl3_chip)
	std::array<int32_t, 4> mixBuff = {}; // delayed DAC pin accumulators
	uint64_t eg_timer = 0;
	uint32_t noise = 1;
	uint16_t timer = 0;
	uint8_t eg_timerrem = 0;
	uint8_t eg_state = 0;
	uint8_t eg_add = 0;
	uint8_t eg_timer_lo = 0;
	uint8_t newm = 0;
	uint8_t nts = 0;
	uint8_t rhy = 0;
	uint8_t vibpos = 0;
	uint8_t vibshift = 1;
	uint8_t tremolo = 0;
	uint8_t tremolopos = 0;
	uint8_t tremoloshift = 4;
	uint8_t rm_hh_bit2 = 0;
	uint8_t rm_hh_bit3 = 0;
	uint8_t rm_hh_bit7 = 0;
	uint8_t rm_hh_bit8 = 0;
	uint8_t rm_tc_bit3 = 0;
	uint8_t rm_tc_bit5 = 0;

	// Silent-chip fast-path bookkeeping. Deliberately NOT serialized: it is
	// derived state, and the fast path produces bit-identical results to the
	// full path, so a restored savestate can safely re-derive it (it will just
	// take one extra full sample before re-engaging the fast path).
	bool idleConfirmed = false;   // predicate holds AND no reg write since
	bool prevSampleIdle = false;  // the previous generated sample was idle
	uint64_t fastPathSamples = 0; // diagnostic counter (see getFastPathSampleCount)

	// 512-byte register mirror (only used for peekReg()).
	std::array<uint8_t, 512> regs = {};
};

} // namespace openmsx::YMF262NukeYKT

namespace openmsx {
SERIALIZE_CLASS_VERSION(YMF262NukeYKT::YMF262, 1);
}

#endif
