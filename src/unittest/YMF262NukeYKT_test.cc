#include "catch.hpp"

#include "YMF262NukeYKT.hh"
#include "opl3.hh" // the unmodified original Nuked-OPL3 core (reference)

#include <array>
#include <cstdint>
#include <random>

using namespace openmsx;

// This test proves that our C++ port (YMF262NukeYKT::YMF262) produces
// bit-for-bit identical output as the unmodified original Nuked-OPL3 core
// (opl3.cc / opl3.hh), for every one of the four DAC output pins on every
// generated sample.
//
// - The reference is driven through the original public API:
//     OPL3_Reset(&chip, 49716)  -> 1:1 sample rate (matches the openMSX wrapper)
//     OPL3_WriteReg(&chip, reg, value)
//     OPL3_Generate4Ch(&chip, buf4)
// - The port is driven through YMF262Core::writeReg() and the test-only
//   generate4ChTest() hook (which reproduces OPL3_Generate4Ch() exactly,
//   including the per-pin int16 clipping and the one-sample right-channel
//   delay).

namespace {

// Register offsets of the two operators of each of the 9 (per-bank) channels.
constexpr std::array<std::array<uint8_t, 2>, 9> OP_OFFSET = {{
	{0x00, 0x03}, {0x01, 0x04}, {0x02, 0x05},
	{0x08, 0x0b}, {0x09, 0x0c}, {0x0a, 0x0d},
	{0x10, 0x13}, {0x11, 0x14}, {0x12, 0x15},
}};

struct DualChip {
	opl3_chip ref;
	YMF262NukeYKT::YMF262 dut;
	long comparedSamples = 0;

	DualChip() {
		OPL3_Reset(&ref, 49716);
		// 'dut' is reset by its constructor.
	}

	void resetBoth() {
		OPL3_Reset(&ref, 49716);
		dut.reset();
	}

	[[nodiscard]] uint64_t fastPathSamples() const {
		return dut.getFastPathSampleCount();
	}

	void write(unsigned reg, uint8_t value) {
		OPL3_WriteReg(&ref, uint16_t(reg), value);
		dut.writeReg(reg, value);
	}

	// Generate 'n' samples on both cores and require all 4 pins to be equal on
	// every sample (one assertion per sample).
	void run(unsigned n) {
		for (unsigned i = 0; i < n; ++i) {
			std::array<int16_t, 4> a = {};
			std::array<int16_t, 4> b = {};
			OPL3_Generate4Ch(&ref, a.data());
			dut.generate4ChTest(b);
			INFO("sample index " << comparedSamples);
			REQUIRE(a == b); // compares all 4 DAC pins
			++comparedSamples;
		}
	}

	// Program a full 2-operator voice on channel 'chIdx' (0..17).
	void set2op(unsigned chIdx, uint8_t wf, uint8_t am_vib_mult0, uint8_t am_vib_mult1,
	            uint8_t tl0, uint8_t tl1, uint8_t arDr, uint8_t slRr,
	            uint8_t fnLo, uint8_t blkKeyOn, uint8_t fbCon) {
		unsigned base = (chIdx >= 9) ? 0x100 : 0x000;
		unsigned c9 = chIdx % 9;
		unsigned o0 = base + OP_OFFSET[c9][0];
		unsigned o1 = base + OP_OFFSET[c9][1];
		write(0x20 + o0, am_vib_mult0);
		write(0x20 + o1, am_vib_mult1);
		write(0x40 + o0, tl0);
		write(0x40 + o1, tl1);
		write(0x60 + o0, arDr);
		write(0x60 + o1, arDr);
		write(0x80 + o0, slRr);
		write(0x80 + o1, slRr);
		write(0xe0 + o0, wf);
		write(0xe0 + o1, wf);
		write(0xa0 + base + c9, fnLo);
		write(0xc0 + base + c9, fbCon);
		write(0xb0 + base + c9, blkKeyOn);
	}
};

} // anonymous namespace


TEST_CASE("YMF262 NukeYKT: bit-identical to original Nuked-OPL3")
{
	SECTION("melodic 2-op, all 8 waveforms, NEW=1") {
		DualChip d;
		d.write(0x105, 0x01); // OPL3 mode (NEW=1) so waveforms 0..7 are usable
		for (uint8_t wf = 0; wf < 8; ++wf) {
			unsigned ch = wf % 9;
			d.set2op(ch, wf,
			         0x01,        // op0: mult=1
			         0x01,        // op1: mult=1
			         0x1a,        // op0 (modulator) TL
			         0x00,        // op1 (carrier) TL=0
			         0xf4,        // AR=15, DR=4
			         0x24,        // SL=2, RR=4
			         uint8_t(0x40 + wf * 4), // fnum low
			         uint8_t(0x20 | (3 << 2) | 0x01), // key-on, block=3, fnum-hi=1
			         uint8_t(0x30 | (wf & 1))); // pan L+R, fb, con
			d.run(200);
		}
		// let the envelopes decay/sustain
		d.run(3000);
		// key everything off -> release phase
		for (uint8_t wf = 0; wf < 8; ++wf) {
			unsigned ch = wf % 9;
			unsigned base = (ch >= 9) ? 0x100 : 0x000;
			d.write(0xb0 + base + (ch % 9), uint8_t((3 << 2) | 0x01)); // key-off
		}
		d.run(3000);
		CHECK(d.comparedSamples > 0);
	}

	SECTION("legacy OPL2 mode (NEW=0): bank-1 writes and waveform masking") {
		DualChip d;
		// NEW stays 0. Program voices in both banks; the core must treat the
		// waveform as masked to 0..3 and handle bank-1 register writes exactly
		// as the original does (bank gating itself lives in the wrapper).
		for (unsigned ch : {0u, 3u, 6u, 9u, 12u, 15u}) {
			d.set2op(ch, 0x07,   // wf 7 -> should be masked to 3 in NEW=0
			         0x21, 0x01, 0x15, 0x00, 0xf3, 0x15,
			         0x55, uint8_t(0x20 | (4 << 2) | 0x00), 0x0e);
			d.run(150);
		}
		d.run(2000);
		CHECK(d.comparedSamples > 0);
	}

	SECTION("rhythm mode: all 5 percussion instruments") {
		DualChip d;
		d.write(0x105, 0x01);
		// Program the rhythm channels 6,7,8 operators.
		for (unsigned ch : {6u, 7u, 8u}) {
			unsigned c9 = ch % 9;
			d.write(0x20 + OP_OFFSET[c9][0], 0x01);
			d.write(0x20 + OP_OFFSET[c9][1], 0x01);
			d.write(0x40 + OP_OFFSET[c9][0], 0x00);
			d.write(0x40 + OP_OFFSET[c9][1], 0x00);
			d.write(0x60 + OP_OFFSET[c9][0], 0xf8);
			d.write(0x60 + OP_OFFSET[c9][1], 0xf8);
			d.write(0x80 + OP_OFFSET[c9][0], 0x00);
			d.write(0x80 + OP_OFFSET[c9][1], 0x00);
			d.write(0xa0 + c9, 0x60);
			d.write(0xb0 + c9, uint8_t((4 << 2) | 0x01));
			d.write(0xc0 + c9, 0x30);
		}
		// enable rhythm, key all 5 percussion instruments (bd,hh,sd,tom,tc)
		d.write(0xbd, 0x20 | 0x1f);
		d.run(2000);
		// toggle each instrument off/on
		d.write(0xbd, 0x20 | 0x10); // only BD
		d.run(1000);
		d.write(0xbd, 0x20 | 0x0f); // hh,sd,tom,tc
		d.run(1000);
		// vibrato + tremolo depth on, rhythm on
		d.write(0xbd, 0xc0 | 0x20 | 0x1f);
		d.run(1000);
		// rhythm off
		d.write(0xbd, 0x00);
		d.run(1000);
		CHECK(d.comparedSamples > 0);
	}

	SECTION("4-op channels: all 4 algorithms") {
		// Test all 4 4-op algorithm combinations (ch0.con, ch3.con) for the
		// 0+3 pair, and separately for the 9+12 pair.
		for (unsigned pair = 0; pair < 2; ++pair) {
			unsigned ch0 = (pair == 0) ? 0u : 9u;
			unsigned ch3 = ch0 + 3;
			uint8_t fourOpBit = (pair == 0) ? 0x01 : 0x08;
			for (uint8_t combo = 0; combo < 4; ++combo) {
				DualChip d;
				d.write(0x105, 0x01);      // NEW=1
				d.write(0x104, fourOpBit); // enable this 4-op pair
				// program all four operators of the pair
				for (unsigned ch : {ch0, ch3}) {
					unsigned base = (ch >= 9) ? 0x100 : 0x000;
					unsigned c9 = ch % 9;
					unsigned o0 = base + OP_OFFSET[c9][0];
					unsigned o1 = base + OP_OFFSET[c9][1];
					d.write(0x20 + o0, 0x01);
					d.write(0x20 + o1, 0x02);
					d.write(0x40 + o0, 0x08);
					d.write(0x40 + o1, 0x00);
					d.write(0x60 + o0, 0xf6);
					d.write(0x60 + o1, 0xf6);
					d.write(0x80 + o0, 0x22);
					d.write(0x80 + o1, 0x22);
					d.write(0xe0 + o0, 0x01);
					d.write(0xe0 + o1, 0x02);
				}
				unsigned base0 = (ch0 >= 9) ? 0x100 : 0x000;
				unsigned base3 = (ch3 >= 9) ? 0x100 : 0x000;
				// select algorithm via the two 'con' bits, set panning + fb
				d.write(0xc0 + base0 + (ch0 % 9), uint8_t(0x30 | ((combo >> 1) & 1)));
				d.write(0xc0 + base3 + (ch3 % 9), uint8_t(0x30 | (combo & 1)));
				// fnum + key-on on the primary channel of the pair
				d.write(0xa0 + base0 + (ch0 % 9), 0x81);
				d.write(0xb0 + base0 + (ch0 % 9), uint8_t(0x20 | (4 << 2) | 0x01));
				d.run(2500);
				// key-off
				d.write(0xb0 + base0 + (ch0 % 9), uint8_t((4 << 2) | 0x01));
				d.run(1500);
				CHECK(d.comparedSamples > 0);
			}
		}
	}

	SECTION("vibrato / tremolo depth toggles") {
		DualChip d;
		d.write(0x105, 0x01);
		// two voices with vib+AM enabled per operator (bit6=vib, bit7=am)
		d.set2op(0, 0x00, 0xc1, 0xc1, 0x12, 0x00, 0xf2, 0x12,
		         0x73, uint8_t(0x20 | (5 << 2) | 0x01), 0x31);
		d.set2op(1, 0x00, 0xc1, 0xc1, 0x12, 0x00, 0xf2, 0x12,
		         0x21, uint8_t(0x20 | (2 << 2) | 0x00), 0x30);
		for (uint8_t bd : {uint8_t(0x00), uint8_t(0x40), uint8_t(0x80), uint8_t(0xc0)}) {
			d.write(0xbd, bd); // DAM (bit7) / DVB (bit6) toggles
			d.run(4000);
		}
		CHECK(d.comparedSamples > 0);
	}

	SECTION("key on/off transitions and envelope edge rates (AR=15, RR=15)") {
		DualChip d;
		d.write(0x105, 0x01);
		unsigned c9 = 0;
		unsigned o0 = OP_OFFSET[c9][0];
		unsigned o1 = OP_OFFSET[c9][1];
		d.write(0x20 + o0, 0x01);
		d.write(0x20 + o1, 0x01);
		d.write(0x40 + o0, 0x00);
		d.write(0x40 + o1, 0x00);
		d.write(0x60 + o0, 0xff); // AR=15, DR=15
		d.write(0x60 + o1, 0xff);
		d.write(0x80 + o0, 0x0f); // SL=0, RR=15
		d.write(0x80 + o1, 0x0f);
		d.write(0xe0 + o0, 0x00);
		d.write(0xe0 + o1, 0x00);
		d.write(0xa0 + c9, 0xa0);
		d.write(0xc0 + c9, 0x30);
		// rapid key on/off transitions
		for (int rep = 0; rep < 40; ++rep) {
			d.write(0xb0 + c9, uint8_t(0x20 | (4 << 2) | 0x01)); // key on
			d.run(17);
			d.write(0xb0 + c9, uint8_t((4 << 2) | 0x01));        // key off
			d.run(13);
		}
		d.run(2000);
		CHECK(d.comparedSamples > 0);
	}

	SECTION("deterministic pseudo-random fuzz (>= 100k samples)") {
		DualChip d;
		std::mt19937 rng(0xC0FFEE); // fixed seed -> deterministic
		std::uniform_int_distribution<unsigned> regDist(0, 511);
		std::uniform_int_distribution<unsigned> valDist(0, 255);

		// 2000 batches: each batch does a few random register writes followed by
		// a block of generated samples. 2000 * 55 = 110000 compared samples.
		for (int batch = 0; batch < 2000; ++batch) {
			int nWrites = 1 + int(regDist(rng) % 4); // 1..4 writes per batch
			for (int w = 0; w < nWrites; ++w) {
				d.write(regDist(rng), uint8_t(valDist(rng)));
			}
			d.run(55);
		}
		CHECK(d.comparedSamples >= 100000);
	}

	// -----------------------------------------------------------------------
	// Silent-chip fast path. These stay bit-identical AND additionally check
	// that the fast path did (or did not) engage where expected. See the big
	// comment in YMF262NukeYKT.cc: the fast path targets the deep-idle state
	// (reset-like: f_num==0 and pg_phase==0 everywhere), which is genuinely
	// bit-silent for every waveform. A merely released voice with f_num!=0 is
	// deliberately NOT covered (its phase keeps running and waveforms 0/4/6/7
	// emit -1 on the negative half, so such a chip is not bit-silent).
	// -----------------------------------------------------------------------
	SECTION("silence: long idle from reset, then key-on (bit-exact wake-up)") {
		DualChip d;
		d.write(0x105, 0x01);
		d.run(12000); // deep idle -> fast path
		CHECK(d.fastPathSamples() > 0);
		d.set2op(0, 0x00, 0x01, 0x01, 0x1a, 0x00, 0xf4, 0x24, 0x50,
		         uint8_t(0x20 | (4 << 2) | 0x01), 0x30);
		d.run(3000); // play
		d.write(0xb0, uint8_t((4 << 2) | 0x01)); // key off
		d.run(3000); // release
		// 12000 idle samples, one lost to the pipeline-flush sample.
		CHECK(d.fastPathSamples() == 11999);
	}

	SECTION("silence: vibrato + tremolo depth set while idle (LFO stays in sync)") {
		DualChip d;
		d.write(0x105, 0x01);
		d.write(0xbd, 0xc0); // DAM + DVB depth on, rhythm OFF
		d.run(8000);
		CHECK(d.fastPathSamples() == 7999);
		d.set2op(1, 0x00, 0xc1, 0xc1, 0x12, 0x00, 0xf2, 0x12, 0x40,
		         uint8_t(0x20 | (3 << 2) | 0x01), 0x31);
		d.run(3000);
	}

	SECTION("silence: rhythm mode must NOT take the fast path (still bit-exact)") {
		DualChip d;
		d.write(0x105, 0x01);
		d.write(0xbd, 0x20); // rhythm on (no drum keys)
		d.run(6000);
		d.write(0xbd, 0x20 | 0x1f); // key all 5 drums
		d.run(2000);
		// Rhythm mode is excluded from the fast path.
		CHECK(d.fastPathSamples() == 0);
		d.write(0xbd, 0x00); // rhythm off -> back to deep idle
		d.run(6000);
		CHECK(d.fastPathSamples() > 0);
	}

	SECTION("silence: non-waking register writes while idle, then key-on") {
		DualChip d;
		d.write(0x105, 0x01);
		d.run(4000);
		d.write(0x40, 0x1a); // TL slot0
		d.write(0x43, 0x05); // TL slot3
		d.write(0xe0, 0x07); // waveform slot0 (neg-type): stays silent (phase==0)
		d.write(0xe3, 0x04);
		d.write(0x20, 0xf1); // AM/vib/EG-type/mult
		d.write(0xa0, 0x00); // f_num low = 0 (stays 0)
		d.run(4000);
		// The writes invalidate the cache but do not wake the chip, so both
		// 4000-sample stretches use the fast path (one flush sample overall).
		CHECK(d.fastPathSamples() == 7999);
		d.set2op(0, 0x00, 0x01, 0x01, 0x1a, 0x00, 0xf4, 0x24, 0x50,
		         uint8_t(0x20 | (4 << 2) | 0x01), 0x30);
		d.run(3000);
	}

	SECTION("silence: fast path re-engages after reset following activity") {
		DualChip d;
		d.write(0x105, 0x01);
		d.set2op(0, 0x00, 0x01, 0x01, 0x1a, 0x00, 0xf4, 0x24, 0x50,
		         uint8_t(0x20 | (4 << 2) | 0x01), 0x30);
		d.run(2000);
		CHECK(d.fastPathSamples() == 0); // never idle while playing
		d.resetBoth();
		d.write(0x105, 0x01);
		d.run(8000);
		CHECK(d.fastPathSamples() == 7999);
	}

	SECTION("silence: rapid idle/active toggling (flush + cache-invalidation)") {
		DualChip d;
		d.write(0x105, 0x01);
		for (int rep = 0; rep < 40; ++rep) {
			d.run(1 + (rep % 9));
			d.set2op(0, uint8_t(rep & 7), 0x01, 0x01, 0x1a, 0x00, 0xf4, 0x24,
			         uint8_t(0x40 + (rep & 0x1f)),
			         uint8_t(0x20 | (4 << 2) | 0x01), 0x30);
			d.run(20 + (rep % 5));
			d.write(0xb0, uint8_t((4 << 2) | 0x01)); // key off
			d.run(5 + (rep % 3));
			d.resetBoth();
			d.write(0x105, 0x01);
		}
		d.run(500);
		CHECK(d.comparedSamples > 0);
		CHECK(d.fastPathSamples() > 0);
	}
}
