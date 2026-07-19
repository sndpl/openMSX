#include "YMF262NukeYKT.hh"

#include "serialize.hh"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

namespace openmsx {
namespace YMF262NukeYKT {

namespace {

// ---------------------------------------------------------------------------
// Tables and helper functions, ported verbatim from the original opl3.cc.
// ---------------------------------------------------------------------------

// logsin table
constexpr std::array<uint16_t, 256> LOGSINROM = {
	0x859, 0x6c3, 0x607, 0x58b, 0x52e, 0x4e4, 0x4a6, 0x471,
	0x443, 0x41a, 0x3f5, 0x3d3, 0x3b5, 0x398, 0x37e, 0x365,
	0x34e, 0x339, 0x324, 0x311, 0x2ff, 0x2ed, 0x2dc, 0x2cd,
	0x2bd, 0x2af, 0x2a0, 0x293, 0x286, 0x279, 0x26d, 0x261,
	0x256, 0x24b, 0x240, 0x236, 0x22c, 0x222, 0x218, 0x20f,
	0x206, 0x1fd, 0x1f5, 0x1ec, 0x1e4, 0x1dc, 0x1d4, 0x1cd,
	0x1c5, 0x1be, 0x1b7, 0x1b0, 0x1a9, 0x1a2, 0x19b, 0x195,
	0x18f, 0x188, 0x182, 0x17c, 0x177, 0x171, 0x16b, 0x166,
	0x160, 0x15b, 0x155, 0x150, 0x14b, 0x146, 0x141, 0x13c,
	0x137, 0x133, 0x12e, 0x129, 0x125, 0x121, 0x11c, 0x118,
	0x114, 0x10f, 0x10b, 0x107, 0x103, 0x0ff, 0x0fb, 0x0f8,
	0x0f4, 0x0f0, 0x0ec, 0x0e9, 0x0e5, 0x0e2, 0x0de, 0x0db,
	0x0d7, 0x0d4, 0x0d1, 0x0cd, 0x0ca, 0x0c7, 0x0c4, 0x0c1,
	0x0be, 0x0bb, 0x0b8, 0x0b5, 0x0b2, 0x0af, 0x0ac, 0x0a9,
	0x0a7, 0x0a4, 0x0a1, 0x09f, 0x09c, 0x099, 0x097, 0x094,
	0x092, 0x08f, 0x08d, 0x08a, 0x088, 0x086, 0x083, 0x081,
	0x07f, 0x07d, 0x07a, 0x078, 0x076, 0x074, 0x072, 0x070,
	0x06e, 0x06c, 0x06a, 0x068, 0x066, 0x064, 0x062, 0x060,
	0x05e, 0x05c, 0x05b, 0x059, 0x057, 0x055, 0x053, 0x052,
	0x050, 0x04e, 0x04d, 0x04b, 0x04a, 0x048, 0x046, 0x045,
	0x043, 0x042, 0x040, 0x03f, 0x03e, 0x03c, 0x03b, 0x039,
	0x038, 0x037, 0x035, 0x034, 0x033, 0x031, 0x030, 0x02f,
	0x02e, 0x02d, 0x02b, 0x02a, 0x029, 0x028, 0x027, 0x026,
	0x025, 0x024, 0x023, 0x022, 0x021, 0x020, 0x01f, 0x01e,
	0x01d, 0x01c, 0x01b, 0x01a, 0x019, 0x018, 0x017, 0x017,
	0x016, 0x015, 0x014, 0x014, 0x013, 0x012, 0x011, 0x011,
	0x010, 0x00f, 0x00f, 0x00e, 0x00d, 0x00d, 0x00c, 0x00c,
	0x00b, 0x00a, 0x00a, 0x009, 0x009, 0x008, 0x008, 0x007,
	0x007, 0x007, 0x006, 0x006, 0x005, 0x005, 0x005, 0x004,
	0x004, 0x004, 0x003, 0x003, 0x003, 0x002, 0x002, 0x002,
	0x002, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000
};

// exp table
constexpr std::array<uint16_t, 256> EXPROM = {
	0x7fa, 0x7f5, 0x7ef, 0x7ea, 0x7e4, 0x7df, 0x7da, 0x7d4,
	0x7cf, 0x7c9, 0x7c4, 0x7bf, 0x7b9, 0x7b4, 0x7ae, 0x7a9,
	0x7a4, 0x79f, 0x799, 0x794, 0x78f, 0x78a, 0x784, 0x77f,
	0x77a, 0x775, 0x770, 0x76a, 0x765, 0x760, 0x75b, 0x756,
	0x751, 0x74c, 0x747, 0x742, 0x73d, 0x738, 0x733, 0x72e,
	0x729, 0x724, 0x71f, 0x71a, 0x715, 0x710, 0x70b, 0x706,
	0x702, 0x6fd, 0x6f8, 0x6f3, 0x6ee, 0x6e9, 0x6e5, 0x6e0,
	0x6db, 0x6d6, 0x6d2, 0x6cd, 0x6c8, 0x6c4, 0x6bf, 0x6ba,
	0x6b5, 0x6b1, 0x6ac, 0x6a8, 0x6a3, 0x69e, 0x69a, 0x695,
	0x691, 0x68c, 0x688, 0x683, 0x67f, 0x67a, 0x676, 0x671,
	0x66d, 0x668, 0x664, 0x65f, 0x65b, 0x657, 0x652, 0x64e,
	0x649, 0x645, 0x641, 0x63c, 0x638, 0x634, 0x630, 0x62b,
	0x627, 0x623, 0x61e, 0x61a, 0x616, 0x612, 0x60e, 0x609,
	0x605, 0x601, 0x5fd, 0x5f9, 0x5f5, 0x5f0, 0x5ec, 0x5e8,
	0x5e4, 0x5e0, 0x5dc, 0x5d8, 0x5d4, 0x5d0, 0x5cc, 0x5c8,
	0x5c4, 0x5c0, 0x5bc, 0x5b8, 0x5b4, 0x5b0, 0x5ac, 0x5a8,
	0x5a4, 0x5a0, 0x59c, 0x599, 0x595, 0x591, 0x58d, 0x589,
	0x585, 0x581, 0x57e, 0x57a, 0x576, 0x572, 0x56f, 0x56b,
	0x567, 0x563, 0x560, 0x55c, 0x558, 0x554, 0x551, 0x54d,
	0x549, 0x546, 0x542, 0x53e, 0x53b, 0x537, 0x534, 0x530,
	0x52c, 0x529, 0x525, 0x522, 0x51e, 0x51b, 0x517, 0x514,
	0x510, 0x50c, 0x509, 0x506, 0x502, 0x4ff, 0x4fb, 0x4f8,
	0x4f4, 0x4f1, 0x4ed, 0x4ea, 0x4e7, 0x4e3, 0x4e0, 0x4dc,
	0x4d9, 0x4d6, 0x4d2, 0x4cf, 0x4cc, 0x4c8, 0x4c5, 0x4c2,
	0x4be, 0x4bb, 0x4b8, 0x4b5, 0x4b1, 0x4ae, 0x4ab, 0x4a8,
	0x4a4, 0x4a1, 0x49e, 0x49b, 0x498, 0x494, 0x491, 0x48e,
	0x48b, 0x488, 0x485, 0x482, 0x47e, 0x47b, 0x478, 0x475,
	0x472, 0x46f, 0x46c, 0x469, 0x466, 0x463, 0x460, 0x45d,
	0x45a, 0x457, 0x454, 0x451, 0x44e, 0x44b, 0x448, 0x445,
	0x442, 0x43f, 0x43c, 0x439, 0x436, 0x433, 0x430, 0x42d,
	0x42a, 0x428, 0x425, 0x422, 0x41f, 0x41c, 0x419, 0x416,
	0x414, 0x411, 0x40e, 0x40b, 0x408, 0x406, 0x403, 0x400
};

// freq mult table multiplied by 2
constexpr std::array<uint8_t, 16> MT = {
	1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 20, 24, 24, 30, 30
};

// ksl table
constexpr std::array<uint8_t, 16> KSLROM = {
	0, 32, 40, 45, 48, 51, 53, 55, 56, 58, 59, 60, 61, 62, 63, 64
};
constexpr std::array<uint8_t, 4> KSLSHIFT = {8, 1, 2, 0};

// envelope generator constants
constexpr std::array<std::array<uint8_t, 4>, 4> EG_INCSTEP = {{
	{0, 0, 0, 0},
	{1, 0, 0, 0},
	{1, 0, 1, 0},
	{1, 1, 1, 0},
}};

// address decoding
constexpr std::array<int8_t, 0x20> AD_SLOT = {
	0, 1, 2, 3, 4, 5, -1, -1, 6, 7, 8, 9, 10, 11, -1, -1,
	12, 13, 14, 15, 16, 17, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

// channel -> slot number of its first operator (its second is +3)
constexpr std::array<uint8_t, 18> CH_SLOT = {
	0, 1, 2, 6, 7, 8, 12, 13, 14, 18, 19, 20, 24, 25, 26, 30, 31, 32
};

// slot index of operator 'n' (0 or 1) of channel 'c'. This is fixed after
// reset (was: channel->slotz[n] pointer).
[[nodiscard]] constexpr uint8_t slotIdx(unsigned c, unsigned n)
{
	return uint8_t(CH_SLOT[c] + 3 * n);
}

// reverse mapping slot -> owning channel (was: slot->channel pointer, fixed).
constexpr auto SLOT_CHANNEL = [] {
	std::array<uint8_t, 36> t = {};
	for (uint8_t c = 0; c < 18; ++c) {
		t[CH_SLOT[c] + 0] = c;
		t[CH_SLOT[c] + 3] = c;
	}
	return t;
}();

// 4-operator pairing (was: channel->pair pointer, fixed). 0xff = no pair
// (channels 6,7,8,15,16,17 are never part of a 4op channel; their pair is
// never dereferenced).
constexpr std::array<uint8_t, 18> CHANNEL_PAIR = {
	3, 4, 5, 0, 1, 2, 0xff, 0xff, 0xff,
	12, 13, 14, 9, 10, 11, 0xff, 0xff, 0xff
};

[[nodiscard]] int16_t envelopeCalcExp(uint32_t level)
{
	if (level > 0x1fff) level = 0x1fff;
	return int16_t((EXPROM[level & 0xff] << 1) >> (level >> 8));
}

[[nodiscard]] int16_t envelopeCalcSin0(uint16_t phase, uint16_t envelope)
{
	uint16_t out = 0;
	uint16_t neg = 0;
	phase &= 0x3ff;
	if (phase & 0x200) neg = 0xffff;
	if (phase & 0x100) out = LOGSINROM[(phase & 0xff) ^ 0xff];
	else               out = LOGSINROM[phase & 0xff];
	return int16_t(envelopeCalcExp(out + unsigned(envelope << 3)) ^ neg);
}
[[nodiscard]] int16_t envelopeCalcSin1(uint16_t phase, uint16_t envelope)
{
	uint16_t out = 0;
	phase &= 0x3ff;
	if      (phase & 0x200) out = 0x1000;
	else if (phase & 0x100) out = LOGSINROM[(phase & 0xff) ^ 0xff];
	else                    out = LOGSINROM[phase & 0xff];
	return envelopeCalcExp(out + unsigned(envelope << 3));
}
[[nodiscard]] int16_t envelopeCalcSin2(uint16_t phase, uint16_t envelope)
{
	uint16_t out = 0;
	phase &= 0x3ff;
	if (phase & 0x100) out = LOGSINROM[(phase & 0xff) ^ 0xff];
	else               out = LOGSINROM[phase & 0xff];
	return envelopeCalcExp(out + unsigned(envelope << 3));
}
[[nodiscard]] int16_t envelopeCalcSin3(uint16_t phase, uint16_t envelope)
{
	uint16_t out = 0;
	phase &= 0x3ff;
	if (phase & 0x100) out = 0x1000;
	else               out = LOGSINROM[phase & 0xff];
	return envelopeCalcExp(out + unsigned(envelope << 3));
}
[[nodiscard]] int16_t envelopeCalcSin4(uint16_t phase, uint16_t envelope)
{
	uint16_t out = 0;
	uint16_t neg = 0;
	phase &= 0x3ff;
	if ((phase & 0x300) == 0x100) neg = 0xffff;
	if      (phase & 0x200) out = 0x1000;
	else if (phase & 0x80)  out = LOGSINROM[((phase ^ 0xff) << 1) & 0xff];
	else                    out = LOGSINROM[(phase << 1) & 0xff];
	return int16_t(envelopeCalcExp(out + unsigned(envelope << 3)) ^ neg);
}
[[nodiscard]] int16_t envelopeCalcSin5(uint16_t phase, uint16_t envelope)
{
	uint16_t out = 0;
	phase &= 0x3ff;
	if      (phase & 0x200) out = 0x1000;
	else if (phase & 0x80)  out = LOGSINROM[((phase ^ 0xff) << 1) & 0xff];
	else                    out = LOGSINROM[(phase << 1) & 0xff];
	return envelopeCalcExp(out + unsigned(envelope << 3));
}
[[nodiscard]] int16_t envelopeCalcSin6(uint16_t phase, uint16_t envelope)
{
	uint16_t neg = 0;
	phase &= 0x3ff;
	if (phase & 0x200) neg = 0xffff;
	return int16_t(envelopeCalcExp(unsigned(envelope << 3)) ^ neg);
}
[[nodiscard]] int16_t envelopeCalcSin7(uint16_t phase, uint16_t envelope)
{
	uint16_t neg = 0;
	phase &= 0x3ff;
	if (phase & 0x200) {
		neg = 0xffff;
		phase = (phase & 0x1ff) ^ 0x1ff;
	}
	uint16_t out = uint16_t(phase << 3);
	return int16_t(envelopeCalcExp(out + unsigned(envelope << 3)) ^ neg);
}

using EnvelopeSinFunc = int16_t (*)(uint16_t phase, uint16_t envelope);
constexpr std::array<EnvelopeSinFunc, 8> ENVELOPE_SIN = {
	envelopeCalcSin0, envelopeCalcSin1, envelopeCalcSin2, envelopeCalcSin3,
	envelopeCalcSin4, envelopeCalcSin5, envelopeCalcSin6, envelopeCalcSin7
};

[[nodiscard]] int16_t clipSample(int32_t sample)
{
	if      (sample > 32767)  sample = 32767;
	else if (sample < -32768) sample = -32768;
	return int16_t(sample);
}

} // anonymous namespace


YMF262::YMF262()
{
	reset();
}

// ---------------------------------------------------------------------------
// Envelope generator (OPL3_EnvelopeUpdateKSL / OPL3_EnvelopeCalc)
// ---------------------------------------------------------------------------

void YMF262::envelopeUpdateKSL(uint8_t s)
{
	const Channel& ch = channel[SLOT_CHANNEL[s]];
	int16_t ksl = int16_t((KSLROM[ch.f_num >> 6] << 2)
	                      - ((0x08 - ch.block) << 5));
	if (ksl < 0) ksl = 0;
	slot[s].eg_ksl = uint8_t(ksl);
}

void YMF262::envelopeCalc(uint8_t s)
{
	Slot& sl = slot[s];
	const Channel& ch = channel[SLOT_CHANNEL[s]];

	uint8_t reg_rate = 0;
	uint8_t reset = 0;
	sl.eg_out = uint16_t(sl.eg_rout + (sl.reg_tl << 2)
	                     + (sl.eg_ksl >> KSLSHIFT[sl.reg_ksl])
	                     + (sl.trem ? tremolo : 0));
	if (sl.key && sl.eg_gen == EG_RELEASE) {
		reset = 1;
		reg_rate = sl.reg_ar;
	} else {
		switch (sl.eg_gen) {
		case EG_ATTACK:  reg_rate = sl.reg_ar; break;
		case EG_DECAY:   reg_rate = sl.reg_dr; break;
		case EG_SUSTAIN: if (!sl.reg_type) reg_rate = sl.reg_rr; break;
		case EG_RELEASE: reg_rate = sl.reg_rr; break;
		}
	}
	sl.pg_reset = reset;
	uint8_t ks = uint8_t(ch.ksv >> ((sl.reg_ksr ^ 1) << 1));
	uint8_t nonzero = (reg_rate != 0);
	uint8_t rate = uint8_t(ks + (reg_rate << 2));
	uint8_t rate_hi = rate >> 2;
	uint8_t rate_lo = rate & 0x03;
	if (rate_hi & 0x10) rate_hi = 0x0f;
	uint8_t eg_shift = uint8_t(rate_hi + eg_add);
	uint8_t shift = 0;
	if (nonzero) {
		if (rate_hi < 12) {
			if (eg_state) {
				switch (eg_shift) {
				case 12: shift = 1; break;
				case 13: shift = (rate_lo >> 1) & 0x01; break;
				case 14: shift = rate_lo & 0x01; break;
				default: break;
				}
			}
		} else {
			shift = uint8_t((rate_hi & 0x03) + EG_INCSTEP[rate_lo][eg_timer_lo]);
			if (shift & 0x04) shift = 0x03;
			if (!shift) shift = eg_state;
		}
	}
	uint16_t eg_rout = sl.eg_rout;
	int16_t eg_inc = 0;
	uint8_t eg_off = 0;
	// Instant attack
	if (reset && rate_hi == 0x0f) eg_rout = 0x00;
	// Envelope off
	if ((sl.eg_rout & 0x1f8) == 0x1f8) eg_off = 1;
	if (sl.eg_gen != EG_ATTACK && !reset && eg_off) eg_rout = 0x1ff;
	switch (sl.eg_gen) {
	case EG_ATTACK:
		if (!sl.eg_rout) {
			sl.eg_gen = EG_DECAY;
		} else if (sl.key && shift > 0 && rate_hi != 0x0f) {
			eg_inc = int16_t(~sl.eg_rout >> (4 - shift));
		}
		break;
	case EG_DECAY:
		if ((sl.eg_rout >> 4) == sl.reg_sl) {
			sl.eg_gen = EG_SUSTAIN;
		} else if (!eg_off && !reset && shift > 0) {
			eg_inc = int16_t(1 << (shift - 1));
		}
		break;
	case EG_SUSTAIN:
	case EG_RELEASE:
		if (!eg_off && !reset && shift > 0) {
			eg_inc = int16_t(1 << (shift - 1));
		}
		break;
	}
	sl.eg_rout = (eg_rout + eg_inc) & 0x1ff;
	// Key off
	if (reset) sl.eg_gen = EG_ATTACK;
	if (!sl.key) sl.eg_gen = EG_RELEASE;
}

// ---------------------------------------------------------------------------
// Phase generator (OPL3_PhaseGenerate)
// ---------------------------------------------------------------------------

template<bool RHYTHM>
void YMF262::phaseGenerate(uint8_t s)
{
	Slot& sl = slot[s];
	const Channel& ch = channel[SLOT_CHANNEL[s]];

	uint16_t f_num = ch.f_num;
	if (sl.reg_vib) {
		int8_t range = (f_num >> 7) & 7;
		uint8_t vp = vibpos;
		if (!(vp & 3))     range = 0;
		else if (vp & 1)   range >>= 1;
		range >>= vibshift;
		if (vp & 4)        range = int8_t(-range);
		f_num = uint16_t(f_num + range);
	}
	uint32_t basefreq = uint32_t(f_num << ch.block) >> 1;
	auto phase = uint16_t(sl.pg_phase >> 9);
	if (sl.pg_reset) sl.pg_phase = 0;
	sl.pg_phase += (basefreq * MT[sl.reg_mult]) >> 1;
	uint32_t localNoise = noise;
	sl.pg_phase_out = phase;
	// The hi-hat phase bits are latched every sample on real HW, independent of
	// rhythm mode, so this stays unconditional (keeps rm_hh_bit* in sync so that
	// enabling rhythm later is bit-exact).
	if (s == 13) { // hh
		rm_hh_bit2 = (phase >> 2) & 1;
		rm_hh_bit3 = (phase >> 3) & 1;
		rm_hh_bit7 = (phase >> 7) & 1;
		rm_hh_bit8 = (phase >> 8) & 1;
	}
	// Rhythm mode. RHYTHM==(rhy&0x20)!=0 for the whole call (see header), so the
	// per-slot rhy test is resolved at compile time.
	if constexpr (RHYTHM) {
		if (s == 17) { // tc
			rm_tc_bit3 = (phase >> 3) & 1;
			rm_tc_bit5 = (phase >> 5) & 1;
		}
		uint8_t rm_xor = (rm_hh_bit2 ^ rm_hh_bit7)
		               | (rm_hh_bit3 ^ rm_tc_bit5)
		               | (rm_tc_bit3 ^ rm_tc_bit5);
		switch (s) {
		case 13: // hh
			sl.pg_phase_out = uint16_t(rm_xor << 9);
			if (rm_xor ^ (localNoise & 1)) sl.pg_phase_out |= 0xd0;
			else                           sl.pg_phase_out |= 0x34;
			break;
		case 16: // sd
			sl.pg_phase_out = uint16_t((rm_hh_bit8 << 9)
			                | ((rm_hh_bit8 ^ (localNoise & 1)) << 8));
			break;
		case 17: // tc
			sl.pg_phase_out = uint16_t((rm_xor << 9) | 0x80);
			break;
		default:
			break;
		}
	}
	uint8_t n_bit = ((localNoise >> 14) ^ localNoise) & 0x01;
	noise = (localNoise >> 1) | (n_bit << 22);
}

// ---------------------------------------------------------------------------
// Slot (OPL3_SlotWrite* / OPL3_SlotGenerate / OPL3_SlotCalcFB)
// ---------------------------------------------------------------------------

void YMF262::slotWrite20(uint8_t s, uint8_t data)
{
	Slot& sl = slot[s];
	sl.trem     = (data >> 7) & 0x01; // was pointer to chip->tremolo / zeromod
	sl.reg_vib  = (data >> 6) & 0x01;
	sl.reg_type = (data >> 5) & 0x01;
	sl.reg_ksr  = (data >> 4) & 0x01;
	sl.reg_mult = data & 0x0f;
}
void YMF262::slotWrite40(uint8_t s, uint8_t data)
{
	slot[s].reg_ksl = (data >> 6) & 0x03;
	slot[s].reg_tl  = data & 0x3f;
	envelopeUpdateKSL(s);
}
void YMF262::slotWrite60(uint8_t s, uint8_t data)
{
	slot[s].reg_ar = (data >> 4) & 0x0f;
	slot[s].reg_dr = data & 0x0f;
}
void YMF262::slotWrite80(uint8_t s, uint8_t data)
{
	Slot& sl = slot[s];
	sl.reg_sl = (data >> 4) & 0x0f;
	if (sl.reg_sl == 0x0f) sl.reg_sl = 0x1f;
	sl.reg_rr = data & 0x0f;
}
void YMF262::slotWriteE0(uint8_t s, uint8_t data)
{
	slot[s].reg_wf = data & 0x07;
	if (newm == 0x00) slot[s].reg_wf &= 0x03;
}

void YMF262::slotGenerate(uint8_t s)
{
	Slot& sl = slot[s];
	auto arg = uint16_t(sl.pg_phase_out + getModValue(sl));
	sl.out = ENVELOPE_SIN[sl.reg_wf](arg, sl.eg_out);
}

void YMF262::slotCalcFB(uint8_t s)
{
	Slot& sl = slot[s];
	const Channel& ch = channel[SLOT_CHANNEL[s]];
	if (ch.fb != 0x00) {
		sl.fbmod = int16_t((sl.prout + sl.out) >> (0x09 - ch.fb));
	} else {
		sl.fbmod = 0;
	}
	sl.prout = sl.out;
}

// ---------------------------------------------------------------------------
// Channel (OPL3_Channel*)
// ---------------------------------------------------------------------------

void YMF262::channelUpdateRhythm(uint8_t data)
{
	rhy = data & 0x3f;
	if (rhy & 0x20) {
		channel[6].out = {slotIdx(6, 1), slotIdx(6, 1), NO_SLOT, NO_SLOT};
		channel[7].out = {slotIdx(7, 0), slotIdx(7, 0), slotIdx(7, 1), slotIdx(7, 1)};
		channel[8].out = {slotIdx(8, 0), slotIdx(8, 0), slotIdx(8, 1), slotIdx(8, 1)};
		for (uint8_t c = 6; c < 9; ++c) channel[c].chType = CH_DRUM;
		channelSetupAlg(6);
		channelSetupAlg(7);
		channelSetupAlg(8);
		// hh
		if (rhy & 0x01) slot[slotIdx(7, 0)].key |= EGK_DRUM;
		else            slot[slotIdx(7, 0)].key &= ~EGK_DRUM;
		// tc
		if (rhy & 0x02) slot[slotIdx(8, 1)].key |= EGK_DRUM;
		else            slot[slotIdx(8, 1)].key &= ~EGK_DRUM;
		// tom
		if (rhy & 0x04) slot[slotIdx(8, 0)].key |= EGK_DRUM;
		else            slot[slotIdx(8, 0)].key &= ~EGK_DRUM;
		// sd
		if (rhy & 0x08) slot[slotIdx(7, 1)].key |= EGK_DRUM;
		else            slot[slotIdx(7, 1)].key &= ~EGK_DRUM;
		// bd
		if (rhy & 0x10) {
			slot[slotIdx(6, 0)].key |= EGK_DRUM;
			slot[slotIdx(6, 1)].key |= EGK_DRUM;
		} else {
			slot[slotIdx(6, 0)].key &= ~EGK_DRUM;
			slot[slotIdx(6, 1)].key &= ~EGK_DRUM;
		}
	} else {
		for (uint8_t c = 6; c < 9; ++c) {
			channel[c].chType = CH_2OP;
			channelSetupAlg(c);
			slot[slotIdx(c, 0)].key &= ~EGK_DRUM;
			slot[slotIdx(c, 1)].key &= ~EGK_DRUM;
		}
	}
}

void YMF262::channelWriteA0(uint8_t c, uint8_t data)
{
	Channel& ch = channel[c];
	if (newm && ch.chType == CH_4OP2) return;
	ch.f_num = (ch.f_num & 0x300) | data;
	ch.ksv = uint8_t((ch.block << 1)
	                 | ((ch.f_num >> (0x09 - nts)) & 0x01));
	envelopeUpdateKSL(slotIdx(c, 0));
	envelopeUpdateKSL(slotIdx(c, 1));
	if (newm && ch.chType == CH_4OP) {
		uint8_t p = CHANNEL_PAIR[c];
		channel[p].f_num = ch.f_num;
		channel[p].ksv = ch.ksv;
		envelopeUpdateKSL(slotIdx(p, 0));
		envelopeUpdateKSL(slotIdx(p, 1));
	}
}

void YMF262::channelWriteB0(uint8_t c, uint8_t data)
{
	Channel& ch = channel[c];
	if (newm && ch.chType == CH_4OP2) return;
	ch.f_num = (ch.f_num & 0xff) | uint16_t((data & 0x03) << 8);
	ch.block = (data >> 2) & 0x07;
	ch.ksv = uint8_t((ch.block << 1)
	                 | ((ch.f_num >> (0x09 - nts)) & 0x01));
	envelopeUpdateKSL(slotIdx(c, 0));
	envelopeUpdateKSL(slotIdx(c, 1));
	if (newm && ch.chType == CH_4OP) {
		uint8_t p = CHANNEL_PAIR[c];
		channel[p].f_num = ch.f_num;
		channel[p].block = ch.block;
		channel[p].ksv = ch.ksv;
		envelopeUpdateKSL(slotIdx(p, 0));
		envelopeUpdateKSL(slotIdx(p, 1));
	}
}

void YMF262::channelSetupAlg(uint8_t c)
{
	Channel& ch = channel[c];
	uint8_t s0 = slotIdx(c, 0);
	uint8_t s1 = slotIdx(c, 1);
	auto modZero = [&](uint8_t si) { slot[si].modSrc = MOD_ZERO; };
	auto modFb   = [&](uint8_t si) { slot[si].modSrc = MOD_FBMOD; slot[si].modSlot = si; };
	auto modOut  = [&](uint8_t si, uint8_t src) { slot[si].modSrc = MOD_OUT; slot[si].modSlot = src; };

	if (ch.chType == CH_DRUM) {
		if (c == 7 || c == 8) {
			modZero(s0);
			modZero(s1);
			return;
		}
		switch (ch.alg & 0x01) {
		case 0x00: modFb(s0); modOut(s1, s0); break;
		case 0x01: modFb(s0); modZero(s1);    break;
		}
		return;
	}
	if (ch.alg & 0x08) return;
	if (ch.alg & 0x04) {
		uint8_t p = CHANNEL_PAIR[c];
		Channel& pc = channel[p];
		uint8_t ps0 = slotIdx(p, 0);
		uint8_t ps1 = slotIdx(p, 1);
		pc.out = {NO_SLOT, NO_SLOT, NO_SLOT, NO_SLOT};
		switch (ch.alg & 0x03) {
		case 0x00:
			modFb(ps0); modOut(ps1, ps0); modOut(s0, ps1); modOut(s1, s0);
			ch.out = {s1, NO_SLOT, NO_SLOT, NO_SLOT};
			break;
		case 0x01:
			modFb(ps0); modOut(ps1, ps0); modZero(s0); modOut(s1, s0);
			ch.out = {ps1, s1, NO_SLOT, NO_SLOT};
			break;
		case 0x02:
			modFb(ps0); modZero(ps1); modOut(s0, ps1); modOut(s1, s0);
			ch.out = {ps0, s1, NO_SLOT, NO_SLOT};
			break;
		case 0x03:
			modFb(ps0); modZero(ps1); modOut(s0, ps1); modZero(s1);
			ch.out = {ps0, s0, s1, NO_SLOT};
			break;
		}
	} else {
		switch (ch.alg & 0x01) {
		case 0x00:
			modFb(s0); modOut(s1, s0);
			ch.out = {s1, NO_SLOT, NO_SLOT, NO_SLOT};
			break;
		case 0x01:
			modFb(s0); modZero(s1);
			ch.out = {s0, s1, NO_SLOT, NO_SLOT};
			break;
		}
	}
}

void YMF262::channelUpdateAlg(uint8_t c)
{
	Channel& ch = channel[c];
	ch.alg = ch.con;
	if (newm) {
		uint8_t p = CHANNEL_PAIR[c];
		if (ch.chType == CH_4OP) {
			channel[p].alg = uint8_t(0x04 | (ch.con << 1) | channel[p].con);
			ch.alg = 0x08;
			channelSetupAlg(p);
		} else if (ch.chType == CH_4OP2) {
			ch.alg = uint8_t(0x04 | (channel[p].con << 1) | ch.con);
			channel[p].alg = 0x08;
			channelSetupAlg(c);
		} else {
			channelSetupAlg(c);
		}
	} else {
		channelSetupAlg(c);
	}
}

void YMF262::channelWriteC0(uint8_t c, uint8_t data)
{
	Channel& ch = channel[c];
	ch.fb = (data & 0x0e) >> 1;
	ch.con = data & 0x01;
	channelUpdateAlg(c);
	if (newm) {
		ch.cha = ((data >> 4) & 0x01) ? 0xffff : 0;
		ch.chb = ((data >> 5) & 0x01) ? 0xffff : 0;
		ch.chc = ((data >> 6) & 0x01) ? 0xffff : 0;
		ch.chd = ((data >> 7) & 0x01) ? 0xffff : 0;
	} else {
		ch.cha = ch.chb = 0xffff;
		// TODO: Verify on real chip if DAC2 output is disabled in compat mode
		ch.chc = ch.chd = 0;
	}
}

void YMF262::channelKeyOn(uint8_t c)
{
	const Channel& ch = channel[c];
	if (newm) {
		if (ch.chType == CH_4OP) {
			uint8_t p = CHANNEL_PAIR[c];
			slot[slotIdx(c, 0)].key |= EGK_NORM;
			slot[slotIdx(c, 1)].key |= EGK_NORM;
			slot[slotIdx(p, 0)].key |= EGK_NORM;
			slot[slotIdx(p, 1)].key |= EGK_NORM;
		} else if (ch.chType == CH_2OP || ch.chType == CH_DRUM) {
			slot[slotIdx(c, 0)].key |= EGK_NORM;
			slot[slotIdx(c, 1)].key |= EGK_NORM;
		}
	} else {
		slot[slotIdx(c, 0)].key |= EGK_NORM;
		slot[slotIdx(c, 1)].key |= EGK_NORM;
	}
}

void YMF262::channelKeyOff(uint8_t c)
{
	const Channel& ch = channel[c];
	if (newm) {
		if (ch.chType == CH_4OP) {
			uint8_t p = CHANNEL_PAIR[c];
			slot[slotIdx(c, 0)].key &= ~EGK_NORM;
			slot[slotIdx(c, 1)].key &= ~EGK_NORM;
			slot[slotIdx(p, 0)].key &= ~EGK_NORM;
			slot[slotIdx(p, 1)].key &= ~EGK_NORM;
		} else if (ch.chType == CH_2OP || ch.chType == CH_DRUM) {
			slot[slotIdx(c, 0)].key &= ~EGK_NORM;
			slot[slotIdx(c, 1)].key &= ~EGK_NORM;
		}
	} else {
		slot[slotIdx(c, 0)].key &= ~EGK_NORM;
		slot[slotIdx(c, 1)].key &= ~EGK_NORM;
	}
}

void YMF262::channelSet4Op(uint8_t data)
{
	for (uint8_t bit = 0; bit < 6; ++bit) {
		uint8_t chnum = bit;
		if (bit >= 3) chnum += 9 - 3;
		if ((data >> bit) & 0x01) {
			channel[chnum].chType = CH_4OP;
			channel[chnum + 3].chType = CH_4OP2;
			channelUpdateAlg(chnum);
		} else {
			channel[chnum].chType = CH_2OP;
			channel[chnum + 3].chType = CH_2OP;
			channelUpdateAlg(chnum);
			channelUpdateAlg(chnum + 3);
		}
	}
}

// ---------------------------------------------------------------------------
// Register write dispatch (OPL3_WriteReg)
// ---------------------------------------------------------------------------

void YMF262::writeReg(unsigned reg, uint8_t value)
{
	assert(reg < 512);
	regs[reg] = value; // peekReg() mirror
	idleConfirmed = false; // any register write may invalidate the idle predicate

	uint8_t high = (reg >> 8) & 0x01;
	uint8_t regm = reg & 0xff;
	switch (regm & 0xf0) {
	case 0x00:
		if (high) {
			switch (regm & 0x0f) {
			case 0x04: channelSet4Op(value); break;
			case 0x05: newm = value & 0x01;  break;
			}
		} else {
			switch (regm & 0x0f) {
			case 0x08: nts = (value >> 6) & 0x01; break;
			}
		}
		break;
	case 0x20:
	case 0x30:
		if (AD_SLOT[regm & 0x1f] >= 0) {
			slotWrite20(uint8_t(18 * high + AD_SLOT[regm & 0x1f]), value);
		}
		break;
	case 0x40:
	case 0x50:
		if (AD_SLOT[regm & 0x1f] >= 0) {
			slotWrite40(uint8_t(18 * high + AD_SLOT[regm & 0x1f]), value);
		}
		break;
	case 0x60:
	case 0x70:
		if (AD_SLOT[regm & 0x1f] >= 0) {
			slotWrite60(uint8_t(18 * high + AD_SLOT[regm & 0x1f]), value);
		}
		break;
	case 0x80:
	case 0x90:
		if (AD_SLOT[regm & 0x1f] >= 0) {
			slotWrite80(uint8_t(18 * high + AD_SLOT[regm & 0x1f]), value);
		}
		break;
	case 0xe0:
	case 0xf0:
		if (AD_SLOT[regm & 0x1f] >= 0) {
			slotWriteE0(uint8_t(18 * high + AD_SLOT[regm & 0x1f]), value);
		}
		break;
	case 0xa0:
		if ((regm & 0x0f) < 9) {
			channelWriteA0(uint8_t(9 * high + (regm & 0x0f)), value);
		}
		break;
	case 0xb0:
		if (regm == 0xbd && !high) {
			tremoloshift = uint8_t((((value >> 7) ^ 1) << 1) + 2);
			vibshift = ((value >> 6) & 0x01) ^ 1;
			channelUpdateRhythm(value);
		} else if ((regm & 0x0f) < 9) {
			auto c = uint8_t(9 * high + (regm & 0x0f));
			channelWriteB0(c, value);
			if (value & 0x20) channelKeyOn(c);
			else              channelKeyOff(c);
		}
		break;
	case 0xc0:
		if ((regm & 0x0f) < 9) {
			channelWriteC0(uint8_t(9 * high + (regm & 0x0f)), value);
		}
		break;
	default:
		break;
	}
}

uint8_t YMF262::peekReg(unsigned reg) const
{
	assert(reg < 512);
	return regs[reg];
}

// ---------------------------------------------------------------------------
// Per-sample generation (OPL3_Generate4Ch, OPL_QUIRK_CHANNELSAMPLEDELAY ON)
// ---------------------------------------------------------------------------

void YMF262::advanceState()
{
	// End-of-sample global bookkeeping (identical in the full and fast paths).

	// Tremolo
	if ((timer & 0x3f) == 0x3f) tremolopos = (tremolopos + 1) % 210;
	if (tremolopos < 105) tremolo = tremolopos >> tremoloshift;
	else                  tremolo = uint8_t((210 - tremolopos) >> tremoloshift);

	// Vibrato
	if ((timer & 0x3ff) == 0x3ff) vibpos = (vibpos + 1) & 7;

	timer++;

	if (eg_state) {
		uint8_t shift = 0;
		while (shift < 13 && ((eg_timer >> shift) & 1) == 0) ++shift;
		if (shift > 12) eg_add = 0;
		else            eg_add = uint8_t(shift + 1);
		eg_timer_lo = uint8_t(eg_timer & 0x3);
	}

	if (eg_timerrem || eg_state) {
		if (eg_timer == UINT64_C(0xfffffffff)) {
			eg_timer = 0;
			eg_timerrem = 1;
		} else {
			eg_timer++;
			eg_timerrem = 0;
		}
	}

	eg_state ^= 1;
}

template<bool RHYTHM>
void YMF262::generateSample(std::span<int16_t, 4> pins)
{
	// The right DAC pins are output one sample later than the left (this is
	// OPL_QUIRK_CHANNELSAMPLEDELAY, which is ON in the reference build because
	// OPL_ENABLE_STEREOEXT==0). So they read the accumulators computed at the
	// end of the *previous* call.
	pins[1] = clipSample(mixBuff[1]);
	pins[3] = clipSample(mixBuff[3]);

	for (uint8_t i = 0; i < 15; ++i) processSlot<RHYTHM>(i);

	// left mix (pins 0 and 2: cha/chc)
	int32_t mix0 = 0;
	int32_t mix2 = 0;
	for (uint8_t c = 0; c < 18; ++c) {
		const Channel& ch = channel[c];
		auto accm = int16_t(chanOutVal(ch.out[0]) + chanOutVal(ch.out[1])
		                  + chanOutVal(ch.out[2]) + chanOutVal(ch.out[3]));
		auto la = int16_t(accm & ch.cha);
		mix0 += la;
		mix2 += int16_t(accm & ch.chc);
		chLeftOut[c] = la;
	}
	mixBuff[0] = mix0;
	mixBuff[2] = mix2;

	for (uint8_t i = 15; i < 18; ++i) processSlot<RHYTHM>(i);

	pins[0] = clipSample(mixBuff[0]);
	pins[2] = clipSample(mixBuff[2]);

	for (uint8_t i = 18; i < 33; ++i) processSlot<RHYTHM>(i);

	// right mix (pins 1 and 3: chb/chd)
	int32_t mix1 = 0;
	int32_t mix3 = 0;
	for (uint8_t c = 0; c < 18; ++c) {
		const Channel& ch = channel[c];
		auto accm = int16_t(chanOutVal(ch.out[0]) + chanOutVal(ch.out[1])
		                  + chanOutVal(ch.out[2]) + chanOutVal(ch.out[3]));
		auto rb = int16_t(accm & ch.chb);
		mix1 += rb;
		mix3 += int16_t(accm & ch.chd);
		chRightOut[c] = rb;
	}
	mixBuff[1] = mix1;
	mixBuff[3] = mix3;

	for (uint8_t i = 33; i < 36; ++i) processSlot<RHYTHM>(i);

	advanceState();
}

// ---------------------------------------------------------------------------
// Silent-chip fast path
//
// Unlike the Burczynski core (which freezes state when muted), this core is
// validated per-sample against the die-accurate reference, so the fast path
// must leave ALL state EXACTLY as a full sample would.
//
// Predicate ("deep idle"), all of which must hold:
//   * rhythm mode disabled: (rhy & 0x20) == 0
//   * every channel:  f_num == 0
//   * every slot:     key == 0, eg_gen == RELEASE, eg_rout == 0x1ff,
//                     pg_phase == 0, out == 0, prout == 0, fbmod == 0
//
// Why this is exactly the "provably silent AND trivial-to-advance" set:
//   - f_num == 0  =>  the phase increment (basefreq*mt)>>1 is 0 (basefreq =
//     (f_num<<block)>>1, and vibrato range derives from f_num>>7 == 0), so
//     pg_phase is frozen. With pg_phase == 0 the phase output is 0.
//   - eg_rout == 0x1ff (and key==0, eg_gen==RELEASE)  =>  OPL3_EnvelopeCalc
//     leaves eg_rout at 0x1ff (eg_off path), keeps eg_gen==RELEASE and
//     pg_reset==0, and never triggers attack. The exp() of a >=0x1ff envelope
//     is 0, so every waveform yields out == 0 at phase 0 (no negative-half
//     "-1"). NOTE: a *released* voice with f_num != 0 is deliberately NOT
//     covered - its phase keeps advancing and waveforms 0/4/6/7 emit -1 on the
//     negative half, i.e. such a chip is genuinely not bit-silent.
//   - With pg_phase == 0 the output stays 0 for ANY waveform, so a waveform (or
//     TL/KSL) write during idle keeps the chip silent (out stays 0) - the fast
//     path is robust to such writes without re-deriving out.
//
// Under the predicate, a full sample would change ONLY:
//   - eg_out of every slot (recomputed from tremolo; transient, but reproduced
//     here so the whole state stays bit-exact),
//   - the noise LFSR (advanced once per slot, i.e. 36x),
//   - the global LFO/timer/EG bookkeeping (advanceState()).
// Everything else (out, prout, fbmod, pg_phase, pg_phase_out, eg_rout, eg_gen,
// pg_reset, rm_* bits, mixBuff, chLeftOut/chRightOut) is provably unchanged, and
// all four DAC pins are 0.
//
// Because no register write happens during a generate call, once the predicate
// holds it keeps holding for the rest of the call; it can only be broken by a
// later writeReg (which clears idleConfirmed).
// ---------------------------------------------------------------------------

bool YMF262::fullSilentScan() const
{
	if (rhy & 0x20) return false; // rhythm is excluded from the fast path
	for (const Slot& sl : slot) {
		if (sl.out || sl.prout || sl.fbmod || sl.key || sl.pg_phase ||
		    (sl.eg_rout != 0x1ff) || (sl.eg_gen != EG_RELEASE)) {
			return false;
		}
	}
	for (const Channel& ch : channel) {
		if (ch.f_num) return false;
	}
	return true;
}

bool YMF262::checkIdle()
{
	if (idleConfirmed) return true;      // still valid: no register write since
	if (!fullSilentScan()) return false;
	idleConfirmed = true;                // stays idle until the next writeReg()
	return true;
}

void YMF262::fastSilentAdvance()
{
	// Reproduce exactly the state changes a full sample makes under the idle
	// predicate: recompute eg_out for every slot (mirrors the first line of
	// OPL3_EnvelopeCalc) and advance the noise LFSR once per slot (36x, mirrors
	// OPL3_PhaseGenerate). eg_rout is 0x1ff here, so eg_out stays >= 0x1ff and
	// the output remains 0.
	for (Slot& sl : slot) {
		sl.eg_out = uint16_t(sl.eg_rout + (sl.reg_tl << 2)
		                     + (sl.eg_ksl >> KSLSHIFT[sl.reg_ksl])
		                     + (sl.trem ? tremolo : 0));
		uint32_t n = noise;
		uint8_t n_bit = ((n >> 14) ^ n) & 0x01;
		noise = (n >> 1) | (n_bit << 22);
	}
	advanceState();
}

void YMF262::generateOne(std::span<int16_t, 4> pins)
{
	bool idle = checkIdle();
	// The fast path additionally requires that the *previous* sample was idle:
	// only then are mixBuff / chLeftOut / chRightOut / prevChanRight already
	// flushed to 0 (the chip pipeline spans two samples), so all four pins are 0.
	if (idle && prevSampleIdle) {
		pins[0] = pins[1] = pins[2] = pins[3] = 0;
		fastSilentAdvance();
		++fastPathSamples;
	} else if (rhy & 0x20) {
		generateSample<true>(pins);
	} else {
		generateSample<false>(pins);
	}
	prevSampleIdle = idle;
}

bool YMF262::fastSilentBlock(unsigned num)
{
	// Whole-call fast path: if the chip is confirmed idle AND the previous
	// generated sample was idle (so mixBuff / chLeftOut / chRightOut /
	// prevChanRight are already 0), every sample of this call is silent, so the
	// caller can null all channel buffers.
	if ((rhy & 0x20) || !prevSampleIdle || !checkIdle()) return false;
	for (unsigned j = 0; j < num; ++j) fastSilentAdvance();
	fastPathSamples += num;
	// prevSampleIdle stays true; chLeftOut/chRightOut/prevChanRight stay 0.
	return true;
}

void YMF262::generateChannels(std::span<float*, 18> bufs, unsigned num)
{
	// Silent-chip fast path: when the chip is provably idle for the whole call,
	// advance the internal state cheaply and signal silence to the mixer by
	// nulling the buffers (as allowed by the YMF262Core contract).
	if (fastSilentBlock(num)) {
		std::ranges::fill(bufs, nullptr);
		return;
	}
	for (unsigned j = 0; j < num; ++j) {
		std::array<int16_t, 4> pins; // DAC pins, only needed for state timing
		generateOne(pins);
		for (unsigned i = 0; i < 18; ++i) {
			// left  = this sample's cha contribution
			// right = previous sample's chb contribution (one-sample delay,
			//         matching the chip's right-channel DAC delay)
			bufs[i][2 * j + 0] += float(chLeftOut[i]);
			bufs[i][2 * j + 1] += float(prevChanRight[i]);
			prevChanRight[i] = chRightOut[i];
		}
	}
}

float YMF262::getAmplificationFactor() const
{
	// See YMF262OriginalNukeYKT: matches the Burczynski core's loudness.
	return 1.0f / 4096.0f;
}

void YMF262::reset()
{
	for (auto& s : slot)    s = Slot{};
	for (auto& c : channel) c = Channel{};

	chLeftOut = {};
	chRightOut = {};
	prevChanRight = {};
	mixBuff = {};

	eg_timer = 0;
	noise = 1;
	timer = 0;
	eg_timerrem = 0;
	eg_state = 0;
	eg_add = 0;
	eg_timer_lo = 0;
	newm = 0;
	nts = 0;
	rhy = 0;
	vibpos = 0;
	vibshift = 1;
	tremolo = 0;
	tremolopos = 0;
	tremoloshift = 4;
	rm_hh_bit2 = rm_hh_bit3 = rm_hh_bit7 = rm_hh_bit8 = 0;
	rm_tc_bit3 = rm_tc_bit5 = 0;

	idleConfirmed = false;
	prevSampleIdle = false;
	fastPathSamples = 0;

	for (uint8_t c = 0; c < 18; ++c) channelSetupAlg(c);

	regs = {};
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

template<typename Archive>
void YMF262::Slot::serialize(Archive& ar, unsigned /*version*/)
{
	ar.serialize("out",          out,
	             "fbmod",        fbmod,
	             "prout",        prout,
	             "eg_rout",      eg_rout,
	             "eg_out",       eg_out,
	             "eg_inc",       eg_inc,
	             "eg_gen",       eg_gen,
	             "eg_ksl",       eg_ksl,
	             "reg_vib",      reg_vib,
	             "reg_type",     reg_type,
	             "reg_ksr",      reg_ksr,
	             "reg_mult",     reg_mult,
	             "reg_ksl",      reg_ksl,
	             "reg_tl",       reg_tl,
	             "reg_ar",       reg_ar,
	             "reg_dr",       reg_dr,
	             "reg_sl",       reg_sl,
	             "reg_rr",       reg_rr,
	             "reg_wf",       reg_wf,
	             "key",          key,
	             "pg_reset",     pg_reset,
	             "pg_phase",     pg_phase,
	             "pg_phase_out", pg_phase_out,
	             "modSrc",       modSrc,
	             "modSlot",      modSlot,
	             "trem",         trem);
}

template<typename Archive>
void YMF262::Channel::serialize(Archive& ar, unsigned /*version*/)
{
	ar.serialize("out",    out,
	             "chType", chType,
	             "f_num",  f_num,
	             "block",  block,
	             "fb",     fb,
	             "con",    con,
	             "alg",    alg,
	             "ksv",    ksv,
	             "cha",    cha,
	             "chb",    chb,
	             "chc",    chc,
	             "chd",    chd);
}

template<typename Archive>
void YMF262::serialize(Archive& ar, unsigned /*version*/)
{
	ar.serialize("slots",         slot,
	             "channels",      channel,
	             "prevChanRight", prevChanRight,
	             "mixBuff",       mixBuff,
	             "eg_timer",      eg_timer,
	             "noise",         noise,
	             "timer",         timer,
	             "eg_timerrem",   eg_timerrem,
	             "eg_state",      eg_state,
	             "eg_add",        eg_add,
	             "eg_timer_lo",   eg_timer_lo,
	             "newm",          newm,
	             "nts",           nts,
	             "rhy",           rhy,
	             "vibpos",        vibpos,
	             "vibshift",      vibshift,
	             "tremolo",       tremolo,
	             "tremolopos",    tremolopos,
	             "tremoloshift",  tremoloshift,
	             "rm_hh_bit2",    rm_hh_bit2,
	             "rm_hh_bit3",    rm_hh_bit3,
	             "rm_hh_bit7",    rm_hh_bit7,
	             "rm_hh_bit8",    rm_hh_bit8,
	             "rm_tc_bit3",    rm_tc_bit3,
	             "rm_tc_bit5",    rm_tc_bit5);
	ar.serialize_blob("registers", regs);

	if constexpr (Archive::IS_LOADER) {
		// The idle-detection cache is not serialized: a stale
		// 'idleConfirmed' from before the load could wrongly send the
		// loaded (possibly active) state down the fast path. Force a
		// re-scan and a pipeline-flush sample.
		idleConfirmed = false;
		prevSampleIdle = false;
	}
}

} // namespace YMF262NukeYKT

using YMF262NukeYKT::YMF262;
INSTANTIATE_SERIALIZE_METHODS(YMF262);
REGISTER_POLYMORPHIC_INITIALIZER(YMF262Core, YMF262, "YMF262-NukeYKT");

} // namespace openmsx
