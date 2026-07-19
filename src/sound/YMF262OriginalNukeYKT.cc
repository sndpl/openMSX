#include "YMF262OriginalNukeYKT.hh"

#include "narrow.hh"
#include "serialize.hh"
#include "xrange.hh"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

namespace openmsx {
namespace YMF262OriginalNukeYKT {

YMF262::YMF262()
{
	reset();
}

void YMF262::reset()
{
	// Reset the original Nuked-OPL3 core.
	//
	// We pass samplerate == 49716 (the native OPL3 rate, clock/288). With this
	// value the core's internal resampler runs at a 1:1 ratio
	// (rateratio == 1 << RSM_FRAC, see OPL3_Reset()/RSM_FRAC in opl3.cc). We
	// actually use the non-resampled output path in generateChannels() (see
	// there), which is a plain pass-through regardless, but this keeps the
	// value unambiguous. openMSX does its own resampling (ResampledSoundDevice).
	OPL3_Reset(&chip, 49716);

	// Clear our peekReg() mirror (the Nuked core has no raw register file).
	std::ranges::fill(regs, 0);
}

void YMF262::writeReg(unsigned reg, uint8_t value)
{
	assert(reg < 512);

	// Immediate register write. Deliberately NOT OPL3_WriteRegBuffered(): that
	// variant models the chip's own write delay/timing, but openMSX already
	// supplies the timing by interleaving writeReg() and generateChannels()
	// calls. The register-bank gating is done by the wrapper (see
	// YMF262::writeReg()), so 'reg' is the already resolved 9-bit value.
	OPL3_WriteReg(&chip, narrow<uint16_t>(reg), value);

	// Keep our own mirror in sync (only used by peekReg()).
	regs[reg] = value;
}

uint8_t YMF262::peekReg(unsigned reg) const
{
	// The opl3_chip struct doesn't store a plain register file, so return the
	// last written value from our own mirror (see writeReg()).
	assert(reg < 512);
	return regs[reg];
}

void YMF262::generateChannels(std::span<float*, 18> bufs, unsigned num)
{
	// The original Nuked-OPL3 core only produces a single, already-mixed stereo
	// (left/right) output; it cannot break the sound down per channel. So we
	// collapse the whole chip output into channel-buffer 0 and mark all the
	// other channel buffers silent (nullptr).
	//
	// Each channel buffer is stereo-interleaved: it holds 2*num floats, with the
	// left sample at index [2*j+0] and the right sample at [2*j+1]. This matches
	// exactly how the Burczynski core fills its buffers (chanOut masked with the
	// per-channel left/right 'pan' values). The YMF262 SoundDevice is registered
	// as stereo (see the ResampledSoundDevice ctor in YMF262.cc), so the mixer
	// interprets buffer 0 as a stereo channel and sums it into the final output.
	//
	// This stereo-collapse loses the per-channel information (used for
	// per-channel muting / visualisation), but that is acceptable for a
	// debug-only core: the optimized core should generate identical output.
	std::ranges::fill(bufs.subspan(1), nullptr);

	for (auto j : xrange(num)) {
		std::array<int16_t, 2> buf; // [0] = left (DAC output A), [1] = right (B)
		OPL3_Generate(&chip, buf.data()); // non-resampled: one native sample
		// The contract is to *add* into the (pre-zeroed) buffers.
		bufs[0][2 * j + 0] += narrow_cast<float>(buf[0]);
		bufs[0][2 * j + 1] += narrow_cast<float>(buf[1]);
	}
}

float YMF262::getAmplificationFactor() const
{
	// Chosen to match the Burczynski core's loudness. Reasoning about the two
	// cores' output scales:
	//  - Nuked: a single operator's output comes from the exp-table as
	//    (exprom[..] << 1) >> shift, so a full-scale operator maxes out at
	//    ~±4085 (exprom[0] == 0x7fa == 2042, << 1 == 4084).
	//  - Burczynski: a single operator (op_calc() -> tlTab[]) maxes out at
	//    ~±4086, and that core uses getAmplificationFactor() == 1/4096.
	// Both cores therefore share the same per-operator (and hence per-channel)
	// output scale, so the same 1/4096 factor gives a matching volume level.
	// (Unlike Burczynski, the Nuked core sums all 18 channels internally and
	// clips the sum to int16 - that DAC-style clipping is inherent to the Nuked
	// core and is one of the things a debug comparison can reveal.)
	return 1.0f / 4096.0f;
}

template<typename Archive>
void YMF262::serialize(Archive& /*ar*/, unsigned /*version*/)
{
	// Not implemented. Loading a savestate made with this (debug-only) core
	// results in a freshly reset chip; audio state is wrong until software
	// rewrites the registers.
}

} // namespace YMF262OriginalNukeYKT

using YMF262OriginalNukeYKT::YMF262;
INSTANTIATE_SERIALIZE_METHODS(YMF262);
REGISTER_POLYMORPHIC_INITIALIZER(YMF262Core, YMF262, "YMF262-Original-NukeYKT");

} // namespace openmsx
