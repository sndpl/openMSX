/* This is a wrapper around the original (unmodified) Nuked-OPL3 code. This is
 * only useful for debugging because our (future) modified/optimized NukeYKT
 * code should generate identical output.
 */
#ifndef YMF262ORIGINALNUKEYKT_HH
#define YMF262ORIGINALNUKEYKT_HH

#include "YMF262Core.hh"
#include "opl3.hh"

#include <array>
#include <cstdint>
#include <span>

namespace openmsx::YMF262OriginalNukeYKT {

class YMF262 final : public YMF262Core
{
public:
	YMF262();
	void reset() override;
	void writeReg(unsigned reg, uint8_t value) override;
	[[nodiscard]] uint8_t peekReg(unsigned reg) const override;
	void generateChannels(std::span<float*, 18> bufs, unsigned num) override;
	[[nodiscard]] float getAmplificationFactor() const override;
	// setSpeed(): intentionally not overridden. The original Nuked core applies
	//   register writes immediately (there is no cycle pipeline), so it doesn't
	//   need to react to the openMSX 'speed' setting. The base-class no-op is
	//   fine.

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

private:
	// The complete original Nuked-OPL3 chip state, held by value.
	opl3_chip chip;

	// The opl3_chip struct does not keep a plain 512-byte register file, so we
	// maintain our own mirror (updated on every writeReg()) purely to be able
	// to implement peekReg() (used for debugging and for the wrapper's
	// status/NEW2 logic).
	std::array<uint8_t, 512> regs;
};

} // namespace openmsx::YMF262OriginalNukeYKT

#endif
