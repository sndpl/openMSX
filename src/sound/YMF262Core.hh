#ifndef YMF262CORE_HH
#define YMF262CORE_HH

#include <cstdint>
#include <span>

namespace openmsx {

/** Abstract interface for the YMF262 (OPL3) core.
 *
 * We currently have three concrete implementations:
 *  - YMF262Burczynski: the original openMSX core (default)
 *  - YMF262NukeYKT: C++ port of the die-shot-accurate Nuked-OPL3 core
 *  - YMF262OriginalNukeYKT: wrapper around the unmodified Nuked-OPL3 C code,
 *    only useful for debugging/validation
 *
 * This interface separates the actual YMF262 sound synthesis from the rest of
 * the chip emulation (the timers, the interrupt/status logic, the NEW2 status
 * signaling and the mix-level handling that is specific to the YMF278/OPL4).
 * All of that lives in the 'YMF262' wrapper class (which is a SoundDevice).
 * This split allows to more easily share this implementation between different
 * emulators and to test the synthesis in isolation. It also mirrors the
 * existing YM2413 / YM2413Core setup.
 *
 * There are two main functions in this interface: write to registers and get
 * output samples. All timing information is implicit in the order of the calls
 * to these functions (e.g. write some register, generate 10 output samples,
 * write another register, ...).
 */
class YMF262Core
{
public:
	virtual ~YMF262Core() = default;

	/** Reset this YMF262 core.
	 * This only resets the sound-synthesis related state (registers,
	 * channels, operators, LFO, ...). The timer/status/IRQ state is not part
	 * of this core, it is handled by the 'YMF262' wrapper class.
	 */
	virtual void reset() = 0;

	/** Write to a YMF262 register.
	 * @param reg The register number. This is a 9-bit value [0..511], the
	 *            registers in the second bank have an offset of 0x100.
	 * @param value The value to write.
	 *
	 * The OPL2/OPL3 register-bank gating (in OPL2-mode the second bank is not
	 * accessible except for register 0x105) is applied by the caller (see
	 * YMF262::writeReg()). So this method receives the already resolved 9-bit
	 * register number.
	 *
	 * The core stores the value in its internal register file and updates the
	 * relevant synthesis state. The core uses the OPL3-mode bit (register
	 * 0x105 bit 0) for its internal 4-operator / waveform-select / panning
	 * gating.
	 *
	 * The timer and status registers (0x02, 0x03, 0x04) and the NEW2 side
	 * effect of register 0x105 are chip-package concerns: they are handled by
	 * the wrapper. The core does store these registers in its register file
	 * (so they can be read back), but it takes no timer/status action.
	 */
	virtual void writeReg(unsigned reg, uint8_t value) = 0;

	/** Read from a YMF262 register (for debug and for the status/NEW2 logic).
	 * Note that the real YMF262 chip doesn't allow reading back most
	 * registers. This returns the last written value (or the default value if
	 * this register hasn't been written to since the last reset()).
	 * Reading registers has no influence on the generated sound.
	 */
	[[nodiscard]] virtual uint8_t peekReg(unsigned reg) const = 0;

	/** Generate the sound output.
	 * @param bufs Pointers to the 18 output buffers (one per channel).
	 * @param num The number of required output samples.
	 *
	 * The YMF262 is a stereo device: each output buffer holds interleaved
	 * left/right samples, so each buffer must be big enough to hold 2*num
	 * floats.
	 *
	 * Like the YM2413Core interface, the output is added to the existing data
	 * in the buffers (so zero them first). When a channel is silent the core
	 * assigns nullptr to the corresponding buffer pointer (leaving the buffer
	 * content unchanged) so subsequent processing can be skipped.
	 */
	virtual void generateChannels(std::span<float*, 18> bufs, unsigned num) = 0;

	/** Returns normalization factor.
	 * The output of generateChannels() should still be amplified (multiplied)
	 * with this factor to get a consistent volume level across the different
	 * implementations of the YMF262 core.
	 */
	[[nodiscard]] virtual float getAmplificationFactor() const = 0;

	/** Sets real-time speed factor (aka the openMSX 'speed' setting).
	 * The default implementation does nothing. A core with a cycle-based
	 * write pipeline (like YM2413NukeYKT has) would need this; the current
	 * YMF262 cores apply writes immediately and don't.
	 */
	virtual void setSpeed(double /*speed*/) {}

protected:
	YMF262Core() = default;
};

} // namespace openmsx

#endif
