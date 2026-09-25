#ifndef YMF262_HH
#define YMF262_HH

#include "ResampledSoundDevice.hh"

#include "EmuTimer.hh"

#include "EmuTime.hh"
#include "IRQHelper.hh"
#include "SimpleDebuggable.hh"
#include "serialize_meta.hh"

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace openmsx {

class DeviceConfig;
class YMF262Core;

// Thin wrapper around a (selectable) YMF262 (OPL3) synthesis core. This class
// is the SoundDevice; it owns the chip-package concerns (the two timers, the
// IRQ/status logic, the NEW2 status signaling and the YMF278/OPL4 mix-level
// handling) and delegates the actual sound synthesis to a YMF262Core.
class YMF262 final : private ResampledSoundDevice, private EmuTimerCallback
{
public:
	YMF262(const std::string& name, const DeviceConfig& config,
	       bool isYMF278);
	~YMF262();

	void reset(EmuTime time);
	void writeReg   (unsigned r, uint8_t v, EmuTime time);
	void writeReg512(unsigned r, uint8_t v, EmuTime time);
	[[nodiscard]] uint8_t readReg(unsigned reg) const;
	[[nodiscard]] uint8_t peekReg(unsigned reg) const;
	[[nodiscard]] uint8_t readStatus();
	[[nodiscard]] uint8_t peekStatus() const;

	void setMixLevel(uint8_t x, EmuTime time);

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

private:
	// SoundDevice
	void setOutputRate(unsigned hostSampleRate, double speed) override;
	[[nodiscard]] float getAmplificationFactorImpl() const override;
	void generateChannels(std::span<float*> bufs, unsigned num) override;

	// EmuTimerCallback
	void callback(uint8_t flag) override;

	void writeRegDirect(unsigned r, uint8_t v, EmuTime time);
	[[nodiscard]] bool getOPL3Mode() const;
	void setStatus(uint8_t flag);
	void resetStatus(uint8_t flag);
	void changeStatusMask(uint8_t flag);

private:
	const std::unique_ptr<YMF262Core> core;

	struct Debuggable final : SimpleDebuggable {
		Debuggable(MSXMotherBoard& motherBoard, const std::string& name);
		[[nodiscard]] uint8_t read(unsigned address) override;
		void write(unsigned address, uint8_t value, EmuTime time) override;
	} debuggable;

	// Bitmask for register 0x04
	static constexpr int R04_ST1       = 0x01; // Timer1 Start
	static constexpr int R04_ST2       = 0x02; // Timer2 Start
	static constexpr int R04_MASK_T2   = 0x20; // Mask Timer2 flag
	static constexpr int R04_MASK_T1   = 0x40; // Mask Timer1 flag
	static constexpr int R04_IRQ_RESET = 0x80; // IRQ RESET

	// Bitmask for status register
	static constexpr int STATUS_T2      = R04_MASK_T2;
	static constexpr int STATUS_T1      = R04_MASK_T1;

	// Timers (see EmuTimer class for details about timing)
	const std::unique_ptr<EmuTimer> timer1; //  80.8us OPL4  ( 80.5us OPL3)
	const std::unique_ptr<EmuTimer> timer2; // 323.1us OPL4  (321.8us OPL3)

	IRQHelper irq;

	uint8_t status{0};		// status flag
	uint8_t status2{0};
	uint8_t statusMask{0};		// status mask

	bool alreadySignaledNEW2{false};
	const bool isYMF278;		// true iff this is actually a YMF278
					// ATM only used for NEW2 bit
};
SERIALIZE_CLASS_VERSION(YMF262, 3);

} // namespace openmsx

#endif
