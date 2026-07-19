/*
 * YMF262 (OPL3) - thin wrapper around a selectable synthesis core.
 *
 * This class used to contain the full (Jarek-Burczynski based) OPL3 synthesis.
 * That synthesis has been moved to a separate 'YMF262Core' implementation
 * (see YMF262Burczynski.cc), so that alternative cores (e.g. a cycle-accurate
 * NukeYKT based one) can be plugged in. This mirrors the existing YM2413 /
 * YM2413Core setup.
 *
 * This wrapper keeps the chip-package concerns that are not part of the pure
 * sound synthesis:
 *  - the two timers,
 *  - the interrupt / status register logic,
 *  - the YMF278/OPL4 NEW2 status signaling,
 *  - the YMF278/OPL4 mix-level handling,
 *  - the OPL2/OPL3 register-bank gating on the register-write port.
 */

#include "YMF262.hh"

#include "YMF262Burczynski.hh"
#include "YMF262Core.hh"
#include "YMF262NukeYKT.hh"
#include "YMF262OriginalNukeYKT.hh"

#include "DeviceConfig.hh"
#include "MSXException.hh"
#include "MSXMotherBoard.hh"
#include "serialize.hh"

#include "outer.hh"

#include <array>
#include <cassert>
#include <cmath>
#include <memory>

namespace openmsx {

static std::unique_ptr<YMF262Core> createCore(const DeviceConfig& config)
{
	auto core = config.getChildData("ymf262-core", "");
	if (core.empty() || (core == "Burczynski")) {
		return std::make_unique<YMF262Burczynski::YMF262>();
	} else if (core == "NukeYKT") {
		return std::make_unique<YMF262NukeYKT::YMF262>();
	} else if (core == "Original-NukeYKT") {
		return std::make_unique<YMF262OriginalNukeYKT::YMF262>(); // for debug
	}
	throw MSXException("Unknown YMF262 core '", core,
	                   "'. Must be 'Burczynski', 'NukeYKT' or 'Original-NukeYKT'.");
}

void YMF262::callback(uint8_t flag)
{
	setStatus(flag);
}

// status set and IRQ handling
void YMF262::setStatus(uint8_t flag)
{
	// set status flag masking out disabled IRQs
	status |= flag;
	if (status & statusMask) {
		status |= 0x80;
		irq.set();
	}
}

// status reset and IRQ handling
void YMF262::resetStatus(uint8_t flag)
{
	// reset status flag
	status &= ~flag;
	if (!(status & statusMask)) {
		status &= 0x7F;
		irq.reset();
	}
}

// IRQ mask set
void YMF262::changeStatusMask(uint8_t flag)
{
	statusMask = flag;
	status &= statusMask;
	if (status) {
		status |= 0x80;
		irq.set();
	} else {
		status &= 0x7F;
		irq.reset();
	}
}

bool YMF262::getOPL3Mode() const
{
	// The OPL3-mode bit lives in the core's register file (register 0x105
	// bit 0). It's kept in sync there by the core (see YMF262Core::writeReg).
	return (core->peekReg(0x105) & 0x01) != 0;
}

uint8_t YMF262::readReg(unsigned r) const
{
	// no need to call updateStream(time)
	return peekReg(r);
}

uint8_t YMF262::peekReg(unsigned r) const
{
	return core->peekReg(r);
}

void YMF262::writeReg(unsigned r, uint8_t v, EmuTime time)
{
	if (!getOPL3Mode() && (r != 0x105)) {
		// in OPL2 mode the only accessible in set #2 is register 0x05
		r &= ~0x100;
	}
	writeReg512(r, v, time);
}
void YMF262::writeReg512(unsigned r, uint8_t v, EmuTime time)
{
	updateStream(time); // TODO optimize only for regs that directly influence sound
	writeRegDirect(r, v, time);
}
void YMF262::writeRegDirect(unsigned r, uint8_t v, EmuTime time)
{
	// Handle the chip-package registers (timers, status/IRQ and the NEW2
	// signaling). The value is also stored in the core's register file (and
	// all sound-relevant handling is done) by the core->writeReg() call
	// below. These registers themselves have no sound-synthesis effect.
	switch (r) {
	case 0x002: // Timer 1
		timer1->setValue(v);
		break;

	case 0x003: // Timer 2
		timer2->setValue(v);
		break;

	case 0x004: // IRQ clear / mask and Timer enable
		if (v & 0x80) {
			// IRQ flags clear
			resetStatus(0x60);
		} else {
			changeStatusMask((~v) & 0x60);
			timer1->setStart((v & R04_ST1) != 0, time);
			timer2->setStart((v & R04_ST2) != 0, time);
		}
		break;

	case 0x105:
		// Verified on real YMF278: When NEW2 bit is first set, a read
		// from the status register (once) returns bit 1 set (0x02).
		// This only happens once after reset, so clearing NEW2 and
		// setting it again doesn't cause another change in the status
		// register. Also, only bit 1 changes.
		if ((v & 0x02) && !alreadySignaledNEW2 && isYMF278) {
			status2 = 0x02;
			alreadySignaledNEW2 = true;
		}
		break;

	default:
		break;
	}

	core->writeReg(r, v);
}


void YMF262::reset(EmuTime time)
{
	// Reset the synthesis core. This also clears the register file, including
	// the timer registers 0x02/0x03/0x04 (but without any timer side effect,
	// those are handled here in the wrapper).
	core->reset();

	// Reset the chip-package state. This mirrors the timer/status side effects
	// that the original monolithic YMF262::reset() produced (via
	// resetStatus(0x60) and the register writes to 0x02/0x03/0x04). The order
	// is chosen so that resetStatus(0x60) still comes before
	// changeStatusMask(0x60), exactly as before.
	alreadySignaledNEW2 = false;
	resetStatus(0x60);
	timer1->setValue(0);          // reg 0x02 = 0
	timer2->setValue(0);          // reg 0x03 = 0
	changeStatusMask(0x60);       // reg 0x04 = 0 (v & 0x80 == 0 path)
	timer1->setStart(false, time);
	timer2->setStart(false, time);

	setMixLevel(0x1b, time); // -9dB left and right
}

static unsigned calcInputRate(bool isYMF278)
{
	return unsigned(lrintf(isYMF278 ?    33868800.0f / (19 * 36)
	                                : 4 * 3579545.0f / ( 8 * 36)));
}
YMF262::YMF262(const std::string& name_,
               const DeviceConfig& config, bool isYMF278_)
	: ResampledSoundDevice(config.getMotherBoard(), name_, "MoonSound FM-part",
	                       18, calcInputRate(isYMF278_), true)
	, core(createCore(config))
	, debuggable(config.getMotherBoard(), getName())
	, timer1(isYMF278_
	         ? EmuTimer::createOPL4_1(config.getScheduler(), *this)
	         : EmuTimer::createOPL3_1(config.getScheduler(), *this))
	, timer2(isYMF278_
	         ? EmuTimer::createOPL4_2(config.getScheduler(), *this)
	         : EmuTimer::createOPL3_2(config.getScheduler(), *this))
	, irq(config.getMotherBoard(), getName() + ".IRQ")
	, isYMF278(isYMF278_)
{
	registerSound(config);
	reset(config.getMotherBoard().getCurrentTime()); // must come after registerSound() because of call to setSoftwareVolume() via setMixLevel()
}

YMF262::~YMF262()
{
	unregisterSound();
}

uint8_t YMF262::readStatus()
{
	// no need to call updateStream(time)
	uint8_t result = status | status2;
	status2 = 0;
	return result;
}

uint8_t YMF262::peekStatus() const
{
	return status | status2;
}

void YMF262::setMixLevel(uint8_t x, EmuTime time)
{
	// Only present on YMF278
	// see mix_level[] and vol_factor() in YMF278.cc
	static constexpr std::array<float, 8> level = {
		(1.00f / 1), //   0dB
		(0.75f / 1), //  -3dB (approx)
		(1.00f / 2), //  -6dB
		(0.75f / 2), //  -9dB (approx)
		(1.00f / 4), // -12dB
		(0.75f / 4), // -15dB (approx)
		(1.00f / 8), // -18dB
		 0.00f       // -inf dB
	};
	setSoftwareVolume(level[x & 7], level[(x >> 3) & 7], time);
}

void YMF262::setOutputRate(unsigned hostSampleRate, double speed)
{
	ResampledSoundDevice::setOutputRate(hostSampleRate, speed);
	core->setSpeed(speed);
}

float YMF262::getAmplificationFactorImpl() const
{
	return core->getAmplificationFactor();
}

void YMF262::generateChannels(std::span<float*> bufs, unsigned num)
{
	assert(bufs.size() == 18);
	core->generateChannels(bufs.first<18>(), num);
}


// version 1: initial version
// version 2: added alreadySignaledNEW2
// version 3: split off the synthesis core (polymorphic 'core'); the wrapper now
//            only serializes its own (timer / status / NEW2) state. Older
//            savestates are loaded via the legacy path below.
template<typename Archive>
void YMF262::serialize(Archive& a, unsigned version)
{
	if (a.versionAtLeast(version, 3)) {
		// current format
		a.serialize("timer1",              *timer1,
		            "timer2",              *timer2,
		            "irq",                 irq,
		            "status",              status,
		            "status2",             status2,
		            "statusMask",          statusMask,
		            "alreadySignaledNEW2", alreadySignaledNEW2);
		a.serializePolymorphic("core", *core);
	} else {
		// legacy format (version < 3): the whole (former monolithic) YMF262
		// state was serialized flat. Such savestates predate the multi-core
		// support, so the instantiated core must be the (default) Burczynski
		// core. Guard with a dynamic_cast to be sure.
		assert(Archive::IS_LOADER);
		auto* burc = dynamic_cast<YMF262Burczynski::YMF262*>(core.get());
		if (!burc) {
			throw MSXException(
				"Can't load an old (pre-version-3) YMF262 savestate "
				"with a non-default YMF262 core. Please use the "
				"default (Burczynski) core.");
		}
		a.serialize("timer1", *timer1,
		            "timer2", *timer2,
		            "irq",    irq);
		// The synthesis fields (chanout, registers, channels, ...) follow at
		// this same element level; delegate them to the core.
		burc->serializeLegacy(a, version);
		a.serialize("status",     status,
		            "status2",    status2,
		            "statusMask", statusMask);
		if (a.versionAtLeast(version, 2)) {
			a.serialize("alreadySignaledNEW2", alreadySignaledNEW2);
		} else {
			alreadySignaledNEW2 = true; // we can't know the actual value,
			                            // but 'true' is the safest value
		}
	}
}

INSTANTIATE_SERIALIZE_METHODS(YMF262);


// YMF262::Debuggable

YMF262::Debuggable::Debuggable(MSXMotherBoard& motherBoard_,
                               const std::string& name_)
	: SimpleDebuggable(motherBoard_, name_ + " regs",
	                   "MoonSound FM-part registers", 0x200)
{
}

uint8_t YMF262::Debuggable::read(unsigned address)
{
	const auto& ymf262 = OUTER(YMF262, debuggable);
	return ymf262.peekReg(address);
}

void YMF262::Debuggable::write(unsigned address, uint8_t value, EmuTime time)
{
	auto& ymf262 = OUTER(YMF262, debuggable);
	ymf262.writeReg512(address, value, time);
}

} // namespace openmsx
