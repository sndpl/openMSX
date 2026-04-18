#include "DeyonetNetworkCartridge.hh"

#include "CacheLine.hh"
#include "CPURegs.hh"
#include "MSXException.hh"
#include "serialize.hh"

#include <cstdio>

#include <algorithm>

namespace openmsx {

static constexpr uint16_t ROM_WINDOW_SIZE = 0x8000;
static constexpr uint16_t W5100_WINDOW_SIZE = 0x4000;
static constexpr uint16_t MAPPING_PORT = 0x28;
static constexpr uint16_t LED_PORT = 0x29;
static constexpr uint16_t CARTRIDGE_BASE = 0x4000;
static constexpr uint16_t PAGE2_BASE = 0x8000;
static constexpr uint16_t PAGE3_BASE = 0xC000;

DeyonetNetworkCartridge::DeyonetNetworkCartridge(DeviceConfig& config)
	: MSXDevice(config)
	, rom(getName() + " ROM", "rom", config)
{
	if (rom.size() == 0) {
		throw MSXException("DenYoNet cartridge requires a ROM image.");
	}

	romVisibleSize = (rom.size() <= 0x4000) ? 0x4000 : ROM_WINDOW_SIZE;
	auto paddedSize = (std::max<size_t>(rom.size(), romVisibleSize) + romVisibleSize - 1) &
	                  ~(romVisibleSize - 1);
	rom.addPadding(paddedSize);
	romBankCount = std::max(1u, unsigned(rom.size() / ROM_WINDOW_SIZE));

	reset(getCurrentTime());
}

DeyonetNetworkCartridge::~DeyonetNetworkCartridge() = default;

void DeyonetNetworkCartridge::reset(EmuTime /*time*/)
{
	mappingControl = 0;
	ledStatus = 0;
	mappingActive = false;
	exxActive = false;
	exafActive = false;
	w5100WindowActive = false;
	savedIFF1 = true;
	savedIFF2 = true;
	w5100.reset();
	invalidateDeviceRWCache();
}

byte DeyonetNetworkCartridge::readMem(uint16_t address, EmuTime /*time*/)
{
	if (address < CARTRIDGE_BASE) {
		return 0xFF;
	}
	if (address < PAGE2_BASE) {
		auto value = readRom(address);
		// Protect EXX (0xD9) and EX AF,AF' (0x08) windows from VDP
		// interrupt corruption. Track each independently and suppress
		// interrupts when either register set is swapped.
		if (value == 0xD9 || value == 0x08) {
			if (getCPU().isM1Cycle(address)) {
				bool wasProtected = exxActive || exafActive;
				if (value == 0xD9) exxActive = !exxActive;
				if (value == 0x08) exafActive = !exafActive;
				bool nowProtected = exxActive || exafActive;
				if (nowProtected && !wasProtected) {
					auto& regs = getCPU().getRegisters();
					savedIFF1 = regs.getIFF1();
					savedIFF2 = regs.getIFF2();
					regs.setIFF1(false);
					regs.setIFF2(false);
				} else if (!nowProtected && wasProtected) {
					auto& regs = getCPU().getRegisters();
					regs.setIFF1(savedIFF1);
					regs.setIFF2(savedIFF2);
				}
			}
		}
		return value;
	}
	return w5100.readMem(isW5100Segment1(address), address & (W5100_WINDOW_SIZE - 1));
}

byte DeyonetNetworkCartridge::peekMem(uint16_t address, EmuTime /*time*/) const
{
	if (address < CARTRIDGE_BASE) {
		return 0xFF;
	}
	if (address < PAGE2_BASE) {
		return readRom(address);
	}
	return w5100.peekMem(isW5100Segment1(address), address & (W5100_WINDOW_SIZE - 1));
}

void DeyonetNetworkCartridge::writeMem(uint16_t address, byte value, EmuTime /*time*/)
{
	if (address < CARTRIDGE_BASE) {
		return;
	}
	if (address < PAGE2_BASE) {
		return;
	}
	if (!mappingActive) {
		return;
	}
	w5100.writeMem(isW5100Segment1(address), address & (W5100_WINDOW_SIZE - 1), value);
}

const byte* DeyonetNetworkCartridge::getReadCacheLine(uint16_t /*start*/) const
{
	// Read cache disabled so readMem runs every fetch (needed for the
	// EXX/EX AF,AF' M1-cycle tracking that suppresses interrupts while
	// the alternate register set is active).
	return nullptr;
}

byte* DeyonetNetworkCartridge::getWriteCacheLine(uint16_t start)
{
	if (start < CARTRIDGE_BASE) {
		return nullptr;
	}
	if (start < PAGE2_BASE) {
		return unmappedWrite.data();
	}
	if (!mappingActive) {
		return unmappedWrite.data();
	}
	return nullptr;
}

byte DeyonetNetworkCartridge::readIO(uint16_t port, EmuTime time)
{
	return peekIO(port, time);
}

byte DeyonetNetworkCartridge::peekIO(uint16_t port, EmuTime /*time*/) const
{
	switch (port & 0xFF) {
	case MAPPING_PORT:
		return mappingControl;
	case LED_PORT:
		return ledStatus;
	default:
		return 0xFF;
	}
}

void DeyonetNetworkCartridge::writeIO(uint16_t port, byte value, EmuTime /*time*/)
{
	switch (port & 0xFF) {
	case MAPPING_PORT: {
		bool hadW5100Window = mappingActive && ((mappingControl & 0x30) != 0);
		if (!mappingActive || mappingControl != value) {
			mappingActive = true;
			mappingControl = value;
			invalidateDeviceRWCache();
		}
		bool hasW5100Window = (mappingControl & 0x30) != 0;
		// Also suppress interrupts while the W5100 memory window is
		// active to protect slot-switching operations that occur
		// between W5100 window enable/disable cycles.
		if (hasW5100Window && !hadW5100Window) {
			auto& regs = getCPU().getRegisters();
			if (!w5100WindowActive && !(exxActive || exafActive)) {
				savedIFF1 = regs.getIFF1();
				savedIFF2 = regs.getIFF2();
			}
			regs.setIFF1(false);
			regs.setIFF2(false);
			w5100WindowActive = true;
		} else if (!hasW5100Window && hadW5100Window) {
			w5100WindowActive = false;
			if (!(exxActive || exafActive)) {
				auto& regs = getCPU().getRegisters();
				regs.setIFF1(savedIFF1);
				regs.setIFF2(savedIFF2);
			}
		}
		break;
	}
	case LED_PORT:
		ledStatus = value;
		break;
	default:
		break;
	}
}

unsigned DeyonetNetworkCartridge::getRomBankOffset() const
{
	auto bank = std::min<unsigned>(mappingControl & 0x0F, romBankCount - 1);
	return bank * romVisibleSize;
}

unsigned DeyonetNetworkCartridge::getRomAddressMask() const
{
	return romVisibleSize - 1;
}

byte DeyonetNetworkCartridge::readRom(uint16_t address) const
{
	return rom[getRomBankOffset() + ((address - CARTRIDGE_BASE) & getRomAddressMask())];
}

bool DeyonetNetworkCartridge::isW5100Segment1(uint16_t address) const
{
	return (address >= PAGE3_BASE) ? ((mappingControl & 0x20) != 0)
	                               : ((mappingControl & 0x10) != 0);
}

void DeyonetNetworkCartridge::patchRestslotp2()
{
}

template<typename Archive>
void DeyonetNetworkCartridge::serialize(Archive& ar, unsigned /*version*/)
{
	ar.template serializeBase<MSXDevice>(*this);
	ar.serialize("w5100", w5100,
	             "mappingControl", mappingControl,
	             "ledStatus", ledStatus,
	             "mappingActive", mappingActive,
	             "romBankCount", romBankCount);
	if constexpr (Archive::IS_LOADER) {
		invalidateDeviceRWCache();
	}
}
INSTANTIATE_SERIALIZE_METHODS(DeyonetNetworkCartridge);
REGISTER_MSXDEVICE(DeyonetNetworkCartridge, "DeyonetNetworkCartridge");

} // namespace openmsx
