#ifndef DEYONETNETWORKCARTRIDGE_HH
#define DEYONETNETWORKCARTRIDGE_HH

#include "MSXCPU.hh"
#include "MSXDevice.hh"
#include "Rom.hh"
#include "W5100.hh"

namespace openmsx {

class DeyonetNetworkCartridge final : public MSXDevice
{
public:
	explicit DeyonetNetworkCartridge(DeviceConfig& config);
	~DeyonetNetworkCartridge() override;

	void reset(EmuTime time) override;

	[[nodiscard]] byte readMem(uint16_t address, EmuTime time) override;
	[[nodiscard]] byte peekMem(uint16_t address, EmuTime time) const override;
	void writeMem(uint16_t address, byte value, EmuTime time) override;

	[[nodiscard]] const byte* getReadCacheLine(uint16_t start) const override;
	[[nodiscard]] byte* getWriteCacheLine(uint16_t start) override;

	[[nodiscard]] byte readIO(uint16_t port, EmuTime time) override;
	[[nodiscard]] byte peekIO(uint16_t port, EmuTime time) const override;
	void writeIO(uint16_t port, byte value, EmuTime time) override;

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

private:
	[[nodiscard]] unsigned getRomBankOffset() const;
	[[nodiscard]] unsigned getRomAddressMask() const;
	[[nodiscard]] byte readRom(uint16_t address) const;
	[[nodiscard]] bool isW5100Segment1(uint16_t address) const;
	void patchRestslotp2();

private:
	Rom rom;
	W5100 w5100;
	byte mappingControl = 0;
	byte ledStatus = 0;
	bool mappingActive = false;
	bool exxActive = false;
	bool exafActive = false;
	bool w5100WindowActive = false;
	bool savedIFF1 = true;
	bool savedIFF2 = true;
	unsigned romBankCount = 1;
	unsigned romVisibleSize = 0x8000;
};

} // namespace openmsx

#endif
