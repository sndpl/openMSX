#ifndef WAVAUDIOINPUT_HH
#define WAVAUDIOINPUT_HH

#include "AudioInputDevice.hh"
#include "FilenameSetting.hh"
#include "WavData.hh"
#include "Observer.hh"
#include "EmuTime.hh"

namespace openmsx {

class CommandController;

class WavAudioInput final : public AudioInputDevice, private Observer<Setting>
{
public:
	explicit WavAudioInput(CommandController& commandController);
	~WavAudioInput() override;

	// AudioInputDevice
	const std::string& getName() const override;
	std::string_view getDescription() const override;
	void plugHelper(Connector& connector, EmuTime::param time) override;
	void unplugHelper(EmuTime::param time) override;
	int16_t readSample(EmuTime::param time) override;

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

private:
	void loadWave();
	void update(const Setting& setting) override;

	FilenameSetting audioInputFilenameSetting;
	WavData wav;
	EmuTime reference;
};

} // namespace openmsx

#endif
