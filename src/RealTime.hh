// $Id$

#ifndef __MSXREALTIME_HH__
#define __MSXREALTIME_HH__

#include "Schedulable.hh"
#include "IntegerSetting.hh"
#include "BooleanSetting.hh"
#include "SettingListener.hh"
#include "EmuTime.hh"


namespace openmsx {

class Scheduler;
class MSXConfig;


class RealTime : private Schedulable, private SettingListener
{
public:
	virtual ~RealTime();

	static RealTime& instance();

	/**
	 * Convert EmuTime to RealTime and vice versa
	 */
	float getRealDuration(const EmuTime& time1, const EmuTime& time2);
	EmuDuration getEmuDuration(float realDur);

	/**
	 * Synchronize EmuTime with RealTime, normally this is done
	 * automatically, but some devices have additional information
	 * and can indicate 'good' moments to sync, eg: VDP can call
	 * this method at the end of each frame.
	 */
	float sync(const EmuTime& time);

private:
	Scheduler& scheduler;
	MSXConfig& msxConfig;

protected:
	RealTime(); 
	
	virtual float doSync(const EmuTime& time) = 0;  
	virtual void resync() = 0;

	IntegerSetting speedSetting;
	int maxCatchUpTime;	// max nb of ms overtime
	int maxCatchUpFactor;	// max catch up speed factor (percentage)

private:
	virtual void executeUntil(const EmuTime& time, int userData) throw();
	virtual const string& schedName() const;

	float internalSync(const EmuTime& time);
	
	// SettingListener
	void update(const SettingLeafNode* setting) throw();

	BooleanSetting throttleSetting;
	BooleanSetting& pauseSetting;
	BooleanSetting& powerSetting;
};

} // namespace openmsx

#endif // __MSXREALTIME_HH__
