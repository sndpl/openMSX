#ifndef VDPACCESSSLOTS_HH
#define VDPACCESSSLOTS_HH

#include "VDP.hh"

#include "narrow.hh"

#include <cassert>
#include <cstdint>
#include <span>
#include <utility>

namespace openmsx::VDPAccessSlots {

inline constexpr int TICKS = VDP::TICKS_PER_LINE;

/** Minimum distance until the next VRAM access.
  *
  * D0 and D1 are internal helpers, D16 and D28 are the CPU access delays
  * (V99x8 resp. TMS99x8). All the others are command engine steps, and for
  * those the distance is counted in the VDP's memory cycles rather than in VDP
  * cycles; see the comment above CycleTable in VDPAccessSlots.cc. */
enum class Delta : int {
	D0    =  0 * TICKS,
	D1    =  1 * TICKS,
	D16   =  2 * TICKS,
	D28   =  3 * TICKS,
	D24   =  4 * TICKS,
	D32   =  5 * TICKS,
	D38   =  6 * TICKS,
	D48   =  7 * TICKS,
	D60   =  8 * TICKS,
	D72   =  9 * TICKS,
	D84   = 10 * TICKS,
	D88   = 11 * TICKS,
	D104  = 12 * TICKS,
	D120  = 13 * TICKS,
	D128  = 14 * TICKS,
	D132  = 15 * TICKS,
};
static constexpr int NUM_DELTAS = 16;
/** The first command engine step in the 'Delta' enum; everything from here on
  * is subject to the memory-cycle counting. */
static constexpr int FIRST_CMD_DELTA = 4;

/** VDP-VRAM access slot calculator, meant to be used in the inner loops of the
  * VDPCmdEngine commands. Code optimized for the case that:
  *  - timing remains constant (sprites/display enable/disable)
  *  - there are more calls to next() and limitReached() than to getTime()
  */
class Calculator
{
public:
	/** This shouldn't be called directly, instead use getCalculator(). */
	Calculator(EmuTime frame, EmuTime time,
	           EmuTime limit_, std::span<const uint8_t, NUM_DELTAS * TICKS> tab_)
		: ref(frame), tab(tab_)
	{
		assert(frame <= time);
		assert(frame <= limit_);
		// not required that time <= limit

		ticks = narrow<int>(ref.getTicksTill_fast(time));
		limit = narrow<int>(ref.getTicksTill_fast(limit_));
		int lines = ticks / TICKS;
		ticks -= lines * TICKS;
		limit -= lines * TICKS; // might be negative
		ref   += lines * TICKS;
		assert(0 <= ticks); assert(ticks < TICKS);
	}

	/** Has 'time' advanced to or past 'limit'? */
	[[nodiscard]] bool limitReached() const {
		return ticks >= limit;
	}

	/** Get the current time. Initially this will return the 'time'
	  * constructor parameter. Each call to next() will increase this
	  * value. */
	[[nodiscard]] EmuTime getTime() const {
		return ref.getFastAdd(ticks);
	}

	/** Advance time to the earliest access slot that is at least 'delta'
	  * ticks later than the current time. */
	void next(Delta delta) {
		ticks += tab[std::to_underlying(delta) + ticks];
		if (ticks >= TICKS) [[unlikely]] {
			ticks -= TICKS;
			limit -= TICKS;
			ref   += TICKS;
		}
	}

private:
	int ticks;
	int limit;
	VDP::VDPClock ref;
	std::span<const uint8_t, NUM_DELTAS * TICKS> tab;
};

/** Return the time of the next available access slot that is at least 'delta'
  * cycles later than 'time'. The start of the current 'frame' is needed for
  * reference. */
[[nodiscard]] EmuTime getAccessSlot(EmuTime frame, EmuTime time, Delta delta,
                      const VDP& vdp);

/** When many calls to getAccessSlot() are needed, it's more efficient to
  * instead use this function. */
[[nodiscard]] Calculator getCalculator(
	EmuTime frame, EmuTime time, EmuTime limit,
	const VDP& vdp);

} // namespace openmsx::VDPAccessSlots

#endif
