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

/** Minimum distance (in VDP cycles) until the next VRAM access.
  *
  * D0/D1 are internal helpers, D16 and D28 are used for CPU accesses (V99x8
  * resp. TMS99x8). All the others are used by the command engine, where the
  * value is 'command engine work' + 'request arbitration latency'. The work is
  * a multiple of 8 (the command engine runs at 1/8 of the VDP clock), the
  * latency is 14. Note that the original measurements could only determine
  * these values modulo 8, see
  * doc/internal/vdp-vram-timing/issue-2057-analysis.md.
  *
  * D30_NI ('not immediate') behaves like a 30 cycle delay, except that the
  * access slot immediately following the current one can only be used when
  * it's at least 38 (= 30 + one command engine tick) cycles away. Only LMMM
  * needs this, and only there can the difference be observed. */
enum class Delta : int {
	D0     =  0 * TICKS,
	D1     =  1 * TICKS,
	D16    =  2 * TICKS,
	D22    =  3 * TICKS,
	D28    =  4 * TICKS,
	D30_NI =  5 * TICKS,
	D38    =  6 * TICKS,
	D46    =  7 * TICKS,
	D62    =  8 * TICKS,
	D70    =  9 * TICKS,
	D86    = 10 * TICKS,
	D102   = 11 * TICKS,
	D118   = 12 * TICKS,
	D126   = 13 * TICKS,
	D134   = 14 * TICKS,
};
static constexpr int NUM_DELTAS = 15;

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
