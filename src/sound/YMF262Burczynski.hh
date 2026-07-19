#ifndef YMF262BURCZYNSKI_HH
#define YMF262BURCZYNSKI_HH

#include "YMF262Core.hh"

#include "FixedPoint.hh"
#include "serialize_meta.hh"

#include <array>
#include <cstdint>
#include <span>

namespace openmsx {
namespace YMF262Burczynski {

// sin-wave entries
inline constexpr int SIN_BITS = 10;
inline constexpr int SIN_LEN  = 1 << SIN_BITS;
inline constexpr int SIN_MASK = SIN_LEN - 1;

/** Jarek-Burczynski based implementation of the YMF262 (OPL3) core.
 *
 * This is the original openMSX YMF262 synthesis code, extracted (almost)
 * unchanged from the (former) monolithic YMF262 class. The timer/status/IRQ,
 * NEW2-signaling and mix-level handling have been moved to the YMF262 wrapper
 * class; this class only contains the actual sound synthesis.
 */
class YMF262 final : public YMF262Core
{
public:
	/** 16.16 fixed point type for frequency calculations */
	using FreqIndex = FixedPoint<16>;

	enum class EnvelopeState : uint8_t {
		ATTACK, DECAY, SUSTAIN, RELEASE, OFF
	};

private:
	class Channel;

	class Slot {
	public:
		Slot();
		[[nodiscard]] int op_calc(unsigned phase, unsigned lfo_am) const;
		void FM_KEYON(uint8_t key_set);
		void FM_KEYOFF(uint8_t key_clr);
		void advanceEnvelopeGenerator(unsigned egCnt);
		void advancePhaseGenerator(const Channel& ch, unsigned lfo_pm);
		void update_ar_dr();
		void update_rr();
		void calc_fc(const Channel& ch);

		/** Sets the amount of feedback [0..7]
		 */
		void setFeedbackShift(uint8_t value) {
			fb_shift = value ? 9 - value : 0;
		}

		template<typename Archive>
		void serialize(Archive& ar, unsigned version);

		// Phase Generator
		FreqIndex Cnt{0};  // frequency counter
		FreqIndex Incr{0}; // frequency counter step
		int* connect{nullptr}; // slot output pointer
		std::array<int, 2> op1_out{0, 0}; // slot1 output for feedback

		// Envelope Generator
		unsigned TL{0};  // total level: TL << 2
		unsigned TLL{0}; // adjusted now TL
		int volume{0};   // envelope counter
		int sl{0};       // sustain level: sl_tab[SL]

		std::span<const unsigned, SIN_LEN> waveTable; // waveform select

		EnvelopeState state{EnvelopeState::OFF}; // EG: phase type
		unsigned eg_m_ar{0};  // (attack state)
		unsigned eg_m_dr{0};  // (decay state)
		unsigned eg_m_rr{0};  // (release state)
		uint8_t eg_sh_ar{0};  // (attack state)
		uint8_t eg_sel_ar{0}; // (attack state)
		uint8_t eg_sh_dr{0};  // (decay state)
		uint8_t eg_sel_dr{0}; // (decay state)
		uint8_t eg_sh_rr{0};  // (release state)
		uint8_t eg_sel_rr{0}; // (release state)

		uint8_t key{0}; // 0 = KEY OFF, >0 = KEY ON

		uint8_t fb_shift{0}; // PG: feedback shift value
		bool CON{false};     // PG: connection (algorithm) type
		bool eg_type{false}; // EG: percussive/non-percussive mode

		// LFO
		uint8_t AMmask{0}; // LFO Amplitude Modulation enable mask
		bool vib{false};   // LFO Phase Modulation enable flag (active high)

		uint8_t ar{0};	// attack rate: AR<<2
		uint8_t dr{0};	// decay rate:  DR<<2
		uint8_t rr{0};	// release rate:RR<<2
		uint8_t KSR{0};	// key scale rate
		uint8_t ksl{0};	// key scale level
		uint8_t ksr{0};	// key scale rate: kcode>>KSR
		uint8_t mul{0};	// multiple: mul_tab[ML]
	};

	class Channel {
	public:
		void chan_calc(unsigned lfo_am);
		void chan_calc_ext(unsigned lfo_am);

		template<typename Archive>
		void serialize(Archive& ar, unsigned version);

		std::array<Slot, 2> slot;

		int block_fnum{0};    // block+fnum
		FreqIndex fc{0};      // Freq. Increment base
		unsigned ksl_base{0}; // KeyScaleLevel Base step
		uint8_t kcode{0};     // key code (for key scaling)

		// there are 12 2-operator channels which can be combined in pairs
		// to form six 4-operator channel, they are:
		//  0 and 3,
		//  1 and 4,
		//  2 and 5,
		//  9 and 12,
		//  10 and 13,
		//  11 and 14
		bool extended{false}; // set if this channel forms up a 4op channel with
		                      // another channel (only used by first of pair of
		                      // channels, ie 0,1,2 and 9,10,11)
	};

public:
	YMF262();

	// YMF262Core
	void reset() override;
	void writeReg(unsigned r, uint8_t v) override;
	[[nodiscard]] uint8_t peekReg(unsigned reg) const override;
	void generateChannels(std::span<float*, 18> bufs, unsigned num) override;
	[[nodiscard]] float getAmplificationFactor() const override;

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

	/** Load the sound-synthesis part of a pre-version-3 (legacy) YMF262
	  * savestate. In those savestates the whole (former monolithic) YMF262
	  * state was serialized flat; the YMF262 wrapper loads its own (timer,
	  * status, ...) fields and delegates the synthesis fields to this method.
	  * This is only ever used while loading (never while saving).
	  */
	template<typename Archive>
	void serializeLegacy(Archive& ar, unsigned version);

private:
	template<typename Archive>
	void serializeState(Archive& ar);

	void advance();

	[[nodiscard]] unsigned genPhaseHighHat();
	[[nodiscard]] unsigned genPhaseSnare();
	[[nodiscard]] unsigned genPhaseCymbal();

	void chan_calc_rhythm(unsigned lfo_am);
	void set_mul(unsigned sl, uint8_t v);
	void set_ksl_tl(unsigned sl, uint8_t v);
	void set_ar_dr(unsigned sl, uint8_t v);
	void set_sl_rr(unsigned sl, uint8_t v);
	[[nodiscard]] bool checkMuteHelper() const;

	[[nodiscard]] bool isExtended(unsigned ch) const;
	[[nodiscard]] Channel& getFirstOfPair(unsigned ch);
	[[nodiscard]] Channel& getSecondOfPair(unsigned ch);

private:
	std::array<int, 18> chanOut = {};      // 18 channels

	std::array<uint8_t, 512> reg = {};
	std::array<Channel, 18> channel;  // OPL3 chips have 18 channels

	std::array<int, 18 * 4> pan; // channels output masks 4 per channel
	                             //    0xffffffff = enable
	unsigned eg_cnt{0};          // global envelope generator counter
	unsigned noise_rng{1};       // 23 bit noise shift register

	// LFO
	using LFOAMIndex = FixedPoint< 6>;
	using LFOPMIndex = FixedPoint<10>;
	LFOAMIndex lfo_am_cnt{0};
	LFOPMIndex lfo_pm_cnt{0};
	bool lfo_am_depth{false};
	uint8_t lfo_pm_depth_range{0};

	uint8_t rhythm{0};		// Rhythm mode
	bool nts{false};			// NTS (note select)
	bool OPL3_mode{false};		// OPL3 extension enable flag
};

} // namespace YMF262Burczynski

SERIALIZE_CLASS_VERSION(YMF262Burczynski::YMF262, 1);

} // namespace openmsx

#endif
