// $Id$

#ifndef __JOYSTICK_HH__
#define __JOYSTICK_HH__

#include "JoystickDevice.hh"
#include "EventDistributor.hh"
#include <SDL/SDL.h>


class Joystick : public JoystickDevice, EventListener
{
	public:
		Joystick(int joyNum);
		virtual ~Joystick();

		//JoystickDevice
		byte read();
		void write(byte value);

		//EventListener
		void signalEvent(SDL_Event &event);

	private:
		static const int JOY_UP      = 0x01;
		static const int JOY_DOWN    = 0x02;
		static const int JOY_LEFT    = 0x04;
		static const int JOY_RIGHT   = 0x08;
		static const int JOY_BUTTONA = 0x10;
		static const int JOY_BUTTONB = 0x20;
		static const int THRESHOLD = 32768/10;

		int joyNum;
		SDL_Joystick* joystick;
		byte status;
};
#endif
