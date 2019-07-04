#ifndef __REGISTER_MECHANISM_H_
#define __REGISTER_MECHANISM_H_

#include "sys/Event.hpp"
#include "sys/SystemMonitor.hpp"

class RegisterMechanism
{
	public:
		RegisterMechanism(SystemMonitor& sm):_sm(sm), _initialized(false)
		{
			if(!sm.IsEventSupported())
			{
				throw std::runtime_error("Event not supported");
			}
		}
		status_t Init();
		void DeInit();
		status_t InsertRegisterEvent(const ProcessChangeEvent* ev);
		status_t RemoveRegisterEvent(const ProcessChangeEvent* ev);

		void ProcessRegisterEvent(vmi_event_t* ev);
		
		SystemMonitor& GetSystemMonitor()
		{
			return _sm;
		}
	private:
		SystemMonitor& _sm;

		vmi_event_t _register_event;

		EventManager<uint64_t, const RegEvent*> _RegEvents;

		bool _initialized;
};

#endif