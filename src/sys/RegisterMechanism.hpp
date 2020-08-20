
#ifndef __REGISTER_MECHANISM_H_
#define __REGISTER_MECHANISM_H_

#include <sys/Event.hpp>
#include <sys/SystemMonitor.hpp>

namespace libvmtrace
{
	class RegisterMechanism
	{
		public:
			RegisterMechanism(std::shared_ptr<SystemMonitor> sm);
			~RegisterMechanism();

			void InsertRegisterEvent(const ProcessChangeEvent* ev);
			void RemoveRegisterEvent(const ProcessChangeEvent* ev);

		private:
			static event_response_t HandleRegisterEvent(vmi_instance_t vmi, vmi_event_t *event);

			std::shared_ptr<SystemMonitor> sm;
			vmi_event_t register_event;
			EventManager<uint64_t, const RegEvent*> reg_events;
	};
}

#endif

