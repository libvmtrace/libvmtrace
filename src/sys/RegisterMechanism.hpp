
#ifndef __REGISTER_MECHANISM_H_
#define __REGISTER_MECHANISM_H_

#include <sys/Event.hpp>
#include <sys/SystemMonitor.hpp>

namespace libvmtrace
{
	constexpr auto reg_detach = (1 << 31);

	class RegisterMechanism
	{
		public:
			RegisterMechanism(std::shared_ptr<SystemMonitor> sm);
			~RegisterMechanism();

			void InsertRegisterEvent(ProcessChangeEvent* ev);
			void RemoveRegisterEvent(ProcessChangeEvent* ev);

		private:
			void SetRegisterEvent(const bool value);
			static event_response_t HandleRegisterEvent(vmi_instance_t vmi, vmi_event_t *event);

			std::shared_ptr<SystemMonitor> sm;
			vmi_event_t register_event{};
			std::vector<RegEvent*> reg_events;
	};
}

#endif

