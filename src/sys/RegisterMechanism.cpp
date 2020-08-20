
#include <sys/RegisterMechanism.hpp>
#include <util/LockGuard.hpp>

namespace libvmtrace
{
	using namespace util;
	using namespace std::chrono_literals;

	RegisterMechanism::RegisterMechanism(std::shared_ptr<SystemMonitor> sm) : sm(sm)
	{
		if (!sm->IsEventSupported())
			throw std::runtime_error("Event not supported");

		LockGuard guard(sm);

		SETUP_REG_EVENT(&register_event, CR3, VMI_REGACCESS_W, false, HandleRegisterEvent);
		register_event.data = this;
		vmi_register_event(guard.get(), &register_event);
	}

	RegisterMechanism::~RegisterMechanism()
	{
		// make sure all rings have been processed.
		vmi_instance_t vmi;
		for (;;)
		{
			{
				vmi = sm->Lock();
				if (!vmi_are_events_pending(vmi))
					break;
				sm->Unlock();
			}
			std::this_thread::sleep_for(1ms);
		}

		vmi_clear_event(vmi, &register_event, nullptr);
		sm->Unlock();
	}

	void RegisterMechanism::InsertRegisterEvent(const ProcessChangeEvent* ev)
	{
		reg_events.RegisterEvent(ev->ev.reg_event.reg, ev);
	}

	void RegisterMechanism::RemoveRegisterEvent(const ProcessChangeEvent* ev)
	{
		reg_events.DeRegisterEvent(ev->ev.reg_event.reg, ev);
	}

	event_response_t RegisterMechanism::HandleRegisterEvent(vmi_instance_t vmi, vmi_event_t *event)
	{
		const auto instance = (RegisterMechanism*) event->data;

		LockGuard guard(instance->sm);
		instance->reg_events.Call(event->reg_event.reg, event);

		return 0;
	}
}

