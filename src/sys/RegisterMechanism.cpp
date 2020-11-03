
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

		SETUP_REG_EVENT(&register_event, CR3, VMI_REGACCESS_W, false, HandleRegisterEvent);
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

	void RegisterMechanism::InsertRegisterEvent(ProcessChangeEvent* ev)
	{
		reg_events.push_back(ev);
		SetRegisterEvent(true);
	}

	void RegisterMechanism::RemoveRegisterEvent(ProcessChangeEvent* ev)
	{
		reg_events.erase(std::remove(reg_events.begin(), reg_events.end(), ev), reg_events.end());
		if (reg_events.empty()) SetRegisterEvent(false);
	}

	void RegisterMechanism::SetRegisterEvent(const bool value)
	{
		LockGuard guard(sm);

		if (!!register_event.data == value)
			return;

		if (vmi_pause_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to pause VM.");

		if (value)
		{
			register_event.data = this;
			vmi_register_event(guard.get(), &register_event);
		}
		else
		{
			register_event.data = nullptr;
			vmi_clear_event(guard.get(), &register_event, nullptr);
		}

		if (vmi_resume_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to resume VM.");
	}

	event_response_t RegisterMechanism::HandleRegisterEvent(vmi_instance_t vmi, vmi_event_t* event)
	{
		const auto instance = (RegisterMechanism*) event->data;
		LockGuard guard(instance->sm);
		auto ret = 0u;

		for (auto it = instance->reg_events.begin(); it != instance->reg_events.end();)
			if (*it)
			{
				(*it)->response = ret;
				const auto r = (*it)->callback(event);
				ret = (*it)->response;
				
				if (r)
					it = instance->reg_events.erase(it);
				else
					it++;
			}
			else
				it++;
		
		if (instance->reg_events.empty()) instance->SetRegisterEvent(false);
		return ret;
	}
}

