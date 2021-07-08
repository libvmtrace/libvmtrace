
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

	void RegisterMechanism::InsertRegisterEvent(const ProcessChangeEvent* ev)
	{
		reg_events.push_back(ev);
		SetRegisterEvent(true);
	}

	bool RegisterMechanism::RemoveRegisterEvent(const ProcessChangeEvent* ev)
	{
		if (reg_events.size() == 1 && reg_events[0] == ev)
		{
			if (!SetRegisterEvent(false))
				return false;

			reg_events.clear();
		}
		else
			reg_events.erase(std::remove(reg_events.begin(), reg_events.end(), ev), reg_events.end());
		return true;
	}

	void RegisterMechanism::AttemptRemoveRegisterEvent(const ProcessChangeEvent* ev)
	{
		if (std::find(to_remove.begin(), to_remove.end(), ev) == to_remove.end())
			to_remove.push_back(ev);
	}

	void RegisterMechanism::FinalizeEvents()
	{
		for (auto it = to_remove.begin(); it != to_remove.end();)
			if (RemoveRegisterEvent(reinterpret_cast<const ProcessChangeEvent*>(*it)))
				it = to_remove.erase(it);
			else
				++it;
	}

	bool RegisterMechanism::SetRegisterEvent(const bool value)
	{
		LockGuard guard(sm);

		if (!!register_event.data == value)
			return true;

		if (vmi_pause_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to pause VM.");

		if (vmi_are_events_pending(guard.get()) != 0)
			return false;

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

		return true;
	}

	event_response_t RegisterMechanism::HandleRegisterEvent(vmi_instance_t vmi, vmi_event_t* event)
	{
		const auto instance = (RegisterMechanism*) event->data;
		LockGuard guard(instance->sm);
		event->reg_event.value &= ~0x1FFF;
		for (auto it = instance->reg_events.begin(); it != instance->reg_events.end(); it++)
		{
			const auto rm = std::find(instance->to_remove.begin(), instance->to_remove.end(), *it) != instance->to_remove.end();
			if (*it && !rm && (*it)->callback(event))
				instance->to_remove.push_back(*it);
		}
		return 0;
	}
}

