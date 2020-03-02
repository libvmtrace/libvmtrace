
#include <sys/RegisterMechanism.hpp>

namespace libvmtrace
{
	static event_response_t REG_CB(vmi_instance_t vmi, vmi_event_t *event)
	{
		RegisterMechanism* rm = (RegisterMechanism*)event->data; 

		rm->ProcessRegisterEvent(event);

		return 0;
	}

	void RegisterMechanism::ProcessRegisterEvent(vmi_event_t* ev)
	{
		_sm.Lock();

		_RegEvents.Call(ev->reg_event.reg, ev);
		
		_sm.Unlock();
	}

	status_t RegisterMechanism::Init()
	{
		if(GetSystemMonitor().IsInitialized())
		{
			vmi_instance_t vmi = GetSystemMonitor().Lock();

			memset(&_register_event, 0, sizeof(vmi_event_t));
			_register_event.version = VMI_EVENTS_VERSION;
			_register_event.type = VMI_EVENT_REGISTER;
			_register_event.reg_event.reg = CR3;
			_register_event.reg_event.in_access = VMI_REGACCESS_W;
			_register_event.data = this;
			_register_event.callback = REG_CB;
			vmi_register_event(vmi, &_register_event);

			GetSystemMonitor().Unlock();

			_initialized = true;

			return VMI_SUCCESS;
		}
		else
		{
			throw runtime_error("System Monitor is not yet initialized");
		
		return VMI_FAILURE;
		}
		

		return VMI_FAILURE;
	}

	void RegisterMechanism::DeInit()
	{
		if(_initialized)
		{
			vmi_instance_t vmi = GetSystemMonitor().Lock();

			vmi_clear_event(vmi, &_register_event, NULL);
			_initialized = false;

			GetSystemMonitor().Unlock();
		}
	}

	status_t RegisterMechanism::InsertRegisterEvent(const ProcessChangeEvent* ev)
	{
		_RegEvents.RegisterEvent(ev->ev.reg_event.reg, ev);
		if(!_initialized)
		{
			Init();
		}

		return VMI_FAILURE;
	}

	status_t RegisterMechanism::RemoveRegisterEvent(const ProcessChangeEvent* ev)
	{
		_RegEvents.DeRegisterEvent(ev->ev.reg_event.reg, ev);
		if (_RegEvents.GetCount(ev->ev.reg_event.reg) == 0)
		{
			if(_initialized)
			{
				DeInit();
			}
		}

		return VMI_FAILURE;
	}
}

