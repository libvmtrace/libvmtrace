#include "sys/Altp2m.hpp"

status_t Altp2m::Init()
{
	if(GetSystemMonitor().GetBPMType() != DRAKVUF)
	{
		GetSystemMonitor().Stop();
		throw runtime_error("Not match BPM type");

		return VMI_FAILURE;
	}

	//already handled by system monitor
	return VMI_SUCCESS;
}

static event_response_t BP_CB(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
	Altp2m* altp2m = (Altp2m*)info->trap->data;
	altp2m->ProcessBreakpointEvent(drakvuf, info);

	return 0;
}

status_t Altp2m::InsertBreakpoint(const BreakpointEvent* ev) 
{
	addr_t addr = ev->GetAddr();
	_BPEvents.RegisterEvent(addr, ev);

#ifdef VMTRACE_DEBUG
	cout << "adding BP @" << hex << addr << dec << endl;
#endif

	if (_BPEvents.GetCount(addr) == 1) 
	{
		drakvuf_trap_t* trap = (drakvuf_trap_t*)malloc(sizeof(drakvuf_trap_t));
		trap->breakpoint.lookup_type = LOOKUP_NONE;
		trap->breakpoint.pid = 0;
		trap->breakpoint.addr_type = ADDR_PA;
		trap->breakpoint.addr = addr;
		trap->breakpoint.module = "linux";
		trap->name = ev->GetName().c_str();
		trap->type = BREAKPOINT;
		trap->cb = BP_CB;
		trap->data = this;
		_bp_traps.insert(std::pair<uint64_t, drakvuf_trap_t*>(addr, trap));
		drakvuf_add_trap(GetSystemMonitor().GetDrakvuf(), trap);
	}

	return VMI_SUCCESS;
}

status_t Altp2m::RemoveBreakpoint(const BreakpointEvent* ev) 
{
	addr_t addr = ev->GetAddr();

	_BPEvents.DeRegisterEvent(addr, ev); 
	if (_BPEvents.GetCount(addr) == 0) 
	{
		auto it = _bp_traps.find(addr);
		if (it != _bp_traps.end()) 
		{
			drakvuf_remove_trap(GetSystemMonitor().GetDrakvuf(), it->second, NULL);
		}	
	}

	return VMI_SUCCESS;
}

void Altp2m::ProcessBreakpointEvent(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
	addr_t paddr = info->trap_pa;
	struct BPEventData bpd = {0};

	bpd.beforeSingleStep = info->before_single_step;
	if(!info->before_single_step)
	{
		bpd.ripAfterSingleStep = info->rip_after_single_step;
	}
	bpd.vcpu = info->vcpu;
	bpd.pid = info->proc_data.pid;
	bpd.proc_name = info->proc_data.name == NULL ? "" : string(info->proc_data.name);

	memcpy(&bpd.regs, info->regs, sizeof(x86_registers_t));
	_BPEvents.Call(paddr, &bpd);
	if (_BPEvents.GetCount(paddr) == 0)
	{
		auto it = _bp_traps.find(paddr);
		if (it != _bp_traps.end())
		{
			drakvuf_remove_trap(GetSystemMonitor().GetDrakvuf(), it->second, NULL);
			_bp_traps.erase(it);
		}
	}
}

void Altp2m::DeInit()
{
	drakvuf_interrupt(GetSystemMonitor().GetDrakvuf(), 1);
}

status_t Altp2m::TemporaryRemoveBreakpoint(const BreakpointEvent* ev)
{
	return VMI_SUCCESS;
}

status_t Altp2m::ReInsertBreakpoint(const BreakpointEvent* ev)
{
	return VMI_SUCCESS;
}