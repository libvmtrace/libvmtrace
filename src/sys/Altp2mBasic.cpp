#include "sys/Altp2mBasic.hpp"

static uint8_t int3 = TRAP;

static event_response_t BPSingleStepCB(vmi_instance_t vmi, vmi_event_t* event)
{
	BPEventData* bpd = (BPEventData*)event->data;
	Altp2mBasic* altp2mbasic = dynamic_cast<Altp2mBasic*>(bpd->bpm);

	addr_t rip = 0;
	vmi_get_vcpureg(vmi, &rip, RIP , event->vcpu_id);

	altp2mbasic->ProcessBPSingleStepCB(event, bpd, rip);

	delete bpd;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

void Altp2mBasic::RemoveBreakpointPa(vmi_instance_t vmi, addr_t paddr)
{

#ifdef VMTRACE_DEBUG
	cout << "removing bp @ " << hex << paddr << endl;
#endif

	// All events are deregistered at this BP now. Remove the BP
	for(vector<remmaped_gfn>::iterator it = _remmaped_gfns.begin(); it != _remmaped_gfns.end();)
	{
		//cout << "loop" << endl;
		map<addr_t, addr_t>::iterator it2;
		it2 = (*it).addrs.find(paddr);
		if(it2 != (*it).addrs.end())
		{
			map<addr_t, uint8_t>::iterator it3;
			it3 = _SavedInstructions.find(it2->first);

			uint8_t instr = it3->second;

			size_t written = 0;
			if (vmi_write_pa (vmi, it2->second, 1, &instr, &written) == VMI_FAILURE && written != 1)
			{
				throw runtime_error("Could not write BP");
			}

			_SavedInstructions.erase(it3);
			(*it).addrs.erase(it2);
		}

		if((*it).addrs.size() == 0)
		{
			vmi_slat_change_gfn(vmi, _view_x, (*it).original, ~0);
			vmi_slat_change_gfn(vmi, _view_r, (*it).remapped, ~0);

			_xen->DestroyPage(&((*it).remapped));

#ifdef VMTRACE_DEBUG
	cout << "destroying page @ " << hex << (*it).remapped << " orig @ " << (*it).original << endl;
#endif

			it = _remmaped_gfns.erase(it);
		}
		else
		{
			++it;
		}
	}
}

void Altp2mBasic::ProcessBPSingleStepCB(vmi_event_t* event, BPEventData* bpd, addr_t rip)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();

	addr_t paddr;
	reg_t rip_pa;

	paddr = bpd->paddr;
	vmi_pagetable_lookup(vmi, bpd->regs.cr3 , rip, &rip_pa);

#ifdef VMTRACE_DEBUG
	cout << "ProcessBPSingleStepCB @ " << hex << paddr << endl;
#endif

	if(!GetSystemMonitor().IsExcludeAddress(rip_pa))
	{
		bpd->beforeSingleStep = false;
		bpd->ripAfterSingleStep = rip;

		if(_BPEvents.GetCount(paddr) != 0)
			_BPEvents.Call(paddr, bpd);
	}

	if (_BPEvents.GetCount(paddr) == 0)
	{
		RemoveBreakpointPa(vmi, paddr);
	}

#ifdef VMTRACE_DEBUG
	cout << "\tswitch to view " << dec << _view_x << endl;
#endif

	event->slat_id = _view_x;
	_step_events[event->vcpu_id].callback = BPSingleStepCB;
	_step_events[event->vcpu_id].data = (void*) this;

	GetSystemMonitor().Unlock();
}

static event_response_t MEMSingleStepCB(vmi_instance_t vmi, vmi_event_t* event)
{
	// cout << "MEMSingleStepCB slat : " << event->slat_id << endl;
	Altp2mBasic* altp2mbasic = (Altp2mBasic*)event->data;
	altp2mbasic->ProcessMEMSingleStepCB(event);

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

void Altp2mBasic::ProcessMEMSingleStepCB(vmi_event_t* event)
{
	event->slat_id = _view_x;
	_step_events[event->vcpu_id].callback = BPSingleStepCB;
	_step_events[event->vcpu_id].data = (void*) this;
}

static event_response_t MEM_CB(vmi_instance_t vmi, vmi_event_t* event)
{
	Altp2mBasic* altp2mbasic = (Altp2mBasic*)event->data;

	return altp2mbasic->ProcessMemoryEvent(event);
}

static event_response_t BP_CB(vmi_instance_t vmi, vmi_event_t* event)
{
	Altp2mBasic* altp2mbasic = (Altp2mBasic*)event->data;

	return altp2mbasic->ProcessBreakpointEvent(event);
}

event_response_t Altp2mBasic::ProcessBreakpointEvent(vmi_event_t* event)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();

	addr_t paddr = 0;
	vmi_pagetable_lookup(vmi, event->x86_regs->cr3, event->interrupt_event.gla, &paddr);

	struct BPEventData* bpd = new struct BPEventData();
	bpd->vcpu = event->vcpu_id;
	bpd->bpm = this;
	memcpy(&bpd->regs,event->x86_regs, sizeof(x86_registers_t));
	bpd->paddr = paddr;

#ifdef VMTRACE_DEBUG
	cout << "ProcessBreakpointEvent @ " << hex << paddr << endl;
#endif

	event->interrupt_event.reinject = 0;
	if(_BPEvents.GetCount(paddr) == 0)
	{
		event->interrupt_event.reinject = 1;
	}
	else
	{
		bpd->beforeSingleStep = true;
		_BPEvents.Call(paddr, bpd);
	}

#ifdef VMTRACE_DEBUG
	cout << "\tswitch to view 0" << endl;
#endif

	event->slat_id = 0;

	_step_events[event->vcpu_id].callback = BPSingleStepCB;
	_step_events[event->vcpu_id].data = (void*) bpd;

	GetSystemMonitor().Unlock();

	return 0 | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

event_response_t Altp2mBasic::ProcessMemoryEvent(vmi_event_t* event)
{
	addr_t gfn = event->mem_event.gfn;

	if(gfn == _zero_page_gfn)
	{
#ifdef VMTRACE_DEBUG
		cout << "somebody try to read / write to the empty page" << endl;
#endif
		return VMI_EVENT_RESPONSE_EMULATE_NOWRITE;
	}

	vector<remmaped_gfn>::iterator it = find_if(_remmaped_gfns.begin(), _remmaped_gfns.end(), boost::bind(&remmaped_gfn::remapped, _1) == gfn);
	if (it != _remmaped_gfns.end())
	{
		event->slat_id = _view_r;
		_step_events[event->vcpu_id].callback = MEMSingleStepCB;
		_step_events[event->vcpu_id].data = (void*) this;

#ifdef VMTRACE_DEBUG
		cout << "somebody try to read / write to the shadow copy page" << endl;
#endif

		return VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
	}

	event->slat_id = _view_r;
	_step_events[event->vcpu_id].callback = MEMSingleStepCB;
	_step_events[event->vcpu_id].data = (void*) this;

	return 0 | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

status_t Altp2mBasic::Init()
{
	if(GetSystemMonitor().GetBPMType() != ALTP2M)
	{
		GetSystemMonitor().Stop();
		throw runtime_error("Not match BPM type");
		return VMI_FAILURE;
	}

	if(!GetSystemMonitor().IsInitialized())
	{
		throw runtime_error("System Monitor is not yet initialized");
		return VMI_FAILURE;
	}

	vmi_instance_t vmi = GetSystemMonitor().Lock();

	_xen = new Xen(vmi_get_vmid(vmi));

	_init_memsize = _xen->GetMaxMem();

	_xen->GetMaxGFN(&_max_gpfn);
	_xen->SetMaxMem(~0);

	_zero_page_gfn = ++_max_gpfn;

	_xen->CreateNewPage(&_zero_page_gfn);

#ifdef VMTRACE_DEBUG
	cout << "zero page gfn : " << hex << _zero_page_gfn << endl;
#endif

	uint8_t fmask[VMI_PS_4KB] = {0xFF};
	fill_n(fmask, VMI_PS_4KB, 0xFF);
	if (VMI_FAILURE == vmi_write_pa(vmi, _zero_page_gfn<<12, VMI_PS_4KB, &fmask, NULL))
	{
		throw runtime_error("Failed to mask zero page with FF");
		return VMI_FAILURE;
	}

	int rc = 0;

	rc = vmi_slat_set_domain_state(vmi, 1);
	if (rc < 0)
	{
		throw runtime_error("Failed to change domain state");
		return VMI_FAILURE;
	}

	if(vmi_slat_create(vmi, &_view_x) == VMI_FAILURE)
	{
		throw runtime_error("Failed to create view X");
		return VMI_FAILURE;
	}

	if(vmi_slat_create(vmi, &_view_r) == VMI_FAILURE)
	{
		throw runtime_error("Failed to create view R");
		return VMI_FAILURE;
	}

	SETUP_INTERRUPT_EVENT(&_interrupt_event, BP_CB);
	_interrupt_event.data = this;
	vmi_register_event(vmi, &_interrupt_event);

	SETUP_MEM_EVENT(&_mem_event, ~0ULL, VMI_MEMACCESS_RW, MEM_CB, 1);
	_mem_event.data = this;
	vmi_register_event(vmi, &_mem_event);

	for (int i = 0; i < 16; i++)
	{
		memset(&_step_events[i], 0, sizeof(vmi_event_t));
		SETUP_SINGLESTEP_EVENT(&_step_events[i], 1u << i, BPSingleStepCB, 0);
		_step_events[i].data = (void*)this;
		vmi_register_event(vmi, &_step_events[i]);
	}

	vmi_slat_switch(vmi, _view_x);
	vmi_set_mem_event(vmi, _zero_page_gfn, VMI_MEMACCESS_RW, _view_x);

	GetSystemMonitor().Unlock();

	return VMI_SUCCESS;
}

void Altp2mBasic::DeInit()
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();

	for(vector<remmaped_gfn>::iterator it = _remmaped_gfns.begin(); it != _remmaped_gfns.end(); ++it)
	{
		vmi_slat_change_gfn(vmi, _view_x, (*it).original, ~0);
		vmi_slat_change_gfn(vmi, _view_r, (*it).remapped, ~0);

#ifdef VMTRACE_DEBUG
	cout << "destroying page @ " << hex << (*it).remapped << " orig @ " << (*it).original << endl;
#endif

		_xen->DestroyPage(&((*it).remapped));
	}

	_xen->DestroyPage(&_zero_page_gfn);

	vmi_slat_switch(vmi, 0);

	vmi_clear_event(vmi, &_interrupt_event, NULL);
	vmi_clear_event(vmi, &_mem_event, NULL);

	vmi_slat_destroy(vmi, _view_r);
	vmi_slat_destroy(vmi, _view_x);
	vmi_slat_set_domain_state(vmi, 0);

	_xen->SetMaxMem(_init_memsize);

	cout << "Counter : " << dec << GetCounter() << endl;

	delete _xen;

	GetSystemMonitor().Unlock();	
}

status_t Altp2mBasic::InsertBreakpoint(const BreakpointEvent* ev)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	status_t success = VMI_SUCCESS;

	uint8_t instr;
	addr_t addr = ev->GetAddr();
	addr_t current_gfn = addr >> 12;

#ifdef VMTRACE_DEBUG
	cout << "adding BP @" << hex << addr << " for : " << ev->GetName() << endl;
#endif

	_BPEvents.RegisterEvent(addr, ev);
	if (_BPEvents.GetCount(addr) == 1) 
	{
		if (vmi_read_8_pa (vmi, addr, &instr))
		{
		success = VMI_FAILURE;
		throw runtime_error("Could not read instruction");
		}

		_SavedInstructions.insert(pair<addr_t, uint8_t>(addr, instr));

		vector<remmaped_gfn>::iterator it = find_if(_remmaped_gfns.begin(), _remmaped_gfns.end(), boost::bind(&remmaped_gfn::original, _1) == current_gfn);
		if (it != _remmaped_gfns.end())
		{
			addr_t remapped_gfn = (*it).remapped;

			addr_t remmaped_addr = (remapped_gfn << 12) + (addr & VMI_BIT_MASK(0, 11));
			if(vmi_write_8_pa(vmi, remmaped_addr, &int3) == VMI_FAILURE)
			{
				throw runtime_error("Could not write BP");
			}

			IncreaseCounter();

			(*it).addrs.insert(pair<addr_t, addr_t>(addr, remmaped_addr));

#ifdef VMTRACE_DEBUG
			cout << "\texist : " << hex << "current gfn " << current_gfn << " remapped gfn " << remapped_gfn << " remmaped_addr " << remmaped_addr << endl;
#endif
		}
		else
		{
			addr_t remapped_gfn = ++_max_gpfn;
			_xen->CreateNewPage(&remapped_gfn);

			uint8_t backup[VMI_PS_4KB] = {0};
			vmi_read_pa(vmi, current_gfn << 12, VMI_PS_4KB, &backup, NULL);
			vmi_write_pa(vmi, remapped_gfn << 12, VMI_PS_4KB, &backup, NULL);

			remmaped_gfn rg;
			rg.original = current_gfn;
			rg.remapped = remapped_gfn;

			vmi_slat_change_gfn(vmi, _view_x, current_gfn, remapped_gfn);
			vmi_slat_change_gfn(vmi, _view_r, remapped_gfn, _zero_page_gfn);

			vmi_set_mem_event(vmi, current_gfn, VMI_MEMACCESS_RW, _view_x);
			vmi_set_mem_event(vmi, remapped_gfn, VMI_MEMACCESS_RW, _view_x);

			addr_t remmaped_addr = (remapped_gfn<<12) + (addr & VMI_BIT_MASK(0,11));
			if(vmi_write_8_pa(vmi, remmaped_addr, &int3) == VMI_FAILURE)
			{
				throw runtime_error("Could not write BP");
			}

			rg.addrs.insert(pair<addr_t, addr_t>(addr, remmaped_addr));
			_remmaped_gfns.push_back(rg);

			IncreaseCounter();

#ifdef VMTRACE_DEBUG
			cout << "\tnew : " << hex << "current gfn " << current_gfn << " remapped gfn " << remapped_gfn << " remmaped_addr " << remmaped_addr << endl;
#endif
		}
	}

	GetSystemMonitor().Unlock();
	return success;
}

status_t Altp2mBasic::RemoveBreakpoint(const BreakpointEvent* ev)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	status_t success = VMI_SUCCESS;

	addr_t addr = ev->GetAddr();

	_BPEvents.DeRegisterEvent(addr, ev);

	RemoveBreakpointPa(vmi, addr);

	DecreaseCounter();

	GetSystemMonitor().Unlock();

	return success;
}

status_t Altp2mBasic::TemporaryRemoveBreakpoint(const BreakpointEvent* ev)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	status_t success = VMI_SUCCESS;

	addr_t addr = ev->GetAddr();

	for(vector<remmaped_gfn>::iterator it = _remmaped_gfns.begin(); it != _remmaped_gfns.end(); ++it)
	{
		//cout << "loop" << endl;
		map<addr_t, addr_t>::iterator it2;
		it2 = (*it).addrs.find(addr);
		if(it2 != (*it).addrs.end())
		{
			vmi_slat_change_gfn(vmi, _view_x, (*it).original, ~0);
			vmi_slat_change_gfn(vmi, _view_r, (*it).remapped, ~0);
			break;
			// size_t written = 0;
			// if (vmi_write_pa (vmi, it2->second, 1, &int3, &written) == VMI_SUCCESS && written == 1)
			// {
			// 	break;			
			// }
		}
	}

	GetSystemMonitor().Unlock();

	return success;
}

status_t Altp2mBasic::ReInsertBreakpoint(const BreakpointEvent* ev)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();

	addr_t addr = ev->GetAddr();

	// cout << "reinject" << hex << addr << endl;

	for(vector<remmaped_gfn>::iterator it = _remmaped_gfns.begin(); it != _remmaped_gfns.end(); ++it)
	{
		//cout << "loop" << endl;
		map<addr_t, addr_t>::iterator it2;
		it2 = (*it).addrs.find(addr);
		if(it2 != (*it).addrs.end())
		{
			vmi_slat_change_gfn(vmi, _view_x, (*it).original, (*it).remapped);
			vmi_slat_change_gfn(vmi, _view_r, (*it).remapped, _zero_page_gfn);
			break;
			// size_t written = 0;
			// if (vmi_write_pa (vmi, it2->second, 1, &int3, &written) == VMI_SUCCESS && written == 1)
			// {
			// 	break;			
			// }
		}
	}

	GetSystemMonitor().Unlock();
	return VMI_SUCCESS;
}