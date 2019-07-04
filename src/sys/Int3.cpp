#include "sys/Int3.hpp"

static uint8_t int3opcode = TRAP;
//static int stop_now = 0;
static int stop_soon = 0;


static event_response_t MemSingleStepCB(vmi_instance_t vmi, vmi_event_t* event)
{
	BPEventData* bpd = (BPEventData*)event->data;
	addr_t paddr = bpd->paddr;

	size_t written = 0;

	if(!stop_soon)
	{
		if(vmi_write_pa(vmi, paddr, 1, &int3opcode, &written) == VMI_FAILURE && written != 1)
			throw runtime_error("Could not reinsert Breakpoint");
	}

	Int3* int3 = (Int3*)bpd->bpm;
	int3->IncreaseCounter();

	delete bpd;

	return 0;
}

static event_response_t MEM_CB(vmi_instance_t vmi, vmi_event_t* event)
{
	Int3* int3 = (Int3*)event->data;
	int3->ProcessMemoryEvent(event);

	return 0 | VMI_EVENT_RESPONSE_EMULATE;
}

void Int3::ProcessMemoryEvent(vmi_event_t* event)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();

	addr_t paddr = (event->mem_event.gfn<<12) + event->mem_event.offset;

	struct BPEventData* bpd = new struct BPEventData();
	bpd->paddr = paddr;
	bpd->bpm = this;

	map<addr_t, uint8_t>::iterator it;
	it = _SavedInstructions.find(paddr);
	size_t written = 0;
	if (vmi_write_pa (vmi, it->first, 1, &it->second, &written) == VMI_FAILURE && written != 1)
		throw runtime_error("Could not write BP");

	DecreaseCounter();

	vmi_event_t* single_step_event = new vmi_event_t;
	memset(single_step_event, 0, sizeof(vmi_event_t));
	single_step_event-> data = (void*) bpd;
	vmi_step_event(vmi, single_step_event, event->vcpu_id, 1, MemSingleStepCB);

	GetSystemMonitor().Unlock();
}

static event_response_t BP_CB(vmi_instance_t vmi, vmi_event_t* event)
{
	Int3* int3 = (Int3*)event->data;
	int3->ProcessBreakpointEvent(event);

	return 0 | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

static event_response_t BPSingleStepCB(vmi_instance_t vmi, vmi_event_t* event)
{
	BPEventData* bpd = static_cast<BPEventData*>(event->data);
	Int3* int3 = dynamic_cast<Int3*>(bpd->bpm);

	addr_t rip = 0;
	vmi_get_vcpureg(vmi, &rip, RIP , event->vcpu_id);
	
	int3->ProcessBPSingleStepCB(bpd, rip);
	
	delete bpd;
	
	return 0 | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

status_t Int3::Init()
{
	if(GetSystemMonitor().GetBPMType() != INTTHREE)
	{
		GetSystemMonitor().Stop();
		throw runtime_error("Not match BPM type");

		return VMI_FAILURE;
	}

	if(GetSystemMonitor().IsInitialized())
	{ 
		vmi_instance_t vmi = GetSystemMonitor().Lock();

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

		GetSystemMonitor().Unlock();

		return VMI_SUCCESS;
	}
	else
	{
		throw runtime_error("System Monitor is not yet initialized");
		
		return VMI_FAILURE;
	}
}

void Int3::ProcessBreakpointEvent(vmi_event_t* event)
{
	struct BPEventData* bpd = new struct BPEventData();
	bpd->vcpu = event->vcpu_id;
	bpd->bpm = this;
	memcpy(&bpd->regs,event->x86_regs, sizeof(x86_registers_t));
	reg_t cr3 = bpd->regs.cr3;
	addr_t paddr = 0;

	vmi_instance_t vmi = GetSystemMonitor().Lock();

	vmi_pagetable_lookup(vmi, cr3, event->interrupt_event.gla, &paddr); 
	bpd->paddr = paddr;

#ifdef VMTRACE_DEBUG
	cout << "process breakpoint event @ " << hex << paddr << endl;
#endif

	event->interrupt_event.reinject = 0;
	if (_BPEvents.GetCount(paddr) == 0)
	{

#ifdef VMTRACE_DEBUG
	cout << "\t\tsomehow the getcount == 0, reinject->1" << endl;
#endif

		event->interrupt_event.reinject = 1;
	}
	else
	{
		bpd->beforeSingleStep = true;
		_BPEvents.Call(paddr, bpd);

		map<addr_t, uint8_t>::iterator it;
		it = _SavedInstructions.find(paddr);
		size_t written = 0;
		if(vmi_write_pa (vmi, it->first, 1, &it->second, &written) == VMI_FAILURE && written != 1)
		{
			throw runtime_error("Could not write BP");
		}
		else
		{
			DecreaseCounter();
		}

		// vmi_event_t* single_step_event = new vmi_event_t;
		// memset(single_step_event, 0, sizeof(vmi_event_t));
		// single_step_event->data = (void*)bpd;
		// vmi_step_event(vmi, single_step_event, event->vcpu_id, 1, BPSingleStepCB);

		_step_events[event->vcpu_id].callback = BPSingleStepCB;
		_step_events[event->vcpu_id].data = (void*) bpd;
	}

	GetSystemMonitor().Unlock();
}

status_t Int3::ProcessBPSingleStepCB(BPEventData* bpd, addr_t rip)
{
	addr_t paddr;
	reg_t rip_pa;

	vmi_instance_t vmi = GetSystemMonitor().Lock();

	paddr = bpd->paddr;

#ifdef VMTRACE_DEBUG
	cout << "process single step event @ " << hex << paddr << endl;
#endif

	vmi_pagetable_lookup(vmi, bpd->regs.cr3 , rip, &rip_pa);

	if(!GetSystemMonitor().IsExcludeAddress(rip_pa))
	{
		bpd->beforeSingleStep = false;
		bpd->ripAfterSingleStep = rip;
		
		if(_BPEvents.GetCount(paddr) != 0 && !stop_soon)
			_BPEvents.Call(paddr, bpd);
	}

	if (_BPEvents.GetCount(paddr) == 0  || stop_soon) 
	{ 

#ifdef VMTRACE_DEBUG
	cout << "\t\tremove the BP" << endl;
#endif

		// All events are deregistered at this BP now. Remove the BP
		map<addr_t, uint8_t>::iterator it;
		it = _SavedInstructions.find(paddr);
		if (it == _SavedInstructions.end())
			throw runtime_error("Could not find old instruction?");
		
		uint8_t instr = it->second;   
		_SavedInstructions.erase(it);
		
		size_t written = 0;
		if (vmi_write_pa (vmi, paddr, 1, &instr, &written) == VMI_FAILURE && written != 1)
			throw runtime_error("Could not write saved BP");

		// DecreaseCounter();
	}
	else
	{
		size_t written = 0;
		if (vmi_write_pa(vmi, paddr, 1, &int3opcode, &written) == VMI_FAILURE && written != 1)
		{
			throw runtime_error("Could not reinsert Breakpoint");
		}
		else
		{
			IncreaseCounter();
		}
	}
	
	GetSystemMonitor().Unlock();
	return VMI_SUCCESS;
}

void Int3::DeInit() 
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();

	cerr << "Preparing to stop: handler will not re-inject BP any more" << endl;
	stop_soon = 1;
	
	cerr << "Removing BP from VM memory (without de-registering)" << endl;


	for (std::map<addr_t, uint8_t>::iterator it=_SavedInstructions.begin(); 
		it != _SavedInstructions.end(); ++it) 
	{

#ifdef VMTRACE_DEBUG
	cout << "deinit: remove BP @ " << hex << it->first << endl;
#endif
	
		size_t written = 0;
		if(vmi_write_pa(vmi, it->first, 1, &it->second, &written) == VMI_FAILURE && written != 1) 
		{
			throw runtime_error("Could not write BP");        
		}
		DecreaseCounter();
	}
	while(true) 
	{
		int n = 0;
		n = vmi_are_events_pending(vmi);
		cerr << "Pending events... (" << n << ")" << endl;
		usleep(100000);
		if ( n == 0 ) {
			break;
		}	
	}

	cout << "Counter : " << dec << GetCounter() << endl;

	vmi_clear_event(vmi, &_interrupt_event, NULL);
	vmi_clear_event(vmi, &_mem_event, NULL);

	GetSystemMonitor().Unlock();
}

status_t Int3::InsertBreakpoint(const BreakpointEvent* ev) 
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	status_t success = VMI_SUCCESS;

	uint8_t instr;
	addr_t addr = ev->GetAddr();

#ifdef VMTRACE_DEBUG
	cout << "adding BP @" << hex << addr << dec << endl;
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
		size_t written = 0;
		if (vmi_write_pa(vmi, addr, 1, &int3opcode, &written) == VMI_FAILURE && written != 1) 
		{
			success = VMI_FAILURE;
			throw runtime_error("Could not write BP");
		}

		addr_t gfn = addr >> 12;

		if (vmi_set_mem_event(vmi, gfn, VMI_MEMACCESS_RW, 0) == VMI_FAILURE)
		{
			success = VMI_FAILURE;
			throw runtime_error("Could not change page permission");
		}

		IncreaseCounter();
	}

	GetSystemMonitor().Unlock();
	return success;
}

status_t Int3::RemoveBreakpoint(const BreakpointEvent* ev) 
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	status_t success = VMI_SUCCESS;

	addr_t addr = ev->GetAddr();
	
	_BPEvents.DeRegisterEvent(addr, ev);

#ifdef VMTRACE_DEBUG
	cout << "removing BP @" << hex << addr << dec << endl;
#endif

	if (_BPEvents.GetCount(addr) == 0) 
	{
		map<addr_t, uint8_t>::iterator it;
		it = _SavedInstructions.find(addr);
		
		if (it == _SavedInstructions.end())
		{ 
			success = VMI_FAILURE;
		}

		uint8_t instr = it->second;
		_SavedInstructions.erase(it);
		size_t written = 0;
		if (vmi_write_pa(vmi, addr, 1, &instr, &written) == VMI_FAILURE && written != 1)
		{
			success = VMI_FAILURE;
			throw runtime_error("Could not write saved BP");
		}

		DecreaseCounter();
	}

	GetSystemMonitor().Unlock();
	return success;
}

status_t Int3::TemporaryRemoveBreakpoint(const BreakpointEvent* ev)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	addr_t addr = ev->GetAddr();
	status_t success = VMI_SUCCESS;

	map<addr_t, uint8_t>::iterator it;
	it = _SavedInstructions.find(addr);

	if (it == _SavedInstructions.end())
	{ 
		success = VMI_FAILURE;
	}

	uint8_t instr = it->second;
	size_t written = 0;
	if (vmi_write_pa(vmi, addr, 1, &instr, &written) == VMI_FAILURE && written != 1)
	{
		success = VMI_FAILURE;
	}

	GetSystemMonitor().Unlock();

	return success;
}

status_t Int3::ReInsertBreakpoint(const BreakpointEvent* ev)
{
	vmi_instance_t vmi = GetSystemMonitor().Lock();
	addr_t addr = ev->GetAddr();
	status_t success = VMI_SUCCESS;

	map<addr_t, uint8_t>::iterator it;
	it = _SavedInstructions.find(addr);

	if (it == _SavedInstructions.end())
	{ 
		success = VMI_FAILURE;
	}
	
	if (stop_soon)
		return success;

	size_t written = 0;
	if (vmi_write_pa(vmi, addr, 1, &int3opcode, &written) == VMI_FAILURE && written != 1)
	{
		success = VMI_FAILURE;
	}

	GetSystemMonitor().Unlock();
	
	return success;
}