
#include <sys/BreakpointMechanism.hpp>
#include <util/LockGuard.hpp>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

namespace libvmtrace
{
	using namespace util;
	using namespace std::chrono_literals;

	BreakpointMechanism::BreakpointMechanism(std::shared_ptr<SystemMonitor> sm) : sm(sm)
	{
		LockGuard guard(sm);
		
		if (!sm->IsEventSupported())
			throw std::runtime_error("Event not supported");

		extended = !!dynamic_cast<ExtendedInjectionStrategy*>(sm->GetInjectionStrategy().get());
		
		// setup interrupt event.
		SETUP_INTERRUPT_EVENT(&interrupt_event, HandleInterruptEvent);
		interrupt_event.data = this;
		vmi_register_event(guard.get(), &interrupt_event);
		
		// setup step events.
		for (auto i = 0; i < vmi_get_num_vcpus(guard.get()); i++)
		{
			vmi_event_t step_event;
			SETUP_SINGLESTEP_EVENT(&step_event, 1u << i, HandleStepEvent, false);
			step_event.data = nullptr;
			step_events.push_back(step_event);
			vmi_register_event(guard.get(), &step_events[i]);
		}
	}

	BreakpointMechanism::~BreakpointMechanism()
	{
		// disable breakpoints and reinsertion.
		{
			LockGuard guard(sm);
			Disable();
			for (auto& event : step_events)
				event.data = nullptr;
		}

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
	
		// remove event handler.
		vmi_clear_event(vmi, &interrupt_event, nullptr);
		
		for (auto& event : step_events)
			vmi_clear_event(vmi, &event, nullptr);

		sm->Unlock();
	}

	status_t BreakpointMechanism::InsertBreakpoint(BreakpointEvent* ev)
	{
		LockGuard guard(sm);
		auto addr = ev->GetAddr();
		const auto kernel_space = !!dynamic_cast<const SyscallBreakpoint*>(ev);
		const auto pbp = dynamic_cast<const ProcessBreakpointEvent*>(ev);
		const auto patch = std::make_shared<Patch>(addr, pbp ? pbp->GetPid() : 0, ALL_VCPU, std::vector<uint8_t>{ TRAP }, kernel_space);

		// if the breakpoint is inside a process, translate it here,
		// so that we only use physical addresses for lookup.
		if (pbp && pbp->GetPid() > 0 && !kernel_space &&
				vmi_translate_uv2p(guard.get(), addr, pbp->GetPid(), &addr) != VMI_SUCCESS)
			throw std::runtime_error("Could not translate breakpoint location.");

		if (patch && !sm->GetInjectionStrategy()->Apply(patch))
			throw std::runtime_error("Failed to apply patch!");

		bp.insert_or_assign(addr, breakpoint { patch, ev });
		return VMI_SUCCESS;
	}

	status_t BreakpointMechanism::RemoveBreakpoint(BreakpointEvent* ev)
	{
		LockGuard guard(sm);
		auto addr = ev->GetAddr();
		const auto kernel_space = !!dynamic_cast<const SyscallBreakpoint*>(ev);
		const auto pbp = dynamic_cast<const ProcessBreakpointEvent*>(ev);
		
		// if the breakpoint is inside a process, translate it here,
		// so that we only use physical addresses for lookup.
		if (pbp && pbp->GetPid() > 0 && !kernel_space &&
				vmi_translate_uv2p(guard.get(), addr, pbp->GetPid(), &addr) != VMI_SUCCESS)
			throw std::runtime_error("Could not translate breakpoint location.");
		
		const auto b = bp.find(addr);

		if (b == bp.end())
			throw std::runtime_error("Tried to remove breakpoint that is not attached!");

		if (b->second.patch && !sm->GetInjectionStrategy()->Undo(b->second.patch))
			throw std::runtime_error("Failed to undo patch!");

		b->second = { };
		return VMI_SUCCESS;
	}

	void BreakpointMechanism::Disable()
	{
		disabled = true;

		for (auto& b : bp)
			if (b.second.patch)
				sm->GetInjectionStrategy()->Undo(b.second.patch);
	}
	
	void BreakpointMechanism::Enable()
	{
		for (auto& b : bp)
			if (b.second.patch)
				sm->GetInjectionStrategy()->Apply(b.second.patch);

		disabled = false;
	}

	event_response_t BreakpointMechanism::HandleInterruptEvent(vmi_instance_t vmi, vmi_event_t* event)
	{
		const auto instance = reinterpret_cast<BreakpointMechanism*>(event->data);

		const auto bpd = new BPEventData();
		bpd->bpm = instance;
		bpd->vcpu = event->vcpu_id;
		memcpy(&bpd->regs, event->x86_regs, sizeof(x86_registers_t));
		event->interrupt_event.reinject = true;

		if (vmi_pagetable_lookup(vmi, event->x86_regs->cr3,
					event->interrupt_event.gla, &bpd->paddr) == VMI_SUCCESS)
		{
			const auto b = instance->bp.find(bpd->paddr);
		
			if (b != instance->bp.end())
			{	
				event->interrupt_event.reinject = false;
				
				if (!b->second.patch)
					return 0;

				bpd->bp = &b->second;
				if (b->second.event->callback(bpd))
				{
					instance->sm->GetInjectionStrategy()->Undo(b->second.patch);
					b->second.patch = nullptr;

					delete bpd;
					return 0;
				}
			
				bpd->beforeSingleStep = false;
				instance->step_events[event->vcpu_id].data = reinterpret_cast<void*>(bpd);

				if (instance->extended)
				{
					event->next_slat_id = bpd->slat_id = event->slat_id;
					event->slat_id = 0;
					return VMI_EVENT_RESPONSE_SLAT_ID | ((b->second.event && b->second.event->IsFast()) ?
							VMI_EVENT_RESPONSE_NEXT_SLAT_ID : // here we don't get the step event.
							VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP); // and here we do.
				}

				instance->sm->GetInjectionStrategy()->Undo(b->second.patch);
				return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
			}
		}
		
		return 0;
	}
	
	event_response_t BreakpointMechanism::HandleStepEvent(vmi_instance_t vmi, vmi_event_t* event)
	{
		const auto bpd = reinterpret_cast<BPEventData*>(event->data);
		auto response = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

		if (bpd && bpd->bpm && bpd->bp)
		{
			const auto bpm = bpd->bpm;
			const auto bp = bpd->bp;
			const auto remove = bp->event && bp->event->callback(bpd);

			// in case we ever want to trap to the monitor on the singlestep.
			if (bpm->extended)
			{
				// remove in the respective view now.
				if (remove)
				{
					bpm->sm->GetInjectionStrategy()->Undo(bp->patch);
					bp->patch = nullptr;
				}

				event->slat_id = bpd->slat_id;
				response |= VMI_EVENT_RESPONSE_SLAT_ID;
			}
			else if (!bpm->disabled && bp->patch && !remove)
				bpm->sm->GetInjectionStrategy()->Apply(bp->patch);

			delete bpd;
			event->data = nullptr;
		}

		return response;
	}
}

