
#include <sys/CodeInjection.hpp>
#include <util/LockGuard.hpp>
#include <libvmi/slat.h>
#include <numeric>

namespace libvmtrace
{
	using namespace util;
	using namespace std::chrono_literals;

	ExtendedInjectionStrategy::ExtendedInjectionStrategy(std::shared_ptr<SystemMonitor> sm) : InjectionStrategy(sm)
	{
		// setup scheduler events.
		if (coordinated)
			return;
		
		cr3_listener = std::make_unique<injection_listener>(
				std::bind(&ExtendedInjectionStrategy::HandleSchedulerEvent, this, std::placeholders::_1, std::placeholders::_2));
		cr3_change = std::make_unique<ProcessChangeEvent>(*cr3_listener);
		sm->GetRM()->InsertRegisterEvent(cr3_change.get());
	}

	void ExtendedInjectionStrategy::Initialize()
	{
		LockGuard guard(sm);
		xen = std::make_shared<Xen>(vmi_get_vmid(guard.get()));
		xc = xc_interface_open(0, 0, 0);
		vmid = vmi_get_vmid(guard.get());

		// enable altp2m support.
		EnableAltp2m();

		// we need to register the memory event even on coordinated injection,
		// because vmi_set_mem_event has a sanity check that prevents us from setting
		// the EPT permissions if there is no suitable handler, however,
		// in the coordinated case, the actual handler is never invoked.
		SETUP_MEM_EVENT(&mem_event, ~0ull, VMI_MEMACCESS_RWX, HandleMemEvent, true);
		mem_event.data = this;
		vmi_register_event(guard.get(), &mem_event);

		// create our sink page.
		xen->GetMaxGFN(&last_page);
		sink_page = AllocatePage();

		// mask the sink page.
		uint8_t mask[PAGE_SIZE];
		memset(mask, 0xFF, sizeof(mask));
		if (vmi_write_pa(guard.get(), page_to_addr(sink_page), sizeof(mask), &mask, nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Failed to mask sink page.");

		// switch domain state.
		if (vmi_slat_set_domain_state(guard.get(), true) != VMI_SUCCESS)
			throw std::runtime_error("Failed to switch domain state.");

		// create read / write view.
		if (vmi_slat_create(guard.get(), &view_rw) != VMI_SUCCESS)
			throw std::runtime_error("Failed to create r/w view.");
		
		// create and hide execute view.
		for (auto i = 0; i < vmi_get_num_vcpus(guard.get()); i++)
		{
			uint16_t view;
			if (vmi_slat_create(guard.get(), &view) != VMI_SUCCESS)
				throw std::runtime_error("Failed to create x view.");
			if (hide && xc_altp2m_set_visibility(xc, vmid, view, false) < 0)
				throw std::runtime_error("Could not hide x view.");
			view_x.push_back(view);
		}
	}

	ExtendedInjectionStrategy::~ExtendedInjectionStrategy()
	{
		// never initialized...
		if (!xen)
			return;

		// make sure all rings have been processed.
		vmi_instance_t vmi;
		decommissioned = true;
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
		if (!coordinated)
			sm->GetRM()->RemoveRegisterEvent(cr3_change.get());
		vmi_clear_event(vmi, &mem_event, nullptr);

		// remove all custom views.
		vmi_slat_switch(vmi, 0);
		vmi_slat_destroy(vmi, view_rw);
		for (auto i = 0; i < vmi_get_num_vcpus(vmi); i++)
			vmi_slat_destroy(vmi, view_x[i]);
		vmi_slat_set_domain_state(vmi, false);

		// free our sink page.
		FreePage(sink_page);

		// close xen access handle.
		xc_interface_close(xc);

		// reset memory.
		xen->SetMaxMem(init_mem);
		sm->Unlock();
	}

	bool ExtendedInjectionStrategy::Apply(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);

		// pause the virtual machine.
		if (vmi_pause_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to pause VM.");

		// lazy initialize.
		if (!xen)
			Initialize();

		// if we are trying to apply a patch to virtual memory,
		// translate it into physical memory first.
		if (patch->pid != 0 && patch->virt != ~0ull)
		{
			addr_t location_pa;
			if (vmi_translate_uv2p(guard.get(), patch->location, patch->pid, &location_pa) != VMI_SUCCESS)
				throw std::runtime_error("Failed to translate patch location.");
			patch->virt = patch->location;
			patch->location = location_pa;
		}

		// synchronize the patch with the monitored virtual machine.
		if (!Synchronize(patch))
		{
			if (vmi_resume_vm(guard.get()) != VMI_SUCCESS)
				throw std::runtime_error("Failed to resume VM.");
			return false;
		}

		// for now every patch must be limited to a single page.
		const auto start_page = addr_to_page(patch->location);
		const auto end_page = addr_to_page(patch->location + patch->data.size());
		if (start_page != end_page)
			throw std::runtime_error("EPT patch cannot modify multiple pages for now.");

		// TODO: we can solve this by dynamically creating a new view for the process / page
		// combination, but for now we just assume there are not different patches in different processes.
		if (patch->virt != ~0ull && std::find_if(patches.begin(), patches.end(),
			[&start_page, &patch](std::shared_ptr<Patch>& p) -> bool
			{ return addr_to_page(p->location) == start_page && p->pid != patch->pid; }) != patches.end())
			throw std::runtime_error("EPT patch cannot modify the same page in two processes.");

		// figure out where to place our patch within the shadow page.
		const auto shadow_page = ReferenceShadowPage(start_page, patch->vcpu, patch->pid);
		const auto offset = translate_page_offset(patch->location, page_to_addr(shadow_page.execute));
	
		// store off original shadow page contents.
		patch->original.resize(patch->data.size());
		if (vmi_read_pa(guard.get(), offset, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
			return false;

		// finally, we can make our changes to our shadow page.
		if (vmi_write_pa(guard.get(), offset, patch->data.size(), patch->data.data(), nullptr) != VMI_SUCCESS)
			return false;

		// resume the virtual machine.
		if (vmi_resume_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to resume VM.");

		return InjectionStrategy::Apply(patch);
	}
	
	void ExtendedInjectionStrategy::NotifyFork(const BPEventData* data)
	{
		LockGuard guard(sm);

		return;
		/*for (auto& patch : patches)
		{
			page_info_t info;
			if (vmi_pagetable_lookup_extended(guard.get(), data->regs.cr3 & ~0x1FFFull,
						patch->location, &info) == VMI_SUCCESS)
			{
				
			std::cout << "FORK 0x" << std::hex << addr_to_page(info.paddr) << std::endl;
			}
			else
				std::cerr << "FAIL!\n";
		}*/
		

		for (auto& shadow_page : shadow_pages)
		{	
		uint8_t buffer[PAGE_SIZE];
		if (vmi_read_pa(guard.get(), page_to_addr(shadow_page.execute), PAGE_SIZE, &buffer, nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Could not read old page contents.");
		if (vmi_write_pa(guard.get(), page_to_addr(shadow_page.read_write), PAGE_SIZE, &buffer, nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Could not write shadow page contents.");
		}
	}
	
	bool ExtendedInjectionStrategy::UndoPatch(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);

		// pause the virtual machine.
		if (vmi_pause_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to pause VM.");

		// synchronize the patch with the monitored virtual machine.
		if (!Synchronize(patch))
		{
			if (vmi_resume_vm(guard.get()) != VMI_SUCCESS)
				throw std::runtime_error("Failed to resume VM.");
			return false;
		}

		const auto shadow_page = UnreferenceShadowPage(addr_to_page(patch->location), patch->vcpu, patch->pid);

		// if the unreferenced shadow page still has references elsewhere, we need to undo our changes.
		if (shadow_page.execute)
		{
			const auto offset = translate_page_offset(patch->location, page_to_addr(shadow_page.execute));

			if (vmi_write_pa(guard.get(), offset, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
				return false;
		}

		// resume the virtual machine.
		if (vmi_resume_vm(guard.get()) != VMI_SUCCESS)
			throw std::runtime_error("Failed to resume VM.");
		
		return InjectionStrategy::UndoPatch(patch);
	}
	
	bool ExtendedInjectionStrategy::HandleSchedulerEvent(Event* ev, void* data)
	{
		const auto event = reinterpret_cast<vmi_event_t* const>(data);
		vmi_pid_t pid;

		if (coordinated)
			return true;

		if (view_x.size() > event->vcpu_id)
			event->slat_id = view_x[event->vcpu_id];
		ev->response |= VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
		return false;
		// disable altp2m on other processes.
		LockGuard guard(sm);
		event->slat_id = 0;

		if (!decommissioned &&
			vmi_dtb_to_pid(guard.get(), event->reg_event.value, &pid) == VMI_SUCCESS)
		{
			auto patch = std::find_if(patches.begin(), patches.end(),
				[&pid](std::shared_ptr<Patch>& p) -> bool { return p->pid == pid; });

			if (patch != patches.end())
				event->slat_id = view_x[event->vcpu_id];
		}
		
		ev->response |= VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
		return false;
	}
	
	event_response_t ExtendedInjectionStrategy::HandleMemEvent(vmi_instance_t vmi, vmi_event_t* event)
	{
		const auto instance = reinterpret_cast<ExtendedInjectionStrategy*>(event->data);

		if (instance->decommissioned)
			return 0;

		if (event->mem_event.gfn == instance->sink_page)
		{
			std::cout << "Someone tried to access the sink page." << std::endl;
			return VMI_EVENT_RESPONSE_EMULATE_NOWRITE;
		}
	
		const auto& target_x = instance->view_x[event->vcpu_id];
		if (event->slat_id == instance->view_rw)
		{
			if (instance->hide && xc_altp2m_set_visibility(instance->xc, instance->vmid, target_x, true) < 0)
				throw std::runtime_error("Could not make x view visible.");
			event->slat_id = target_x;
			return VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
		}
		else if (event->slat_id == target_x)
		{
			if (instance->hide && xc_altp2m_set_visibility(instance->xc, instance->vmid, target_x, false) < 0)
				throw std::runtime_error("Could not hide x view.");
			event->slat_id = instance->view_rw;	
			return VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
		}

		return 0;
	}

	ShadowPage ExtendedInjectionStrategy::ReferenceShadowPage(addr_t page, uint16_t vcpu, vmi_pid_t pid)
	{
		auto shadow_page = std::find_if(shadow_pages.begin(), shadow_pages.end(),
			[&page, &vcpu](ShadowPage& p) -> bool { return p.read_write == page && p.vcpu == vcpu; });
	
		// if the page does not exist yet, we need to create it.
		if (shadow_page == shadow_pages.end())
		{
			LockGuard guard(sm);
			shadow_pages.emplace_back();
			shadow_page = std::prev(shadow_pages.end());

			// make a new empty page to act as a shadow page.
			shadow_page->execute = AllocatePage();
			shadow_page->read_write = page;
			shadow_page->vcpu = vcpu;

			// lookup dtb for the process that we are currently modifying.
			addr_t dtb;
			if (vmi_pid_to_dtb(guard.get(), pid, &dtb) != VMI_SUCCESS)
				throw std::runtime_error("Failed to retrieve DTB for modified process.");

			// copy over page contents to shadow page.
			uint8_t buffer[PAGE_SIZE];
			if (vmi_read_pa(guard.get(), page_to_addr(shadow_page->read_write), PAGE_SIZE, &buffer, nullptr) != VMI_SUCCESS)
				throw std::runtime_error("Could not read old page contents.");
			if (vmi_write_pa(guard.get(), page_to_addr(shadow_page->execute), PAGE_SIZE, &buffer, nullptr) != VMI_SUCCESS)
				throw std::runtime_error("Could not write shadow page contents.");

			// modify each vcpu that is affected by this change.
			const auto set = vcpu == ALL_VCPU ? view_x : std::vector { view_x[vcpu] };
			for (const auto& view : set)
			{
				// remap the pages into respective views.
				if (vmi_slat_change_gfn(guard.get(), view, shadow_page->read_write, shadow_page->execute) != VMI_SUCCESS)
					throw std::runtime_error("Failed to map shadow page into EPT.");

				// activate memory events on both the original and the shadow page.
				if (vmi_set_mem_event(guard.get(), shadow_page->read_write, VMI_MEMACCESS_RW, view) != VMI_SUCCESS
					|| vmi_set_mem_event(guard.get(), shadow_page->execute, VMI_MEMACCESS_RW, view) != VMI_SUCCESS)
					throw std::runtime_error("Failed to enable memory events for x view.");

				// activate fast switching.
				if (coordinated)
				{
					const auto vind = std::distance(view_x.begin(), std::find(view_x.begin(), view_x.end(), view));
					xc_altp2m_add_fast_switch(xc, vmid, vind, dtb, view_rw, view);
				}
			}

			// remap the affected page to sink in r/w view.
			if (vmi_slat_change_gfn(guard.get(), view_rw, shadow_page->execute, sink_page) != VMI_SUCCESS)
				throw std::runtime_error("Failed to map shadow page into EPT.");
			
			// finally, enable events on the r/w view.
			if (vmi_set_mem_event(guard.get(), shadow_page->read_write, VMI_MEMACCESS_X, view_rw) != VMI_SUCCESS
				|| vmi_set_mem_event(guard.get(), shadow_page->execute, VMI_MEMACCESS_X, view_rw) != VMI_SUCCESS)
				throw std::runtime_error("Failed to enable memory events for r/w view.");
		}

		shadow_page->refs++;
		return *shadow_page;
	}
	
	ShadowPage ExtendedInjectionStrategy::UnreferenceShadowPage(addr_t page, uint16_t vcpu, vmi_pid_t pid)
	{
		const auto shadow_page = std::find_if(shadow_pages.begin(), shadow_pages.end(),
			[&page, &vcpu](ShadowPage& p) -> bool { return p.read_write == page && p.vcpu == vcpu; });

		if (shadow_page == shadow_pages.end())
			throw std::runtime_error("Tried to unreference a non-existing shadow page.");

		// did we just lose the last reference to this page?
		if (--shadow_page->refs == 0)
		{
			LockGuard guard(sm);
			
			// lookup dtb for the process that we are currently modifying.
			addr_t dtb;
			if (vmi_pid_to_dtb(guard.get(), pid, &dtb) != VMI_SUCCESS)
				throw std::runtime_error("Failed to retrieve DTB for modified process.");

			// unmap the pages from their respective views.
			const auto set = vcpu == ALL_VCPU ? view_x : std::vector { view_x[vcpu] };
			for (const auto& view : set)
			{
				if (vmi_slat_change_gfn(guard.get(), view, shadow_page->read_write, ~addr_t(0)) != VMI_SUCCESS)
					throw std::runtime_error("Failed to unmap shadow page from EPT.");

				if (coordinated)
				{
					const auto vind = std::distance(view_x.begin(), std::find(view_x.begin(), view_x.end(), view));
					xc_altp2m_remove_fast_switch(xc, vmid, vind, dtb);
				}
			}

			// unmap the sink in r/w view.
			if (vmi_slat_change_gfn(guard.get(), view_rw, shadow_page->execute, ~addr_t(0)) != VMI_SUCCESS)
					throw std::runtime_error("Failed to unmap shadow page from EPT.");

			FreePage(shadow_page->execute);
			shadow_pages.erase(shadow_page);
			return {};
		}

		return *shadow_page;
	}

	bool ExtendedInjectionStrategy::Synchronize(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);

		// no synchronization for kernel threads.
		addr_t dtb;
		if (patch->pid == 0 || vmi_pid_to_dtb(guard.get(), patch->pid, &dtb) != VMI_SUCCESS || !sm->GetBPM())
			return true;

		// build a list of all intersections.
		std::vector<addr_t> intersect;

		// check intersection with all task structs.
		for (const auto& process : sm->GetOS()->GetProcessList())
			if (process.GetDtb() == dtb)
			{
				addr_t location;
				if (vmi_translate_uv2p(guard.get(), process.GetIP(), process.GetPid(), &location) == VMI_SUCCESS
					&& location > patch->location && location <= patch->location + patch->data.size())
					intersect.push_back(location);
			}

		// now check all processors.
		addr_t cmp_dtb;
		vmi_pid_t cmp_pid;
		for (auto i = 0; i < vmi_get_num_vcpus(guard.get()); i++)
		{
			if (vmi_get_vcpureg(guard.get(), &cmp_dtb, CR3, i) != VMI_SUCCESS // should never happen.
				|| vmi_dtb_to_pid(guard.get(), cmp_dtb, &cmp_pid) != VMI_SUCCESS) // missed page-table? try again.
				return false;

			// only check for intersections on *this* process.
			if (cmp_pid != patch->pid)
				continue;

			addr_t location;
			if (vmi_get_vcpureg(guard.get(), &location, RIP, i) == VMI_SUCCESS)
			{
				if (location > patch->location && location <= patch->location + patch->data.size())
					intersect.push_back(location);
			}
			else
				intersect.push_back(0); // make sure we delay, if required.
		}

		// if the patch is not relocatable, e.g., it is a breakpoint, delay.
		if (!patch->relocatable && !intersect.empty())
			return false;

		// finally, relocate it.
		for (const auto& inter : intersect)
			patch->location = std::max(patch->location, inter);
		return true;
	}

	uint64_t ExtendedInjectionStrategy::AllocatePage()
	{
		LockGuard guard(sm);
		
		auto new_page = ++last_page;
		if (xen->CreateNewPage(&new_page) != VMI_SUCCESS)
			throw std::runtime_error("Failed to allocate new page.");
		
		// refresh the cached end of physical memory.
		vmi_get_max_physical_address(guard.get());
		
		return new_page;
	}

	void ExtendedInjectionStrategy::FreePage(uint64_t page)
	{	
		LockGuard guard(sm);
		
		if (xen->DestroyPage(&page) != VMI_SUCCESS)
			throw std::runtime_error("Failed to free page.");
		
		// refresh the cached end of physical memory.
		vmi_get_max_physical_address(guard.get());
	}

	void ExtendedInjectionStrategy::EnableAltp2m()
	{
		LockGuard guard(sm);
		const auto vmi_id = vmi_get_vmid(guard.get());

		// grab current value of ALTP2M.
		uint64_t current_altp2m;
		if (xc_hvm_param_get(xc, vmi_id, HVM_PARAM_ALTP2M, &current_altp2m) < 0)
			throw std::runtime_error("Failed to get HVM_PARAM_ALTP2M.");

		// is ALTP2M not at external mode? turn it on.
		if (current_altp2m != XEN_ALTP2M_external &&
			xc_hvm_param_set(xc, vmi_id, HVM_PARAM_ALTP2M, XEN_ALTP2M_external) < 0)
				throw std::runtime_error("Failed to set HVM_PARAM_ALTP2M.");

		// set default domain state.
		if (xc_altp2m_set_domain_state(xc, vmi_id, 1) < 0)
			throw std::runtime_error("Failed to get altp2m domain state.");

		// make enough room.
		init_mem = xen->GetMaxMem();
		xen->SetMaxMem(~0);
	}
}

