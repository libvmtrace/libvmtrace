
#include <sys/CodeInjection.hpp>
#include <util/LockGuard.hpp>

namespace libvmtrace
{
	using namespace util;

	ExtendedInjectionStrategy::ExtendedInjectionStrategy(std::shared_ptr<SystemMonitor> sm) : InjectionStrategy(sm)
	{
		// we need to do a lazy initialize on the first use,
		// because at this point VMI is not ready yet,
		// but we need to create the sink page.
	}

	void ExtendedInjectionStrategy::Initialize()
	{
		LockGuard guard(sm);
		xen = std::make_shared<Xen>(vmi_get_vmid(guard.get()));
	
		// enable altp2m support.
		EnableAltp2m();

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
		
		// create execute view.
		if (vmi_slat_create(guard.get(), &view_x) != VMI_SUCCESS)
			throw std::runtime_error("Failed to create x view.");

		// setup memory event.
		SETUP_MEM_EVENT(&mem_event, ~0ULL, VMI_MEMACCESS_RW, HandleMemEvent, 1);
		mem_event.data = this;
		vmi_register_event(guard.get(), &mem_event);

		// setup single step events.
		for (auto i = 0; i < max_vcpu; i++)
		{
			auto& event = step_events[i];
			SETUP_SINGLESTEP_EVENT(&event, 1 << i, HandleStepEvent, 0);
			event.data = this;
			vmi_register_event(guard.get(), &event);
		}

		// make execute view active.
		if (vmi_slat_switch(guard.get(), view_x) != VMI_SUCCESS)
			throw std::runtime_error("Failed to switch to x view.");
	}

	ExtendedInjectionStrategy::~ExtendedInjectionStrategy()
	{
		// never initialized...
		if (!xen)
			return;
		
		LockGuard guard(sm);
		
		// remove event handler.
		vmi_clear_event(guard.get(), &mem_event, nullptr);
		for (auto i = 0; i < max_vcpu; i++)
			vmi_clear_event(guard.get(), &step_events[i], nullptr);
		
		// remove all custom views.
		vmi_slat_switch(guard.get(), 0);
		vmi_slat_destroy(guard.get(), view_rw);
		vmi_slat_destroy(guard.get(), view_x);
		vmi_slat_set_domain_state(guard.get(), false);

		// free our sink page.
		FreePage(sink_page);

		// reset memory.
		xen->SetMaxMem(init_mem);
	}

	bool ExtendedInjectionStrategy::Apply(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);
		assert(patch->vcpu == ALL_VCPU);

		// lazy initialize.
		if (!xen)
			Initialize();

		// if we are trying to apply a patch to virtual memory,
		// translate it into physical memory first.
		if (patch->pid != 0)
		{
			addr_t location_pa;
			if (vmi_translate_uv2p(guard.get(), patch->location, patch->pid, &location_pa) != VMI_SUCCESS)
				throw std::runtime_error("Failed to translate patch location.");
			patch->location = location_pa;
		}

		// for now every patch must be limited to a single page.
		const auto start_page = addr_to_page(patch->location);
		const auto end_page = addr_to_page(patch->location + patch->data.size());
		if (start_page != end_page)
			throw std::runtime_error("EPT patch cannot modify multiple pages for now.");

		// figure out where to place our patch within the shadow page.
		const auto shadow_page = ReferenceShadowPage(start_page);
		const auto offset = translate_page_offset(patch->location, page_to_addr(shadow_page.execute));
	
		// store off original shadow page contents.
		patch->original.resize(patch->data.size());
		if (vmi_read_pa(guard.get(), offset, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
			return false;

		// finally, we can make our changes to our shadow page.
		if (vmi_write_pa(guard.get(), offset, patch->data.size(), patch->data.data(), nullptr) != VMI_SUCCESS)
			return false;		

		return InjectionStrategy::Apply(patch);
	}
	
	bool ExtendedInjectionStrategy::UndoPatch(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);

		const auto shadow_page = UnreferenceShadowPage(addr_to_page(patch->location));

		// if the unreferenced shadow page still has references elsewhere, we need to undo our changes.
		if (shadow_page.execute)
		{
			const auto offset = translate_page_offset(patch->location, page_to_addr(shadow_page.execute));

			if (vmi_write_pa(guard.get(), offset, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
				return false;
		}
		
		return InjectionStrategy::UndoPatch(patch);
	}
	
	event_response_t ExtendedInjectionStrategy::HandleMemEvent(vmi_instance_t vmi, vmi_event_t* event)
	{
		const auto instance = reinterpret_cast<ExtendedInjectionStrategy*>(event->data);

		// TODO: check if this is the right process and the right vcpu calling us.
		
		if (event->mem_event.gfn == instance->sink_page)
		{
			std::cout << "Someone tried to access the sink page." << std::endl;
			return VMI_EVENT_RESPONSE_EMULATE_NOWRITE;
		}

		event->slat_id = instance->view_rw;

		return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
	}

	event_response_t ExtendedInjectionStrategy::HandleStepEvent(vmi_instance_t vmi, vmi_event* event)
	{
		const auto instance = reinterpret_cast<ExtendedInjectionStrategy*>(event->data);
	
		// TODO: check if this is the right process and the right vcpu calling us.

		if (event->vcpu_id == 0)	
			event->slat_id = instance->view_x;

		return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
	}

	ShadowPage ExtendedInjectionStrategy::ReferenceShadowPage(addr_t page)
	{
		auto shadow_page = std::find_if(shadow_pages.begin(), shadow_pages.end(),
				[&page](ShadowPage& p) -> bool { return p.read_write == page; });
	
		// if the page does not exist yet, we need to create it.
		if (shadow_page == shadow_pages.end())
		{
			LockGuard guard(sm);
			shadow_pages.emplace_back();
			shadow_page = std::prev(shadow_pages.end());

			// make a new empty page to act as a shadow page.
			shadow_page->execute = AllocatePage();
			shadow_page->read_write = page;

			// copy over page contents to shadow page.
			uint8_t buffer[PAGE_SIZE];
			if (vmi_read_pa(guard.get(), page_to_addr(shadow_page->read_write), PAGE_SIZE, &buffer, nullptr) != VMI_SUCCESS)
				throw std::runtime_error("Could not read old page contents.");
			if (vmi_write_pa(guard.get(), page_to_addr(shadow_page->execute), PAGE_SIZE, &buffer, nullptr) != VMI_SUCCESS)
				throw std::runtime_error("Could not write shadow page contents.");

			// remap the pages into respective views.
			if (vmi_slat_change_gfn(guard.get(), view_x, shadow_page->read_write, shadow_page->execute) != VMI_SUCCESS
				|| vmi_slat_change_gfn(guard.get(), view_rw, shadow_page->execute, sink_page) != VMI_SUCCESS)
				throw std::runtime_error("Failed to map shadow page into EPT.");

			// activate memory events on both the original and the shadow page.
			if (vmi_set_mem_event(guard.get(), shadow_page->read_write, VMI_MEMACCESS_RW, view_x) != VMI_SUCCESS
				|| vmi_set_mem_event(guard.get(), shadow_page->execute, VMI_MEMACCESS_RW, view_x) != VMI_SUCCESS)
				throw std::runtime_error("Failed to enable memory events for x view.");
		}

		shadow_page->refs++;
		return *shadow_page;
	}
	
	ShadowPage ExtendedInjectionStrategy::UnreferenceShadowPage(addr_t page)
	{
		const auto shadow_page = std::find_if(shadow_pages.begin(), shadow_pages.end(),
				[&page](ShadowPage& p) -> bool { return p.read_write == page; });

		if (shadow_page == shadow_pages.end())
			throw std::runtime_error("Tried to unreference a non-existing shadow page.");

		// did we just lose the last reference to this page?
		if (--shadow_page->refs == 0)
		{
			// TODO: unmap it from the slat...

			FreePage(shadow_page->execute);
			shadow_pages.erase(shadow_page);
			return {};
		}

		return *shadow_page;
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

		// open xenctrl interface.
		const auto xc = xc_interface_open(nullptr, nullptr, 0);

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

		// close xenctrl interface.
		xc_interface_close(xc);
	}
}

