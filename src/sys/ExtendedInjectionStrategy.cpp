
#include <sys/CodeInjection.hpp>
#include <util/LockGuard.hpp>


namespace libvmtrace
{
	using namespace util;

	ExtendedInjectionStrategy::ExtendedInjectionStrategy(std::shared_ptr<SystemMonitor> sm) : InjectionStrategy(sm)
	{
		LockGuard guard(sm);
		xen = std::make_shared<Xen>(vmi_get_vmid(guard.get()));
	}

	bool ExtendedInjectionStrategy::Apply(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);
		assert(patch->vcpu != ALL_VCPU);
		assert(patch->pid == 0);
		
		// for now every patch must be limited to a single page.
		const auto start_page = addr_to_page(patch->location);
		const auto end_page = addr_to_page(patch->location + patch->data.size());
		if (start_page != end_page)
			throw std::runtime_error("EPT patch cannot modify multiple pages.");

		patch->original.resize(patch->data.size());
		const auto shadow_page = ReferenceShadowPage(start_page);

		if (vmi_read_pa(guard.get(), patch->location, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
			return false;
	
		return InjectionStrategy::Apply(patch);
	}
	
	bool ExtendedInjectionStrategy::UndoPatch(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);

		// TODO: remove the patch from the shadow page.

		UnreferenceShadowPage(addr_to_page(patch->location));
		return InjectionStrategy::UndoPatch(patch);
	}
	
	ShadowPage ExtendedInjectionStrategy::ReferenceShadowPage(addr_t page)
	{
		auto shadow_page = std::find_if(shadow_pages.begin(), shadow_pages.end(),
				[&page](ShadowPage& p) -> bool { return p.read_write == page; });
	
		// if the page does not exist yet, we need to create it.
		if (shadow_page == shadow_pages.end())
		{
			shadow_pages.emplace_back();
			shadow_page = std::prev(shadow_pages.end());

			// TODO: create the actual page.
		}

		shadow_page->refs++;
		return *shadow_page;
	}
	
	void ExtendedInjectionStrategy::UnreferenceShadowPage(addr_t page)
	{
		const auto shadow_page = std::find_if(shadow_pages.begin(), shadow_pages.end(),
				[&page](ShadowPage& p) -> bool { return p.read_write == page; });

		if (shadow_page == shadow_pages.end())
			throw std::runtime_error("Tried to unreference a non-existing shadow page.");

		// did we just lose the last reference to this page?
		if (--shadow_page->refs == 0)
		{
			// TODO: get rid of the allocated memory.

			shadow_pages.erase(shadow_page);
		}
	}
}

