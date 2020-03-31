
#include <sys/CodeInjection.hpp>
#include <util/LockGuard.hpp>

namespace libvmtrace
{
	using namespace util;

	PrimitiveInjectionStrategy::PrimitiveInjectionStrategy(std::shared_ptr<SystemMonitor> sm) : InjectionStrategy(sm) { }

	bool PrimitiveInjectionStrategy::Apply(std::shared_ptr<Patch> patch)
	{
		LockGuard guard(sm);
		assert(patch->vcpu == ALL_VCPU);
		patch->original.resize(patch->data.size());

		// are we patching virtual memory inside a process?
		if (patch->pid != 0)
		{
			if (vmi_read_va(guard.get(), patch->location, patch->pid, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
				return false;

			if (vmi_write_va(guard.get(), patch->location, patch->pid, patch->data.size(), patch->data.data(), nullptr) != VMI_SUCCESS)
				return false;
		}
		// or are we patching a physical memory address?
		else
		{
			if (vmi_read_pa(guard.get(), patch->location, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
				return false;
			
			if (vmi_write_pa(guard.get(), patch->location, patch->data.size(), patch->data.data(), nullptr) != VMI_SUCCESS)
				return false;
		}

		return InjectionStrategy::Apply(patch);
	}
	
	bool PrimitiveInjectionStrategy::UndoPatch(std::shared_ptr<Patch> patch)
	{
		assert(patch->original.size() == patch->data.size());
		LockGuard guard(sm);

		// are we patching virtual memory inside a process?
		if (patch->pid != 0)
		{
			if (vmi_write_va(guard.get(), patch->location, patch->pid, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
				return false;
		}
		// or are we patching a physical memory address?
		else if (vmi_write_pa(guard.get(), patch->location, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
				return false;

		return InjectionStrategy::UndoPatch(patch);
	}
}

