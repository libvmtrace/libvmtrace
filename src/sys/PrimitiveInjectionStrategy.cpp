
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
		if (patch->pid != 0 && patch->virt != ~0ull)
		{
			addr_t location_pa;
			if (vmi_translate_uv2p(guard.get(), patch->location, patch->pid, &location_pa) != VMI_SUCCESS)
				throw std::runtime_error("Failed to translate patch location.");
			patch->virt = patch->location;
			patch->location = location_pa;
		}

		if (vmi_read_pa(guard.get(), patch->location, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
			return false;

		if (vmi_write_pa(guard.get(), patch->location, patch->data.size(), patch->data.data(), nullptr) != VMI_SUCCESS)
			return false;

		return InjectionStrategy::Apply(patch);
	}
	
	bool PrimitiveInjectionStrategy::UndoPatch(std::shared_ptr<Patch> patch)
	{
		assert(patch->original.size() == patch->data.size());
		LockGuard guard(sm);

		if (vmi_write_pa(guard.get(), patch->location, patch->original.size(), patch->original.data(), nullptr) != VMI_SUCCESS)
			return false;

		return InjectionStrategy::UndoPatch(patch);
	}
}

