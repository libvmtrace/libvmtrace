
#ifndef CODE_INJECTION_H
#define CODE_INJECTION_H

#include <algorithm>
#include <vector>
#include <memory>
#include <climits>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <sys/Xen.hpp>

namespace libvmtrace
{
	inline static constexpr auto ALL_VCPU = ULONG_MAX;
	inline static constexpr auto PAGE_RANGE = 12;
	inline static constexpr auto PAGE_SIZE = 1 << PAGE_RANGE;

	inline addr_t addr_to_page(addr_t addr) { return addr >> PAGE_RANGE; }
	inline addr_t page_to_addr(addr_t page) { return page << PAGE_RANGE; }
	inline addr_t translate_page_offset(addr_t from, addr_t to)
	{
		return to + from & (PAGE_SIZE - 1);
	}

	class SystemMonitor;

	class Patch
	{
		friend class InjectionStrategy;
		friend class PrimitiveInjectionStrategy;
		friend class ExtendedInjectionStrategy;

	public:
		Patch(addr_t location, uint64_t pid, uint64_t vcpu, std::vector<uint8_t> data)
				: location(location), pid(pid), vcpu(vcpu), data(data) { }
	
	private:
		addr_t location;
		uint64_t pid;
		uint64_t vcpu;
		std::vector<uint8_t> data;
		std::vector<uint8_t> original;
		std::vector<std::shared_ptr<Patch>> dependencies;
	};

	struct ShadowPage
	{
		addr_t read_write{}, execute{};
		size_t refs{};
	};

	class InjectionStrategy
	{
	public:
		InjectionStrategy(std::shared_ptr<SystemMonitor> sm) : sm(sm) { }

		virtual ~InjectionStrategy()
		{
			while (!patches.empty())
			{
				auto back = patches.back();
				patches.pop_back();
				Undo(back);
			}
		}
		
		virtual bool Apply(std::shared_ptr<Patch> patch)
		{
			// find patches that interleave with this one.
			for (auto& canidate : patches)	
				if (std::max(canidate->location, patch->location)
						<= std::min(canidate->location + canidate->data.size(),
							patch->location + patch->data.size()))
					patch->dependencies.push_back(canidate);
			
			patches.push_back(patch);	
			return true;
		}

		virtual bool Undo(std::shared_ptr<Patch> patch)
		{
			auto result = UndoPatch(patch);

			for (auto& dep : patch->dependencies)
				result |= UndoPatch(dep);

			return result;
		}

	protected:
		virtual bool UndoPatch(std::shared_ptr<Patch> patch)
		{
			patches.erase(std::remove(patches.begin(),
					patches.end(),
					patch));	
			return true;
		}
	
		std::vector<std::shared_ptr<Patch>> patches{};
		std::shared_ptr<SystemMonitor> sm;
	};
	
	class PrimitiveInjectionStrategy : public InjectionStrategy
	{
	public:
		PrimitiveInjectionStrategy(std::shared_ptr<SystemMonitor> sm);
		virtual bool Apply(std::shared_ptr<Patch> patch) override;
	
	private:
		virtual bool UndoPatch(std::shared_ptr<Patch> patch) override;
	};
	
	class ExtendedInjectionStrategy : public InjectionStrategy
	{
	public:
		ExtendedInjectionStrategy(std::shared_ptr<SystemMonitor> sm);
		virtual ~ExtendedInjectionStrategy() override;
		virtual bool Apply(std::shared_ptr<Patch> patch) override;
	
	private:
		void Initialize();
		virtual bool UndoPatch(std::shared_ptr<Patch> patch) override;

		static event_response_t HandleMemEvent(vmi_instance_t vmi, vmi_event_t* event);

		ShadowPage ReferenceShadowPage(addr_t page);
		ShadowPage UnreferenceShadowPage(addr_t page);

		uint64_t AllocatePage();
		void FreePage(uint64_t page);
		void AdjustMemoryCapacity(int64_t delta);

		std::vector<ShadowPage> shadow_pages;
		std::shared_ptr<Xen> xen;
		uint64_t last_page, sink_page;
		uint16_t view_rw, view_x;
		vmi_event_t mem_event;
	};
}

#endif /* CODE_INJECTION_H */

