
#ifndef CODE_INJECTION_H
#define CODE_INJECTION_H

#define LIBXL_API_VERSION 0x040500
#define XC_WANT_COMPAT_EVTCHN_API 1
#define XC_WANT_COMPAT_MAP_FOREIGN_API 1

#include <algorithm>
#include <vector>
#include <memory>
#include <climits>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <sys/Xen.hpp>
#include <sys/Event.hpp>

// this is needed so that the function signatures are not mangled,
// so that ldd can link against libxenctrl.so without problems.
extern "C"
{
	#include <libxl_utils.h>
	#include <xenctrl.h>
}

namespace libvmtrace
{
	inline static constexpr auto ALL_VCPU = USHRT_MAX;
	inline static constexpr auto PAGE_RANGE = 12;
	inline static constexpr auto PAGE_SIZE = 1 << PAGE_RANGE;

	inline addr_t addr_to_page(addr_t addr) { return addr >> PAGE_RANGE; }
	inline addr_t page_to_addr(addr_t page) { return page << PAGE_RANGE; }
	inline addr_t translate_page_offset(addr_t from, addr_t to)
	{
		return to + (from & (PAGE_SIZE - 1));
	}

	class SystemMonitor;
	class BPEventData;

	class Patch
	{
		friend class InjectionStrategy;
		friend class PrimitiveInjectionStrategy;
		friend class ExtendedInjectionStrategy;

	public:
		Patch(addr_t location, uint64_t pid, uint64_t vcpu, std::vector<uint8_t> data, bool kernel_space = false, bool relocatable = false)
				: location(location), pid(pid), vcpu(vcpu), data(data), virt(kernel_space ? ~0ull : 0ull), relocatable(relocatable) { }

		inline addr_t get_virt() const { return virt; }

	private:
		addr_t location, virt;
		uint64_t pid;
		uint64_t vcpu;
		std::vector<uint8_t> data;
		std::vector<uint8_t> original;
		std::vector<std::shared_ptr<Patch>> dependencies;

		// NOTE: this may not be used on breakpoints as it changes the semantics.
		bool relocatable{};
	};

	struct ShadowPage
	{
		addr_t read_write{}, execute{};
		uint16_t vcpu{};
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
					canidate->dependencies.push_back(canidate);
			
			patches.push_back(patch);	
			return true;
		}

		virtual bool Undo(std::shared_ptr<Patch> patch)
		{
			auto result = false;

			while (!patch->dependencies.empty())
			{
				const auto next = patch->dependencies.back();
				patch->dependencies.pop_back();	
				result |= !UndoPatch(next);
			}
			
			return !result & UndoPatch(patch);
		}

		virtual void NotifyFork(const BPEventData* data) { }

	protected:
		virtual bool UndoPatch(std::shared_ptr<Patch> patch)
		{
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
		virtual void NotifyFork(const BPEventData* data) override;
	
	private:
		void Initialize();
		virtual bool UndoPatch(std::shared_ptr<Patch> patch) override;

		bool HandleSchedulerEvent(Event* event, void* data);
		static event_response_t HandleMemEvent(vmi_instance_t vmi, vmi_event_t* event);

		ShadowPage ReferenceShadowPage(addr_t page, uint16_t vcpu, vmi_pid_t pid);
		ShadowPage UnreferenceShadowPage(addr_t page, uint16_t vcpu, vmi_pid_t pid);

		bool Synchronize(std::shared_ptr<Patch> patch);

		uint64_t AllocatePage();
		void FreePage(uint64_t page);
		void EnableAltp2m();

		std::vector<ShadowPage> shadow_pages;
		std::shared_ptr<Xen> xen;
		uint64_t init_mem, last_page, sink_page;
		uint16_t view_rw;
		std::vector<uint16_t> view_x;
		std::unique_ptr<injection_listener> cr3_listener;
		std::unique_ptr<ProcessChangeEvent> cr3_change;
		vmi_event_t mem_event{};
		bool decommissioned{};

		// paramters for injection.
		bool hide{}, coordinated = true;

		// we need these for now until the xc wrappers are in libvmi upstream.
		uint64_t vmid;
		xc_interface* xc;
	};
}

#endif /* CODE_INJECTION_H */

