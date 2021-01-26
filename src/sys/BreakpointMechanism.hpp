#ifndef __BP_MECHANISM_H_
#define __BP_MECHANISM_H_

#include <sys/Event.hpp>
#include <sys/SystemMonitor.hpp>
#include <unordered_map>

namespace libvmtrace
{
	struct breakpoint
	{
		std::shared_ptr<Patch> patch;
		const BreakpointEvent* event;
		bool nop{};
	};

	typedef event_response_t(*unhandled_fn)(vmi_event_t*);

	struct BPEventData
	{
		unsigned int vcpu;
		x86_registers_t regs;
		breakpoint* bp;
		uint16_t slat_id;
		void* raw_event;
		addr_t paddr;
		BreakpointMechanism* bpm;

		bool beforeSingleStep = true;
		addr_t ripAfterSingleStep;
		std::string proc_name;
		int pid;
	};

	class BreakpointMechanism
	{
		inline static constexpr auto TRAP = 0xCC;

		public:
			BreakpointMechanism(std::shared_ptr<SystemMonitor> sm);
			~BreakpointMechanism();
			status_t InsertBreakpoint(const BreakpointEvent* ev);
			status_t RemoveBreakpoint(const BreakpointEvent* ev);

			void Disable();
			void Enable();

		private:
			static event_response_t HandleInterruptEvent(vmi_instance_t vmi, vmi_event_t* event);
			static event_response_t HandleStepEvent(vmi_instance_t vmi, vmi_event_t* event);

			std::shared_ptr<SystemMonitor> sm;
			vmi_event_t interrupt_event;
			std::vector<vmi_event_t> step_events;
			std::vector<BPEventData> event_data;
			std::unordered_map<addr_t, breakpoint> bp;
			bool disabled{}, extended{};
	};
}

#endif
