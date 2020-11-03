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
		BreakpointEvent* event;
		bool nop;
	};

	class BreakpointMechanism
	{
		inline static constexpr auto TRAP = 0xCC;

		public:
			BreakpointMechanism(std::shared_ptr<SystemMonitor> sm);
			~BreakpointMechanism();
			status_t InsertBreakpoint(BreakpointEvent* ev);
			status_t RemoveBreakpoint(BreakpointEvent* ev);

			void Disable();
			void Enable();

		private:
			static event_response_t HandleInterruptEvent(vmi_instance_t vmi, vmi_event_t* event);
			static event_response_t HandleStepEvent(vmi_instance_t vmi, vmi_event_t* event);

			std::shared_ptr<SystemMonitor> sm;
			vmi_event_t interrupt_event;
			std::vector<vmi_event_t> step_events;
			std::unordered_map<addr_t, breakpoint> bp;
			bool disabled{}, extended{};
	};

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
}

#endif
