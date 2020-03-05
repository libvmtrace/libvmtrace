#ifndef __LINUX_BP_INT_3_H_
#define __LINUX_BP_INT_3_H_

#include <stdint.h>
#include <unistd.h>

#include <sys/BreakpointMechanism.hpp>
#include <libvmi/libvmi.h>

namespace libvmtrace
{
	class Int3 : public BreakpointMechanism
	{
		public:
			Int3(SystemMonitor& sm) : BreakpointMechanism(sm){}

			status_t InsertBreakpoint(const BreakpointEvent* ev);
			status_t RemoveBreakpoint(const BreakpointEvent* ev);
			status_t Init();
			void DeInit();

			status_t TemporaryRemoveBreakpoint(const BreakpointEvent* ev);
			status_t ReInsertBreakpoint(const BreakpointEvent* ev);

			void ProcessBreakpointEvent(vmi_event_t* ev);
			void ProcessMemoryEvent(vmi_event_t* ev);
			status_t ProcessBPSingleStepCB(BPEventData* bpd, addr_t rip);

			bpm_type_t GetType()
			{
				return INTTHREE;
			};
		private:

			/* Breakpoint related */
			vmi_event_t _interrupt_event;
			vmi_event_t _mem_event;

			vmi_event_t _step_events[16];

			EventManager<uint64_t, const BreakpointEvent*> _BPEvents;
			std::map<addr_t, uint8_t> _SavedInstructions;
	};
}

#endif
