#ifndef __LINUX_BP_ALTP2M_V_H_
#define __LINUX_BP_ALTP2M_V_H_

#include <stdint.h>
#include <sys/BreakpointMechanism.hpp>
#include <libvmi/libvmi.h>
#include <libvmi/slat.h>
#include <boost/bind.hpp>
#include <sys/Xen.hpp>

namespace libvmtrace
{
	struct remmaped_gfn
	{
		addr_t original;
		addr_t remapped;
		map<addr_t, addr_t> addrs;
	};

	class Altp2mBasic : public BreakpointMechanism
	{
		public:
			Altp2mBasic(SystemMonitor& sm) : BreakpointMechanism(sm), 
										_init_memsize(0), _max_gpfn(0), _zero_page_gfn(0) {}

			status_t InsertBreakpoint(const BreakpointEvent* ev);
			status_t RemoveBreakpoint(const BreakpointEvent* ev);

			status_t TemporaryRemoveBreakpoint(const BreakpointEvent* ev);
			status_t ReInsertBreakpoint(const BreakpointEvent* ev);

			status_t Init();
			void DeInit();

			bpm_type_t GetType()
			{
				return ALTP2M;
			}

			event_response_t ProcessBreakpointEvent(vmi_event_t* ev);
			event_response_t ProcessMemoryEvent(vmi_event_t* ev);

			void ProcessMEMSingleStepCB(vmi_event_t* event);
			void ProcessBPSingleStepCB(vmi_event_t* event, BPEventData* bpd, addr_t rip);

		private:
			void RemoveBreakpointPa(vmi_instance_t vmi, addr_t paddr);

			/* Breakpoint related */
			EventManager<uint64_t, const BreakpointEvent*> _BPEvents;
			map<addr_t, uint8_t> _SavedInstructions;
			vector<remmaped_gfn> _remmaped_gfns;

			vmi_event_t _interrupt_event;
			vmi_event_t _mem_event;

			vmi_event_t _step_events[16];

			uint64_t _init_memsize;
			uint64_t _max_gpfn;
			uint64_t _zero_page_gfn;

			//view during runtime
			uint16_t _view_x;

			//view when somebody try to read the shadow copy / empty page
			uint16_t _view_r;

			Xen* _xen;
	};
}

#endif
