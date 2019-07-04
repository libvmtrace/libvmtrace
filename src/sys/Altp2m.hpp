#ifndef __LINUX_BP_ALTP2M_H_
#define __LINUX_BP_ALTP2M_H_

#include <stdint.h>

#include <sys/BreakpointMechanism.hpp>
#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>

using namespace std;

class Altp2m : public BreakpointMechanism
{
	public:
		Altp2m(SystemMonitor& sm) : BreakpointMechanism(sm) {}

		status_t InsertBreakpoint(const BreakpointEvent* ev);
		status_t RemoveBreakpoint(const BreakpointEvent* ev);

		status_t TemporaryRemoveBreakpoint(const BreakpointEvent* ev);
		status_t ReInsertBreakpoint(const BreakpointEvent* ev);
		
		status_t Init();
		void DeInit();

		void ProcessBreakpointEvent(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

		bpm_type_t GetType()
		{
			return DRAKVUF;
		};
	private:
		//drakvuf_t _drakvuf;
		int _is_locked;

		/* Breakpoint related */
		EventManager<uint64_t, const BreakpointEvent*> _BPEvents;
		map<uint64_t, drakvuf_trap_t*> _bp_traps;
};

#endif