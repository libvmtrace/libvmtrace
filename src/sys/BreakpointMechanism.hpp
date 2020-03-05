#ifndef __BP_MECHANISM_H_
#define __BP_MECHANISM_H_

#include <sys/Event.hpp>
#include <sys/SystemMonitor.hpp>

namespace libvmtrace
{
	constexpr auto TRAP = 0xCC;

	class BreakpointMechanism
	{
		public:
			BreakpointMechanism(SystemMonitor& sm):_sm(sm)
			{
				_counter = 0;
				if(!sm.IsEventSupported())
				{
					throw std::runtime_error("Event not supported");
				}
			}

			virtual status_t Init() = 0;
			virtual void DeInit() = 0;
			virtual status_t InsertBreakpoint(const BreakpointEvent* ev) = 0;
			virtual status_t RemoveBreakpoint(const BreakpointEvent* ev) = 0;

			//used for procchange
			virtual status_t TemporaryRemoveBreakpoint(const BreakpointEvent* ev) = 0;
			virtual status_t ReInsertBreakpoint(const BreakpointEvent* ev) = 0;

			virtual bpm_type_t GetType() = 0;

			void IncreaseCounter()
			{
				// cout << "add" << endl;
				_counter++;
			}

			void DecreaseCounter()
			{
				// cout << "deduct" << endl;
				_counter--;
			}

			int GetCounter()
			{
				return _counter;
			}

			SystemMonitor& GetSystemMonitor()
			{
				return _sm;
			}
		private:
			SystemMonitor& _sm;
			int _counter;
	};

	struct BPEventData
	{
		unsigned int vcpu;
		x86_registers_t regs;
		void* raw_event;
		addr_t paddr;
		BreakpointMechanism* bpm;

		bool beforeSingleStep;
		addr_t ripAfterSingleStep;
		std::string proc_name;
		int pid;
	};
}

#endif
