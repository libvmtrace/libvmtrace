
#ifndef __EVENT_H_
#define __EVENT_H_

#include <map>
#include <vector>
#include <algorithm>
#include <memory>
#include <iostream>
#include <functional>
#include <assert.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <sys/SyscallBasic.hpp>

namespace libvmtrace
{
	class Event;

	// A class that wants to be informed about new Events must implement this class
	class EventListener 
	{
		public:
			virtual bool callback(Event* ev, void* data) = 0;
	};
	
	using callback_fn = std::function<bool(Event*, void*)>;

	class injection_listener : public EventListener
	{
	public:
		injection_listener(callback_fn fn) : fn(fn) { };
		bool callback(Event* event, void* data) final
		{
			return fn(event, data);
		}

	private:
		callback_fn fn;
	};

	// A very abstract Event class
	class Event 
	{
		public:
			Event(EventListener& el) : _el(el) {}

			virtual bool callback(void* data) 
			{
				return _el.callback(this, data);
			}
			virtual ~Event() {};

			event_response_t response{};

		private:
			EventListener& _el;
	};

	class MemEvent: public Event 
	{
		public:
			MemEvent(const vmi_event_t& ev,  EventListener& el): Event(el), ev(ev) {}
			vmi_event_t ev; 
		
		private:
	};

	class RegEvent: public Event 
	{
		public:
			RegEvent(const vmi_event_t& ev,  EventListener& el): Event(el), ev(ev) {}
			vmi_event_t ev; 

		protected:
			RegEvent(EventListener& el) : Event(el) {}
	};

	class ProcessChangeEvent : public RegEvent 
	{
		public:
			ProcessChangeEvent(EventListener& el) : RegEvent(el) 
			{
				ev.reg_event.reg = CR3;
			}
		
		private:
	};

	class BreakpointEvent : public Event 
	{
		public:
			BreakpointEvent(const std::string name, addr_t addr, EventListener& el, bool fast = false) : Event(el), _name(name), _addr(addr), _fast(fast) {}
			addr_t  GetAddr () const 
			{ 
				return _addr;
			};
			
			std::string GetName () const
			{
				return _name;
			}

			bool IsFast() const
			{
				return _fast;
			}

		protected:
			BreakpointEvent();
			const std::string _name;
			const addr_t _addr;
			const bool _fast;
	};

	enum SyscallType
	{
		ALL_SYSCALLS, BEFORE_CALL, AFTER_CALL
	};

	class SyscallEvent : public Event
	{
		public:
			SyscallEvent(int syscallnumber, EventListener& el, bool with_ret, bool is32bit, bool processJson, vmi_pid_t pid = 0):  
				Event(el), 
				_nr(syscallnumber), 
				_with_ret(with_ret),
				_is32bit(is32bit),
				_processJson(processJson),
				_pid(pid) { }

			inline int GetNr () const { return _nr;};
			inline bool WithRet() const { return _with_ret; };
			inline bool Is32bit() const { return _is32bit; };
			inline bool ProcessJson() const { return _processJson; };
			inline vmi_pid_t GetPid() const { return _pid; }

		private:
			const int _nr;
			const bool _with_ret;
			const bool _is32bit;
			const bool _processJson;
			const vmi_pid_t _pid;
	};

	class ProcessBreakpointEvent : public BreakpointEvent 
	{
		public:
			ProcessBreakpointEvent(const std::string name, vmi_pid_t pid, addr_t addr, EventListener& el, bool fast = false) :
				BreakpointEvent(name, addr, el, fast),
				_pid(pid) { }

			vmi_pid_t GetPid() const { return _pid; };
			
		private:
			vmi_pid_t _pid; 
			bool fast;
	};

	// NOTE: For now we do not support *fast* syscall breakpoints.
	// Unsure, if there are situations, where this is desirable.
	class SyscallBreakpoint : public ProcessBreakpointEvent
	{
		public:
			SyscallBreakpoint(addr_t addr, EventListener& el, int nr, SyscallType type, bool is32bit, bool processJson, vmi_pid_t pid = 0) :
								ProcessBreakpointEvent("syscall_" + std::to_string(nr) + (type == AFTER_CALL ? " after call" : ""), pid, addr, el),
								_nr(nr),
								_type(type),
								_is32bit(is32bit),
								_processJson(processJson),
								_syscall(nullptr) { }

			SyscallBreakpoint(addr_t addr, EventListener& el, int nr, SyscallType type, bool is32bit, bool processJson, SyscallBasic* s, vmi_pid_t pid = 0) :
								ProcessBreakpointEvent("syscall_" + std::to_string(nr) + (type == AFTER_CALL ? " after call" : ""), pid, addr, el),
								_nr(nr),
								_type(type),
								_is32bit(is32bit),
								_processJson(processJson),
								_syscall(s) { }

			~SyscallBreakpoint() {}
			inline int GetNr() const { return _nr; }
			inline SyscallType GetType() const { return _type; }
			inline SyscallBasic* GetSyscall() const { return _syscall; }
			inline bool Is32bit() const { return _is32bit; }
			inline bool ProcessJson() const { return _processJson; }

		private:
			int _nr;
			SyscallType _type;
			bool _is32bit;
			bool _processJson;
			SyscallBasic* _syscall;
	};
}

#endif

