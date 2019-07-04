#ifndef __EVENT_H_
#define __EVENT_H_

#include <map>
#include <vector>
#include <algorithm>
#include <memory>
#include <iostream>
#include <assert.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

using namespace std;

class Event;

// A class that wants to be informed about new Events must implement this class
class EventListener 
{
	public:
		virtual bool callback(const Event* ev, void* data) = 0;
};

// A very abstract Event class
class Event 
{
	public:
		Event(EventListener& el) : _el(el) {}

		virtual bool callback(void* data) const  
		{
			return _el.callback(this, data);
		}
		virtual ~Event() {};

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
		BreakpointEvent(const string name, addr_t addr, EventListener& el): Event(el), _name(name), _addr(addr) {}
		addr_t  GetAddr () const 
		{ 
			return _addr;
		};
		
		string GetName () const
		{
			return _name;
		}

	protected:
		BreakpointEvent();
		const string _name;
		const addr_t _addr;
};

class SyscallEvent : public Event
{
	public:
		SyscallEvent(int syscallnumber, EventListener& el, bool with_ret, bool is32bit, bool processJson):  
			Event(el), 
			_nr(syscallnumber), 
			_with_ret(with_ret),
			_is32bit(is32bit),
			_processJson(processJson) {}

		inline int GetNr () const { return _nr;};
		inline bool WithRet() const { return _with_ret; };
		inline bool Is32bit() const { return _is32bit; };
		inline bool ProcessJson() const { return _processJson; };

	private:
		const int _nr;
		const bool _with_ret;
		const bool _is32bit;
		const bool _processJson;
};

class ProcessBreakpointEvent : public BreakpointEvent 
{
	public:
		ProcessBreakpointEvent(const string name, vmi_pid_t pid,addr_t addr,EventListener& el): 
			BreakpointEvent(name,addr,el),
			_pid(pid) {}

		vmi_pid_t GetPid() const { return _pid; };
		
	private:
		vmi_pid_t _pid; 
};

// The EventManager: It manages Event structures and calls EventListeners
template<typename U, typename T> class EventManager 
{
	public:
		EventManager() {};
		~EventManager() {};
		void RegisterEvent(U signal, T e);
		void DeRegisterEvent(U signal, T e);
		void Call(U signal, void* data);
		uint64_t GetCount(U signal);
		void ForEach(void(*f)(T, void*), void* data);

	private:
		void RemoveEvents();    
		typedef map<U, vector<T>> evmap;
		evmap _Events;
		vector<pair<U, T>> _DeleteEvents;
};

#endif
// vim: tabstop=4 shiftwidth=4 expandtab 
