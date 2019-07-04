#ifndef __SYSTEM_MONITOR_H
#define __SYSTEM_MONITOR_H

#include <string>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <mutex>
#include <vector>
#include <algorithm>
#include <thread>
#include <iostream>
#include <unistd.h>

// #include "libvmtrace.hpp"

using namespace std;

class BreakpointMechanism;
class RegisterMechanism;

enum bpm_type_t
{
	INTTHREE, ALTP2M, DRAKVUF, NONE
};

class SystemMonitor
{
	public:
		SystemMonitor(const string name, const bool event_support):
						_name(name), _initialized(false), _event_support(event_support), _bpm(nullptr), _rm(nullptr), worker(nullptr), _profile(""), _is_locked(0) {}

		~SystemMonitor();

		status_t Init();
		void DeInit();
		vmi_instance_t Lock();
		void Unlock();

		void Loop();
		void Stop();

		bool IsInitialized()
		{
			return _initialized;
		}

		bool IsEventSupported()
		{
			return _event_support;
		}

		const string GetName()
		{
			return _name;
		}

		void SetProfile(string profile)
		{
			_profile = profile;
		}

		void SetBPM(BreakpointMechanism* bpm, bpm_type_t type)
		{
			_bpm = bpm;
			_bpm_type = type;
		}

		BreakpointMechanism* GetBPM()
		{
			return _bpm;
		}

		bpm_type_t GetBPMType()
		{
			return _bpm_type;
		}

		// drakvuf_t& GetDrakvuf()
		// {
		// 	return _drakvuf;
		// }

		void SetRM(RegisterMechanism* rm)
		{
			_rm = rm;
		}

		RegisterMechanism* GetRM()
		{
			return _rm;
		}

		void AddExludeAddress(addr_t address)
		{
			_exclude_addresses.push_back(address);
		}

		bool IsExcludeAddress(addr_t address)
		{
			if(_exclude_addresses.empty())
			{
				return false;
			}

			if(find(_exclude_addresses.begin(), _exclude_addresses.end(), address) != _exclude_addresses.end()) 
			{
				return true;
			}
			else 
			{
				return false;
			}
		}

	private:
		const string _name;
		bool _initialized;
		bool _event_support;
		
		vmi_instance_t _vmi;
		recursive_mutex _vmi_mtx;   

		BreakpointMechanism* _bpm;
		bpm_type_t _bpm_type;

		RegisterMechanism* _rm;

		vector<addr_t> _exclude_addresses;

		thread* worker;

		string _profile;

	protected:
		int _is_locked;
};
#endif
// vim: tabstop=4 shiftwidth=4 expandtab
