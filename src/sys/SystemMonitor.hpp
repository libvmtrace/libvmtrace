
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
#include <sys/CodeInjection.hpp>

namespace libvmtrace
{
	class BreakpointMechanism;
	class RegisterMechanism;

	enum bpm_type_t
	{
		INTTHREE, ALTP2M, DRAKVUF, NONE
	};

	class SystemMonitor
	{
		public:
			SystemMonitor(const std::string name, const bool event_support, const bool ept_support = false) :
				_name(name), _initialized(false), _event_support(event_support), _bpm(nullptr),
				_rm(nullptr), worker(nullptr), _profile(""), _is_locked(0)
			{
				if (ept_support)
					_inj = std::make_shared<ExtendedInjectionStrategy>(
							std::shared_ptr<SystemMonitor>(std::shared_ptr<SystemMonitor>{}, this));
				else
					_inj = std::make_shared<PrimitiveInjectionStrategy>(
							std::shared_ptr<SystemMonitor>(std::shared_ptr<SystemMonitor>{}, this));
			}

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

			const std::string GetName()
			{
				return _name;
			}

			void SetProfile(std::string profile)
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

			std::shared_ptr<InjectionStrategy> GetInjectionStrategy()
			{
				return _inj;
			}

		private:
			const std::string _name;
			bool _initialized;
			bool _event_support;
			
			vmi_instance_t _vmi;
			std::recursive_mutex _vmi_mtx;   

			BreakpointMechanism* _bpm;
			bpm_type_t _bpm_type;

			RegisterMechanism* _rm;
			std::shared_ptr<InjectionStrategy> _inj;

			std::vector<addr_t> _exclude_addresses;

			std::thread* worker;
			std::string _profile;

		protected:
			int _is_locked;
	};
}

#endif

