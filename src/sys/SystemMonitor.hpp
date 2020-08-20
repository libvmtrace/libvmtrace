
#ifndef __SYSTEM_MONITOR_H
#define __SYSTEM_MONITOR_H

#include <string>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <mutex>
#include <vector>
#include <algorithm>
#include <thread>
#include <future>
#include <iostream>
#include <unistd.h>
#include <sys/CodeInjection.hpp>

namespace libvmtrace
{
	class BreakpointMechanism;
	class RegisterMechanism;

	class SystemMonitor : public std::enable_shared_from_this<SystemMonitor>
	{
		public:
			SystemMonitor(const std::string name, const bool event_support,
					const bool ept_support = false) noexcept(false);
			~SystemMonitor() noexcept(false);

			status_t Init();
			void DeInit();
			vmi_instance_t Lock();
			void Unlock();

			void Loop();
			void Stop();

			bool IsEventSupported()
			{
				return event_support;
			}

			const std::string GetName()
			{
				return name;
			}

			void SetProfile(std::string profile)
			{
				this->profile = profile;
			}

			std::shared_ptr<BreakpointMechanism> GetBPM()
			{
				return bpm;
			}

			std::shared_ptr<RegisterMechanism> GetRM()
			{
				return rm;
			}

			void AddExludeAddress(addr_t address)
			{
				exclude_addresses.push_back(address);
			}

			bool IsExcludeAddress(addr_t address)
			{
				return std::find(exclude_addresses.begin(), exclude_addresses.end(), address)
					!= exclude_addresses.end();
			}

			std::shared_ptr<InjectionStrategy> GetInjectionStrategy()
			{
				return inj;
			}

		private:
			void ProcessEvents(); 

			const std::string name;
			bool initialized;
			bool event_support;
			bool ept_support;
			
			vmi_instance_t vmi;
			std::recursive_mutex vmi_mtx;

			std::shared_ptr<BreakpointMechanism> bpm;
			std::shared_ptr<RegisterMechanism> rm;
			std::shared_ptr<InjectionStrategy> inj;

			std::vector<addr_t> exclude_addresses;

			std::shared_ptr<std::thread> worker;
			std::promise<void> worker_exit;
			std::string profile;
	};
}

#endif

