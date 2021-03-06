
#ifndef __OPERATING_SYSTEM_H
#define __OPERATING_SYSTEM_H

#include <net/NetworkConnection.hpp>
#include <sys/Event.hpp>
#include <sys/SystemMonitor.hpp>
#include <sys/Process.hpp>
#include <string.h>
#include <vector>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

namespace libvmtrace
{
	enum ConnectionType
	{
		TCP, UDP
	};

	class OperatingSystem
	{
		public:
			virtual std::vector<Process> GetProcessList() = 0;
			virtual std::vector<net::NetworkConnection> GetNetworkConnections(const Process& p, const ConnectionType type) = 0;
			
			virtual status_t RegisterSyscall(SyscallEvent& ev) = 0;
			virtual status_t DeRegisterSyscall(SyscallEvent& ev) = 0;

			virtual status_t RegisterProcessChange(ProcessChangeEvent& ev) = 0;
			virtual status_t DeRegisterProcessChange(ProcessChangeEvent& ev) = 0;

			std::string GetProcessesListJson(std::vector<Process> processes);

		protected:
			OperatingSystem(std::shared_ptr<SystemMonitor> sm) : _sm(sm) {};
			std::shared_ptr<SystemMonitor> _sm;
	};
}

#endif

