#ifndef __OPERATING_SYSTEM_H
#define __OPERATING_SYSTEM_H

#include "net/NetworkConnection.hpp"
//#include "sys/Snapshot.hpp"
#include "sys/Event.hpp"
#include "sys/SystemMonitor.hpp"
#include "sys/Process.hpp"
//#include "sys/DiffSnapshot.hpp"
//#include "util/json.h"
#include <string.h>
#include <vector>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

using namespace std;
using namespace rapidjson;

enum ConnectionType
{
	TCP, UDP
};

class OperatingSystem
{
	public:
		virtual vector<Process> GetProcessList() = 0;
		virtual vector <NetworkConnection> GetNetworkConnections(const Process& p, const ConnectionType type) = 0;
		
		virtual status_t RegisterSyscall(SyscallEvent& ev) = 0;
		virtual status_t DeRegisterSyscall(SyscallEvent& ev) = 0;

		virtual status_t RegisterProcessChange(ProcessChangeEvent& ev) = 0;
		virtual status_t DeRegisterProcessChange(ProcessChangeEvent& ev) = 0;

		virtual void Stop() = 0;

		string GetProcessesListJson(vector<Process> processes);
	protected:
		OperatingSystem(SystemMonitor* sm) : _sm(sm) {};
		SystemMonitor* _sm;
};

#endif