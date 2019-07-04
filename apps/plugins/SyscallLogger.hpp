#ifndef __SYSCALL_LOGGER__
#define __SYSCALL_LOGGER__

#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"

using namespace std;
using namespace rapidjson;

class SyscallLogger : public Plugin, public EventListener
{
	public:
		SyscallLogger(string vm_id, OperatingSystem& os, ProcessCache& pc, Log& log) : SyscallLogger(vm_id, os, pc, log, true, true) {};
		SyscallLogger(string vm_id, OperatingSystem& os, ProcessCache& pc, Log& log, bool json, bool return_value) : _vm_id(vm_id), _os(os), _pc(pc), _log(log), _json(json), _return_value(return_value)
		{
			_commands.push_back("Trace");
			_commands.push_back("Untrace");

			for (int i = 0; i < 600; i++)
			{
				_events[i] = nullptr;
			}

			_log_name = "sys_syscall_"+vm_id;
		}

		const string ExecuteCommand(const string command, 
									const vector<string> params,
									const string command_id,
									const string vm_id);

		const string GetName() const
		{
			return "SyscallLogger";
		}

		const vector<string> GetListCommands() const
		{
			return _commands;
		}

		const void Stop()
		{
			cout << "STOP" << endl;
		}

		bool callback(const Event* ev, void* data);

	private:
		string _vm_id;
		OperatingSystem& _os;
		SyscallEvent* _events[600];
		ProcessCache& _pc;
		Log& _log;
		bool _json;
		bool _return_value;

		vector<string> _commands;
		string _log_name;
};

#endif
