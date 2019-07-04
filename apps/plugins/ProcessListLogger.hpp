#ifndef __PROCESS_LIST_LOGGER_
#define __PROCESS_LIST_LOGGER_

#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"

using namespace std;

class ProcessListLogger : public Plugin
{
	public:
		ProcessListLogger(string vm_id, OperatingSystem& os, ProcessCache& pc, Log& log) : _vm_id(vm_id), _os(os), _pc(pc), _log(log), _pt(nullptr)
		{
			_commands.push_back("GetProcessList");
			_commands.push_back("EnablePeriodic <time(s)>");
			_commands.push_back("DisablePeriodic");

			_log_name = "processes_list_"+vm_id;

			_start = false;
		}
		~ProcessListLogger() {
			if (_pt != nullptr)
			{
				delete _pt;
				_pt = nullptr;
			}
			
		}

		const string ExecuteCommand(const string command, 
									const vector<string> params,
									const string command_id,
									const string vm_id);

		const string GetName() const
		{
			return "ProcessListLogger";
		}

		const vector<string> GetListCommands() const
		{
			return _commands;
		}

		const void Stop()
		{
			cout << "STOP" << endl;
		}

		string GetVmId()
		{
			return _vm_id;
		}

		bool callback(const Event* ev, void* data);

	private:
		string _vm_id;
		OperatingSystem& _os;
		ProcessCache& _pc;
		Log& _log;

		vector<string> _commands;
		string _log_name;

		PeriodicTimer* _pt;

		bool _start;
};

void LogProcessList(void *data);

#endif
