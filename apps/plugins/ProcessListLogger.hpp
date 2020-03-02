
#ifndef __PROCESS_LIST_LOGGER_
#define __PROCESS_LIST_LOGGER_

#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>

namespace libvmtrace
{
	class ProcessListLogger : public util::Plugin
	{
		public:
			ProcessListLogger(std::string vm_id, OperatingSystem& os, ProcessCache& pc, util::Log& log)
				: _vm_id(vm_id), _os(os), _pc(pc), _log(log), _pt(nullptr)
			{
				_commands.push_back("GetProcessList");
				_commands.push_back("EnablePeriodic <time(s)>");
				_commands.push_back("DisablePeriodic");

				_log_name = "processes_list_"+vm_id;

				_start = false;
			}

			~ProcessListLogger()
			{
				if (_pt != nullptr)
				{
					delete _pt;
					_pt = nullptr;
				}	
			}

			const std::string ExecuteCommand(const std::string command, 
							const std::vector<std::string> params,
							const std::string command_id,
							const std::string vm_id);

			const std::string GetName() const
			{
				return "ProcessListLogger";
			}

			const std::vector<std::string> GetListCommands() const
			{
				return _commands;
			}

			const void Stop()
			{
				std::cout << "STOP" << std::endl;
			}

			std::string GetVmId()
			{
				return _vm_id;
			}

			bool callback(const Event* ev, void* data);

		private:
			std::string _vm_id;
			OperatingSystem& _os;
			ProcessCache& _pc;
			util::Log& _log;

			std::vector<std::string> _commands;
			std::string _log_name;

			util::PeriodicTimer* _pt;

			bool _start;
	};

	void LogProcessList(void *data);
}

#endif

