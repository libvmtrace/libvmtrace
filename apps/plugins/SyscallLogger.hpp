
#ifndef __SYSCALL_LOGGER__
#define __SYSCALL_LOGGER__

#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>

namespace libvmtrace
{
	class SyscallLogger : public util::Plugin, public EventListener
	{
		public:
			SyscallLogger(std::string vm_id, OperatingSystem& os, ProcessCache& pc, util::Log& log)
				: SyscallLogger(vm_id, os, pc, log, true, true) { };

			SyscallLogger(std::string vm_id, OperatingSystem& os, ProcessCache& pc, util::Log& log, bool json, bool return_value)
				: _vm_id(vm_id), _os(os), _pc(pc), _log(log), _json(json), _return_value(return_value)
			{
				_commands.push_back("Trace");
				_commands.push_back("Untrace");

				for (int i = 0; i < 600; i++)
					_events[i] = nullptr;

				_log_name = "sys_syscall_"+vm_id;
			}

			const std::string ExecuteCommand(const std::string command, const std::vector<std::string> params,
								const std::string command_id, const std::string vm_id);

			const std::string GetName() const
			{
				return "SyscallLogger";
			}

			const std::vector<std::string> GetListCommands() const
			{
				return _commands;
			}

			const void Stop()
			{
				std::cout << "STOP" << std::endl;
			}

			bool callback(const Event* ev, void* data);

		private:
			std::string _vm_id;
			OperatingSystem& _os;
			SyscallEvent* _events[600];
			ProcessCache& _pc;
			util::Log& _log;
			bool _json;
			bool _return_value;

			std::vector<std::string> _commands;
			std::string _log_name;
	};
}

#endif

