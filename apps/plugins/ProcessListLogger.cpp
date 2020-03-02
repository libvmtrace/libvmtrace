
#include <plugins/ProcessListLogger.hpp>

using namespace rapidjson;

namespace libvmtrace
{
	const std::string ProcessListLogger::ExecuteCommand(const std::string command, 
					const std::vector<std::string> params,
					const std::string command_id,
					const std::string vm_id)
	{
		if(vm_id != _vm_id)
		{
			return "";
		}

		if(command == "GetProcessList")
		{
			auto start = std::chrono::high_resolution_clock::now();
			_pc.UpdateList();
			auto end = std::chrono::high_resolution_clock::now();
			auto dur = end - start;
			auto ms = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

			std::string s =  _os.GetProcessesListJson(_pc.GetProcessesArray()); 
			s.pop_back();
			s = s + ", \"time_micros:\":\"" + std::to_string(ms) + "\" }";

			//_log.log(_vm_id, _log_name, _os.GetProcessesListJson(_pc.GetProcessesArray()));
			_log.log(_vm_id, _log_name, s);
		}
		else if(command == "EnablePeriodic")
		{
			if (_pt != nullptr)
			{
				return "";
			}

			unsigned int time = 1000;
			if (params.size() == 1)
			{
				int x = atoi(params[0].c_str());
				time = x;
			}

			_pt = new PeriodicTimer(LogProcessList, this, time);
		}
		else if (command == "DisablePeriodic")
		{
			if (_pt != nullptr)
			{
				delete _pt;
				_pt = nullptr;
			}
		}

		return "";
	}

	void LogProcessList(void *data)
	{
		ProcessListLogger* psl = (ProcessListLogger*)(data);
		psl->ExecuteCommand("GetProcessList", vector<string>(), "0", psl->GetVmId());
	}
}

