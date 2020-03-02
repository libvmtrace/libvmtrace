
#include <plugins/ProcessListLogger.hpp>
#include <plugins/ProcessChangeLogger.hpp>
#include <libvmtrace.hpp>

namespace libvmtrace
{
	const std::string ProcessChangeLogger::ExecuteCommand(const std::string command, 
		    const std::vector<std::string> par,
		    const std::string command_id,
		    const std::string vm_id) {
		std::cout << command << std::endl;
		if (command == "Enable") {
			_pce = new ProcessChangeEvent(*this);
			_os.RegisterProcessChange(*_pce);
		}
		return "ok";
	}
}

