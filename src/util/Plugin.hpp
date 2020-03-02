
#ifndef __PLUGIN_H_
#define __PLUGIN_H_

#include <string>
#include <vector>

namespace libvmtrace
{
namespace util
{
	class Plugin
	{
	public:
		virtual const std::string ExecuteCommand(const std::string command, 
				const std::vector<std::string> params,
				const std::string command_id,
				const std::string vm_id)  = 0;
		
		virtual const std::vector<std::string> GetListCommands() const = 0;
		virtual const std::string GetName() const = 0;
		virtual const void Stop() = 0;
	};
}
}

#endif

