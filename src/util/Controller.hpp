
#ifndef __CONTROLER_H_
#define __CONTROLER_H_

#include <string>
#include <vector>
#include <map>
#include <iostream>

#include <util/Plugin.hpp>

namespace libvmtrace 
{
namespace util
{
class Controller
{
	public:
		Controller() = default;
		
		void Stop();
		void RegisterPlugin(Plugin& plugin);
		void DeRegisterPlugin(Plugin& plugin);
		std::vector<std::string> GetListPlugins();
		std::vector<std::string> GetListCommands(const std::string plugin_name);
		std::string ExecuteCommand(const std::string plugin_name, const std::string command,
				const std::vector<std::string> params, const std::string command_id, const std::string vm_id);

	private:
		std::map<std::string, Plugin&> _plugins;
};
}
}

#endif

