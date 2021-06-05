
#include <util/Controller.hpp>

namespace libvmtrace
{
namespace util
{
	void Controller::RegisterPlugin(Plugin& p) 
	{
		if(_plugins.find(p.GetName()) != _plugins.end())
		{
			std::cerr << "The plugin is already registered" << std::endl;
			return;
		}
		
		_plugins.insert(std::pair<const std::string, Plugin&>(p.GetName(), p));
	}

	void Controller::DeRegisterPlugin(Plugin& p) 
	{
		if(_plugins.find(p.GetName()) == _plugins.end())
		{
			std::cerr << "The plugin is not registered" << std::endl;
			return;
		}

		auto it = _plugins.find(p.GetName());
		_plugins.erase(it);
	}

	std::vector<std::string> Controller::GetListPlugins(void) 
	{
		std::vector<std::string> ret;
		
		for (auto& it: _plugins) 
			ret.push_back(it.first);

		return ret;
	}

	std::vector<std::string> Controller::GetListCommands(const std::string plugin) 
	{
		auto it = _plugins.find(plugin);
		if (it == _plugins.end()) 
		{
			std::cerr << "ERR: plugin not found" << std::endl;
			return std::vector<std::string>();
		}

		std::vector<std::string> commands = it->second.GetListCommands();
		return commands;
	}

	void Controller::Stop() 
	{
		for (auto& it: _plugins) 
			it.second.Stop();
	}

	std::string Controller::ExecuteCommand(const std::string plugin, 
					 const std::string command,
					 const std::vector<std::string> params,
					 const std::string command_id,
					 const std::string vm_id)
	{
		auto it = _plugins.find(plugin);
		if (it == _plugins.end()) 
			return "ERR: plugin " + plugin + " not found";

		std::cout << "Execute " << plugin << " " << command << " param : [";
		for (auto i = 0; i < params.size(); i++)
		{
			std::cout << params[i];
			if (i != params.size() - 1)
				std::cout << ", ";
		}
		std::cout << "]" << std::endl;

		return it->second.ExecuteCommand(command, params, command_id, vm_id);
	}
}
}

