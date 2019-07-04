#include "util/Controller.hpp"

void Controller::RegisterPlugin(Plugin& p) 
{
	if(_plugins.find(p.GetName()) != _plugins.end())
	{
		cerr << "The plugin is already registered" << endl;
		return;
	}
	
	_plugins.insert(pair<const string, Plugin&>(p.GetName(), p));
}

void Controller::DeRegisterPlugin(Plugin& p) 
{
	if(_plugins.find(p.GetName()) == _plugins.end())
	{
		cerr << "The plugin is not registered" << endl;
		return;
	}

	auto it = _plugins.find(p.GetName());
	_plugins.erase(it);
}

vector<string> Controller::GetListPlugins(void) 
{
	vector<std::string> ret;
	
	for (auto& it: _plugins) 
	{
		ret.push_back(it.first);
	}

	return ret;
}

vector<string> Controller::GetListCommands(const string plugin) 
{
	auto it = _plugins.find(plugin);
	if (it == _plugins.end()) 
	{
		cerr << "ERR: plugin not found" << endl;
		return vector<string>();
	}
	vector<string> commands = it->second.GetListCommands();

	return commands;
}

void Controller::Stop() 
{
	for (auto& it: _plugins) 
	{
		it.second.Stop();
	}
}

string Controller::ExecuteCommand(const string plugin, 
								 const string command,
								 const vector<string> params,
								 const string command_id,
								 const string vm_id)
{
	auto it = _plugins.find(plugin);
	if (it == _plugins.end()) 
	{
		return "ERR: plugin " + plugin + " not found";
	}

	cout << "Execute " << plugin << " " << command << " param : [";
	for (auto p : params) 
	{
		cout << p << ", ";
	}
	cout << "]" << endl;

	return it->second.ExecuteCommand(command, params, command_id, vm_id);
}