#ifndef __CONTROLER_H_
#define __CONTROLER_H_

#include <string>
#include <vector>
#include <map>
#include <iostream>

#include <util/Plugin.hpp>

class Controller
{
	public:
		Controller() {}
		
		void Stop();
		void RegisterPlugin(Plugin& plugin);
		void DeRegisterPlugin(Plugin& plugin);
		vector<string> GetListPlugins();
		vector<string> GetListCommands(const string plugin_name);
		string ExecuteCommand(const string plugin_name, const string command, const vector<string> params, const string command_id, const string vm_id);

	private:
		map<string, Plugin&> _plugins;
};

#endif