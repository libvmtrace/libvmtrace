#ifndef __PLUGIN_H_
#define __PLUGIN_H_

#include <string>
#include <vector>

using namespace std;

class Plugin
{
	public:
		virtual const string ExecuteCommand(const string command, 
				const vector<string> params,
				const string command_id,
				const string vm_id)  = 0;
		
		virtual const vector<string> GetListCommands() const = 0;
		virtual const string GetName() const = 0;
		virtual const void Stop() = 0;
};

#endif