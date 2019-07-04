#include "util/KafkaCommander.hpp"

void KafkaCommander::GetCommands()
{
	RdKafka::Message *message = _consumer->consume(_topic, 0, 1000);
	switch (message->err())
	{
		case RdKafka::ERR_NO_ERROR:
			ParseCommand(string(static_cast<const char*>(message->payload())));
		default:
			break;
	}
}

void KafkaCommander::ParseCommand(const string command)
{
	Document document;
	try
	{
		document.Parse<kParseStopWhenDoneFlag>(command.c_str());
		if(document.HasParseError())
		{
			cerr << "parse error" << endl;
			cerr << GetParseError_En(document.GetParseError()) << endl;
			return;
		}
		string vm_id = document["vm_id"].GetString();
		if(_vm_id != vm_id)
		{
			return;
		}


		//do checking
		if(!document.HasMember("plugin") || !document.HasMember("command") || !document.HasMember("command_id") || !document.HasMember("params"))
		{
			cout << "json member check failed" << endl;
			return;
		}
		else
		{
			if(!document["plugin"].IsString() || !document["command"].IsString() || !document["command_id"].IsString() || !document["params"].IsArray())
			{
				cout << "json member type check failed" << endl;
				return;
			}
		}

		string plugin = document["plugin"].GetString();
		// cout << plugin << endl;
		string comm = document["command"].GetString();
		// cout << comm << endl;
		string command_id = document["command_id"].GetString();
		// cout << command_id << endl;
		vector<string> parameters;

		Value& params = document["params"];
		for (Value::ConstValueIterator it = params.Begin(); it != params.End(); ++it)
		{
			// cout << it->GetString() << ",";
			parameters.push_back(it->GetString());
		}

		string ret = _controller.ExecuteCommand(plugin, comm, parameters, command_id, vm_id);
		// cout << endl;
		cout << ret << endl;
	}
	catch(...)
	{
		cerr << "parse error catch" << endl;
	}
}