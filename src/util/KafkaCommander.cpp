
#include <util/KafkaCommander.hpp>

namespace libvmtrace
{
namespace util
{
	void KafkaCommander::GetCommands()
	{
		RdKafka::Message *message = _consumer->consume(_topic, 0, 1000);
		switch (message->err())
		{
			case RdKafka::ERR_NO_ERROR:
				ParseCommand(std::string(static_cast<const char*>(message->payload())));
			default:
				break;
		}
	}

	void KafkaCommander::ParseCommand(const std::string command)
	{
		rapidjson::Document document;
		try
		{
			document.Parse<rapidjson::kParseStopWhenDoneFlag>(command.c_str());
			if(document.HasParseError())
			{
				std::cerr << "parse error" << std::endl;
				std::cerr << GetParseError_En(document.GetParseError()) << std::endl;
				return;
			}
	
			std::string vm_id = document["vm_id"].GetString();
			if(_vm_id != vm_id)
				return;

			if(!document.HasMember("plugin") || !document.HasMember("command") || !document.HasMember("command_id") || !document.HasMember("params"))
			{
				std::cout << "json member check failed" << std::endl;
				return;
			}
			else
			{
				if(!document["plugin"].IsString() || !document["command"].IsString() || !document["command_id"].IsString() || !document["params"].IsArray())
				{
					std::cout << "json member type check failed" << std::endl;
					return;
				}
			}

			std::string plugin = document["plugin"].GetString();
			std::string comm = document["command"].GetString();
			std::string command_id = document["command_id"].GetString();
			std::vector<std::string> parameters;

			rapidjson::Value& params = document["params"];
			for (rapidjson::Value::ConstValueIterator it = params.Begin(); it != params.End(); ++it)
				parameters.push_back(it->GetString());

			std::string ret = _controller.ExecuteCommand(plugin, comm, parameters, command_id, vm_id);
			std::cout << ret << std::endl;
		}
		catch(...)
		{
			std::cerr << "parse error catch" << std::endl;
		}
	}
}
}

