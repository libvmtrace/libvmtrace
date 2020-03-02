
#ifndef __KAFKACOMMANDER_H__
#define __KAFKACOMMANDER_H__

#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <util/Controller.hpp>
#include <librdkafka/rdkafkacpp.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

namespace libvmtrace
{
namespace util
{
	class KafkaCommander
	{
	public:
		KafkaCommander(const std::string broker, const std::string command_topic, Controller& contoller, const std::string vm_id) :
						_broker(broker), _controller(contoller), _command_topic(command_topic), _vm_id(vm_id)
		{
			std::string errstr;

			_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
			if(_conf == nullptr)
				std::cerr << "err 1" << std::endl;

			_tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);
			if(_tconf == nullptr)
				std::cerr << "err 1" << std::endl;

			_conf->set("metadata.broker.list", _broker, errstr);
			_conf->set("group.id", "0", errstr);
			if(_conf == nullptr)
				std::cerr << "err 1" << std::endl;

			_consumer = RdKafka::Consumer::create(_conf, errstr);

			_partition = 1;

			_topic = RdKafka::Topic::create(_consumer, _command_topic, _tconf, errstr);

			RdKafka::ErrorCode resp = _consumer->start(_topic, 0, RdKafka::Topic::OFFSET_END);
			if (resp != RdKafka::ERR_NO_ERROR)
				std::cerr << "Failed to start consumer: " << RdKafka::err2str(resp) << std::endl;
		}

		void GetCommands();

	private:
		void ParseCommand(const std::string command);

		const std::string _broker;
		Controller& _controller;
		RdKafka::Conf* _conf;
		RdKafka::Conf* _tconf;
		RdKafka::Consumer* _consumer;
		RdKafka::Topic* _topic;
		int32_t _partition;

		const std::string _command_topic;
		const std::string _vm_id;
	};
}
}

#endif

