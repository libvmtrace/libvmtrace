#ifndef __KAFKACOMMANDER_H__
#define __KAFKACOMMANDER_H__

#include <string>
#include <iostream>
#include <vector>
#include <map>
#include "util/Controller.hpp"
#include "librdkafka/rdkafkacpp.h"

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

using namespace std;
using namespace rapidjson;

class KafkaCommander
{
	public:
		KafkaCommander(const string broker, const string command_topic, Controller& contoller, const string vm_id) :
						_broker(broker), _controller(contoller), _command_topic(command_topic), _vm_id(vm_id)
		{
			string errstr;

			_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
			if(_conf == nullptr)
			{
				cerr << "err 1" << endl;
			}

			_tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);
			if(_tconf == nullptr)
			{
				cerr << "err 1" << endl;
			}

			_conf->set("metadata.broker.list", _broker, errstr);
			_conf->set("group.id", "0", errstr);
			if(_conf == nullptr)
			{
				cerr << "err 1" << endl;
			}

			_consumer = RdKafka::Consumer::create(_conf, errstr);

			_partition = 1;

			_topic = RdKafka::Topic::create(_consumer, _command_topic, _tconf, errstr);

			RdKafka::ErrorCode resp = _consumer->start(_topic, 0, RdKafka::Topic::OFFSET_END);
			if (resp != RdKafka::ERR_NO_ERROR)
			{
				cerr << "Failed to start consumer: " << RdKafka::err2str(resp) << endl;
			}
		}

		void GetCommands();

	private:
		void ParseCommand(const string command);

		const string _broker;
		Controller& _controller;
		RdKafka::Conf* _conf;
		RdKafka::Conf* _tconf;
		RdKafka::Consumer* _consumer;
		RdKafka::Topic* _topic;
		int32_t _partition;

		const string _command_topic;
		const string _vm_id;
};

#endif