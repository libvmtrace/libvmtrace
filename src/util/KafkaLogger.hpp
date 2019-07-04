#ifndef __KAFKALOGGER_H__
#define __KAFKALOGGER_H__

#include <string>
#include <iostream>
#include "util/Logging.hpp"
#include "librdkafka/rdkafkacpp.h"


class KafkaLogger : public Logger
{
	public:
		KafkaLogger(const string broker) : _broker(broker)
		{
			string errstr;
			_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
			_tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);
			_conf->set("metadata.broker.list", _broker, errstr);
			_producer = RdKafka::Producer::create(_conf, errstr);

			_partition = -1;
		}

		void Log(const Entry* e);

	private:
		const string _broker;
		RdKafka::Conf *_conf;
		RdKafka::Conf *_tconf;
		RdKafka::Producer *_producer;
		int32_t _partition;

		vector<pair<string,RdKafka::Topic*>> _topics;
};

#endif