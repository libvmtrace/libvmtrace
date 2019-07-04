#include "util/KafkaLogger.hpp"
#include <boost/algorithm/string/replace.hpp>

void KafkaLogger::Log(const Entry* e)
{
	const string data = e->ToJson();
	
	try
	{
		string errstr;
		string topic_name = e->GetType();

		boost::replace_all(topic_name, ":", "_");

		bool found = false;
		for(vector<pair<string,RdKafka::Topic*>>::iterator it = _topics.begin() ; it != _topics.end(); ++it)
		{
			if((*it).first == topic_name)
			{
				_producer->produce((*it).second, _partition, RdKafka::Producer::RK_MSG_COPY, 
								const_cast<char*>(data.c_str()), data.size(), NULL, NULL);

				found = true;
			}
		}

		if(!found)
		{
			RdKafka::Topic *topic = RdKafka::Topic::create(_producer, topic_name, _tconf, errstr);
			_producer->produce(topic, _partition, RdKafka::Producer::RK_MSG_COPY, 
								const_cast<char*>(data.c_str()), data.size(), NULL, NULL);

			_topics.push_back(pair<string, RdKafka::Topic*>(topic_name, topic));
		}
	}
	catch (logic_error& err)
	{
		cerr << "Problem in KafkaLogger (logic error)" << endl;
		cerr << err.what() << endl;
	}
	catch(...)
	{
		cerr << "Problem in KafkaLogger" << endl;
	}
}
