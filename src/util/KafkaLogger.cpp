
#include <util/KafkaLogger.hpp>
#include <boost/algorithm/string/replace.hpp>

namespace libvmtrace
{
namespace util
{
	void KafkaLogger::Log(const Entry* e)
	{
		const std::string data = e->ToJson();
		
		try
		{
			std::string errstr;
			std::string topic_name = e->GetType();

			boost::replace_all(topic_name, ":", "_");

			bool found = false;
			for (std::vector<std::pair<std::string,RdKafka::Topic*>>::iterator it = _topics.begin() ; it != _topics.end(); ++it)
			{
				if((*it).first == topic_name)
				{
					_producer->produce((*it).second, _partition, RdKafka::Producer::RK_MSG_COPY, 
									const_cast<char*>(data.c_str()), data.size(), NULL, NULL);
					found = true;
				}
			}

			if (!found)
			{
				RdKafka::Topic *topic = RdKafka::Topic::create(_producer, topic_name, _tconf, errstr);
				_producer->produce(topic, _partition, RdKafka::Producer::RK_MSG_COPY, 
									const_cast<char*>(data.c_str()), data.size(), NULL, NULL);
				_topics.push_back(std::pair<std::string, RdKafka::Topic*>(topic_name, topic));
			}
		}
		catch (std::logic_error& err)
		{
			std::cerr << "Problem in KafkaLogger (logic error)" << std::endl;
			std::cerr << err.what() << std::endl;
		}
		catch(...)
		{
			std::cerr << "Problem in KafkaLogger" << std::endl;
		}
	}
}
}

