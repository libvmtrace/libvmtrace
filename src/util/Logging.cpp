
#include <util/Logging.hpp>

namespace libvmtrace
{
namespace util
{
	const std::string Entry::ToJson() const
	{
		rapidjson::Document document;
		document.Parse(_data.c_str());

		rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
		
		rapidjson::Value tmp;
		document.AddMember("ts", _ts, allocator);
		tmp = rapidjson::StringRef(_vmid.c_str());
		document.AddMember("vmid", tmp, allocator);
		tmp = rapidjson::StringRef(_log_type.c_str());
		document.AddMember("logtype", tmp, allocator);

		rapidjson::StringBuffer strbuf;
		rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
		document.Accept(writer);

		return strbuf.GetString();
	}

	static void log_flush(void* data)
	{
		Log* log = (Log*) data;
		log->Flush();
	}

	Log::Log() : _stop(false) 
	{ 
		for (int i = 0; i < 1; i++) 
		{
			std::thread* t = new std::thread(log_flush, this);
			_workers.push_back(t);
		}
	}

	Log::~Log()
	{
		_stop = true;
		_buffer.add(NULL);

		for (auto t: _workers) 
		{
		    t->join();
		    delete t;
		}
	}

	void Log::log(const Entry* e) 
	{
		_buffer.add(e);
	}

	void Log::log(const std::string vmid, const std::string log_type, const std::string data) 
	{
		if (_buffer.size() > 100000)
			std::cerr << "buffer too big" << std::endl;

		Entry* e = new Entry(vmid,log_type,data);
		_buffer.add(e);
	}

	void Log::RegisterLogger(Logger* l) 
	{
		_logger.push_back(l);
	}

	void Log::Flush() 
	{
		while (!_stop) 
		{
			const Entry* dbe = _buffer.remove(); 
			
			if (dbe == NULL)
				break;

			for (std::vector<Logger*>::iterator logit = _logger.begin(); logit != _logger.end(); ++logit) 
				(*logit)->Log(dbe);
			
			delete dbe;
		}
	}

	void StdoutLogger::Log(const Entry* e)
	{
		if (_beauty)
		{
			rapidjson::Document document;
			document.Parse(e->ToJson().c_str());
			rapidjson::StringBuffer strbuf;
			rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(strbuf);
			document.Accept(writer);
			
			std::cout << strbuf.GetString() << std::endl;
		}
		else
			std::cout << e->ToJson() << std::endl;
	}

	void FileLogger::Log(const Entry* e)
	{
		if (_beauty)
		{
			rapidjson::Document document;
			document.Parse(e->ToJson().c_str());
			rapidjson::StringBuffer strbuf;
			rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(strbuf);
			document.Accept(writer);
			
			_logfile << strbuf.GetString() << std::endl;
		}
		else
			_logfile << e->ToJson() << std::endl;
	}
}
}

