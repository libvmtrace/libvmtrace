#include "util/Logging.hpp"

const string Entry::ToJson() const
{
	Document document;
	document.Parse(_data.c_str());

	Document::AllocatorType& allocator = document.GetAllocator();
	
	Value tmp;
	document.AddMember("ts", _ts, allocator);
	tmp = StringRef(_vmid.c_str());
	document.AddMember("vmid", tmp, allocator);
	tmp = StringRef(_log_type.c_str());
	document.AddMember("logtype", tmp, allocator);

	StringBuffer strbuf;
	Writer<StringBuffer> writer(strbuf);
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
	for(int i=0; i<1; i++) 
	{
		thread* t = new thread(log_flush, this);
		_workers.push_back(t);
	}
}

Log::~Log()
{
	_stop = true;
	_buffer.add(NULL);
	for(auto t: _workers) 
	{
	    t->join();
	    delete t;
	}
}

void Log::log(const Entry* e) 
{
	_buffer.add(e);
}

void Log::log(const string vmid, const string log_type, const string data) 
{
	if (_buffer.size() > 100000)
		cout << "buffer too big" << endl;

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

		for(vector<Logger*>::iterator logit = _logger.begin();
		logit != _logger.end(); ++logit) 
		{
			(*logit)->Log(dbe);
		}
		delete dbe;
	}
}



void StdoutLogger::Log(const Entry* e)
{
	// cout << dec << e->GetTs() << " : " << e->GetVMId() << " - " <<  e->GetType() << endl;
	
	if(_beauty)
	{
		Document document;
		document.Parse(e->ToJson().c_str());
		StringBuffer strbuf;
		PrettyWriter<StringBuffer> writer(strbuf);
		document.Accept(writer);
		
		cout << strbuf.GetString() << endl;
	}
	else
	{
		cout << e->ToJson() << endl;
	}
}

void FileLogger::Log(const Entry* e) {
	if(_beauty)
	{
		Document document;
		document.Parse(e->ToJson().c_str());
		StringBuffer strbuf;
		PrettyWriter<StringBuffer> writer(strbuf);
		document.Accept(writer);
		
		_logfile << strbuf.GetString() << endl;
	}
	else
	{
		_logfile << e->ToJson() << endl;
	}
}
