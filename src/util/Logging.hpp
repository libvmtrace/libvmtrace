#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <fstream>


#include "wqueue.h"

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

using namespace std;
using namespace rapidjson;

class Entry
{
	public:
		Entry(const string vmid, const string log_type, const string data):
				_data(data), _vmid(vmid), _log_type(log_type),
				_ts(chrono::system_clock::now().time_since_epoch() / chrono::milliseconds(1))
		{

		}

		const string GetVMId() const { return _vmid; };
		const time_t GetTs() const { return _ts; };
		const string GetData() const { return _data; };
		const string GetType() const { return _log_type; };

		const string ToJson() const;

	private:
		const string _data;
		const string _vmid;
		const string _log_type;
		const time_t _ts;

		StringBuffer s;
		Writer<StringBuffer> writer;
};

class Logger
{
	public:
		virtual void Log(const Entry*) = 0;
		virtual ~Logger() {};
};

class StdoutLogger : public Logger
{
	public:
		StdoutLogger(bool beauty): _beauty(beauty) {}
		void Log(const Entry* e);
	private:
		const bool _beauty;
};

class FileLogger : public Logger
{
	public:
		FileLogger(bool beauty, const string& path): _beauty(beauty), _logfile(path) {};
		void Log(const Entry* e);
	private:
		const bool _beauty;
		std::ofstream _logfile;
};

class Log
{
	public:
		Log();
		~Log();
		void log(const Entry* e);
		void log(const string vmid, const string log_type, const string data);
		void RegisterLogger(Logger* logger);
		void DeRegisterLogger(Logger* logger);
		void Flush();

	private:
		wqueue<const Entry*> _buffer;
		vector<Logger*> _logger;
		vector<thread*> _workers;
		bool _stop;
};
#endif
