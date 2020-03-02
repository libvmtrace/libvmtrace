
#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <fstream>

#include <util/wqueue.hpp>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

namespace libvmtrace
{
namespace util
{
	class Entry
	{
	public:
		Entry(const std::string vmid, const std::string log_type, const std::string data):
				_data(data), _vmid(vmid), _log_type(log_type),
				_ts(std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1)) { };

		const std::string GetVMId() const { return _vmid; };
		const std::time_t GetTs() const { return _ts; };
		const std::string GetData() const { return _data; };
		const std::string GetType() const { return _log_type; };

		const std::string ToJson() const;

	private:
		const std::string _data;
		const std::string _vmid;
		const std::string _log_type;
		const std::time_t _ts;

		rapidjson::StringBuffer s;
		rapidjson::Writer<rapidjson::StringBuffer> writer;
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
		FileLogger(bool beauty, const std::string& path): _beauty(beauty), _logfile(path) {};
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
		void log(const std::string vmid, const std::string log_type, const std::string data);
		void RegisterLogger(Logger* logger);
		void DeRegisterLogger(Logger* logger);
		void Flush();

	private:
		wqueue<const Entry*> _buffer;
		std::vector<Logger*> _logger;
		std::vector<std::thread*> _workers;
		bool _stop;
	};
}
}

#endif

