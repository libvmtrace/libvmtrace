
#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#include <string>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <iostream>
#include <fstream>
#include <vector>

namespace libvmtrace
{
namespace util
{
	class Setting
	{
	public:
		Setting(std::string path) : _path(path)
		{
			std::ifstream ifs(path);
			if (ifs.fail())
				throw runtime_error("Setting file does not exist");

			IStreamWrapper isw(ifs);
			_document.ParseStream(isw);
			if (_document.HasParseError())
				throw runtime_error("Error parse setting file");
		}

		std::string GetStringValue(std::string key)
		{
			if (!_document.HasMember(key.c_str()))
				throw std::runtime_error("Key : " + key + " not found");

			if (!_document[key.c_str()].IsString())
				throw std::runtime_error("Key : " + key + " not a string");
			
			return _document[key.c_str()].GetString();
		}

		int GetIntValue(std::string key)
		{
			if (!_document.HasMember(key.c_str()))
				throw std::runtime_error("Key : " + key + " not found");

			if (!_document[key.c_str()].IsInt())
				throw std::runtime_error("Key : " + key + " not an int");
			
			return _document[key.c_str()].GetInt();
		}

		double GetDoubleValue(std::string key)
		{
			if (!_document.HasMember(key.c_str()))
				throw std::runtime_error("Key : " + key + " not found");

			if (!_document[key.c_str()].IsInt())
				throw std::runtime_error("Key : " + key + " not a double");
			
			return _document[key.c_str()].GetDouble();
		}

		std::vector<string> GetArrayString(std::string key)
		{
			if (!_document.HasMember(key.c_str()))
				throw std::runtime_error("Key : " + key + " not found");

			std::vector<std::string> ret;

			for (rapidjson::SizeType i = 0; i < _document[key.c_str()].Size(); i++)
				if (_document[key.c_str()][i].IsString())
					ret.push_back(_document[key.c_str()][i].GetString());
	
			return ret;
		}

		std::vector<int> GetArrayInteger(std::string key)
		{
			if (!_document.HasMember(key.c_str()))
				throw std::runtime_error("Key : " + key + " not found");

			std::vector<int> ret;

			for (SizeType i = 0; i < _document[key.c_str()].Size(); i++)
				if (_document[key.c_str()][i].IsInt())
					ret.push_back(_document[key.c_str()][i].GetInt());

			return ret;
		}

		std::vector<double> GetArrayDouble(std::string key)
		{
			if (!_document.HasMember(key.c_str()))
				throw std::runtime_error("Key : " + key + " not found");

			std::vector<double> ret;

			for (rapidjson::SizeType i = 0; i < _document[key.c_str()].Size(); i++)
				if (_document[key.c_str()][i].IsDouble())
					ret.push_back(_document[key.c_str()][i].GetDouble());

			return ret;
		}

	private:
		std::string _path;
		rapidjson::Document _document;
	};
}
}

#endif

