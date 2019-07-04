#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#include <string>
#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
using namespace rapidjson;

class Setting
{
	public:
		Setting(string path) : _path(path)
		{
			ifstream ifs(path);
			if(ifs.fail())
			{
				throw runtime_error("Setting file does not exist");
			}

			IStreamWrapper isw(ifs);
			_document.ParseStream(isw);
			if(_document.HasParseError())
			{
				throw runtime_error("Error parse setting file");
			}
		}

		string GetStringValue(string key)
		{
			if(!_document.HasMember(key.c_str()))
			{
				throw runtime_error("Key : "+key+" not found");
			}

			if(!_document[key.c_str()].IsString())
			{
				throw runtime_error("Key : "+key+" not a string");
			}
			
			return _document[key.c_str()].GetString();
		}

		int GetIntValue(string key)
		{
			if(!_document.HasMember(key.c_str()))
			{
				throw runtime_error("Key : "+key+" not found");
			}

			if(!_document[key.c_str()].IsInt())
			{
				throw runtime_error("Key : "+key+" not an int");
			}
			
			return _document[key.c_str()].GetInt();
		}

		double GetDoubleValue(string key)
		{
			if(!_document.HasMember(key.c_str()))
			{
				throw runtime_error("Key : "+key+" not found");
			}

			if(!_document[key.c_str()].IsInt())
			{
				throw runtime_error("Key : "+key+" not a double");
			}
			
			return _document[key.c_str()].GetDouble();
		}

		vector<string> GetArrayString(string key)
		{
			if(!_document.HasMember(key.c_str()))
			{
				throw runtime_error("Key : "+key+" not found");
			}

			vector<string> ret;

			for(SizeType i = 0 ; i < _document[key.c_str()].Size() ; i++)
			{
				if(_document[key.c_str()][i].IsString())
				{
					ret.push_back(_document[key.c_str()][i].GetString());
				}
			}

			return ret;
		}

		vector<int> GetArrayInteger(string key)
		{
			if(!_document.HasMember(key.c_str()))
			{
				throw runtime_error("Key : "+key+" not found");
			}

			vector<int> ret;

			for(SizeType i = 0 ; i < _document[key.c_str()].Size() ; i++)
			{
				if(_document[key.c_str()][i].IsInt())
				{
					ret.push_back(_document[key.c_str()][i].GetInt());
				}
			}

			return ret;
		}

		vector<double> GetArrayDouble(string key)
		{
			if(!_document.HasMember(key.c_str()))
			{
				throw runtime_error("Key : "+key+" not found");
			}

			vector<double> ret;

			for(SizeType i = 0 ; i < _document[key.c_str()].Size() ; i++)
			{
				if(_document[key.c_str()][i].IsDouble())
				{
					ret.push_back(_document[key.c_str()][i].GetDouble());
				}
			}

			return ret;
		}

	private:
		string _path;
		Document _document;
};

#endif