#ifndef __ELASTICLOGGER_H__
#define __ELASTICLOGGER_H__

#include <string>
#include <sstream>
#include <iostream>
#include "util/Logging.hpp"

#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"

#include <curl/curl.h>

struct ElasticResponse
{
	bool error;
	vector<string> messages;
};

namespace
{
	size_t callback1(const char* in, size_t size, size_t num, string* out)
	{
		const size_t totalBytes(size * num);
		out->append(in, totalBytes);
		return totalBytes;
	}
}

class ElasticLogger : public Logger
{
	public:
		//url must be ended with /
		ElasticLogger(const string base_url) : _base_url(base_url), _ok(false)
		{
			_curl = curl_easy_init();

			unique_ptr<string> http_response(new string());

			curl_easy_setopt(_curl, CURLOPT_URL, _base_url.c_str());
			curl_easy_setopt(_curl, CURLOPT_WRITEFUNCTION, callback1);
			curl_easy_setopt(_curl, CURLOPT_WRITEDATA, http_response.get());

			_res = curl_easy_perform(_curl);

			long http_code = 0;
			curl_easy_getinfo(_curl, CURLINFO_RESPONSE_CODE, &http_code);

			if(http_code == 200)
			{
				// cout << *http_response.get() << endl;
				Document doc;
				doc.Parse((*http_response.get()).c_str());
				if(doc.HasParseError())
				{
					cout << "seems like not a json" << endl;
					_ok = false;
				}
				else
				{
					if(doc.HasMember("version"))
					{
						if(doc["version"].HasMember("number"))
						{
							_ok = true;
							_es_version = doc["version"]["number"].GetString();

							_curl_bulk = curl_easy_init();
							string tmp = _base_url+"_bulk";
							curl_easy_setopt(_curl_bulk, CURLOPT_URL, tmp.c_str());
							struct curl_slist *headers = NULL;
							headers = curl_slist_append(headers, "Accept: application/json");
							headers = curl_slist_append(headers, "Content-Type: application/json");
							headers = curl_slist_append(headers, "charsets: utf-8");
							curl_easy_setopt(_curl_bulk, CURLOPT_HTTPHEADER, headers);
						}
					}
				}
			}
			else
			{
				cout << "elasticsearch not reachable" << endl;
			}

			curl_easy_cleanup(_curl);
		}

		~ElasticLogger()
		{
			curl_easy_cleanup(_curl);
			curl_easy_cleanup(_curl_bulk);
			curl_global_cleanup();
		}

		void Log(const Entry* e);

		bool CheckIndex(const string index);
		bool CreateIndex(const string index, const string mappings);

		void BulkInsert(const string index, vector<string> datum);
		string Query(const string index, const string query, const string size, const string sort);
	private:
		string _base_url;
		bool _ok;

		CURL* _curl;
		CURLcode _res;

		CURL* _curl_bulk;

		string _es_version;
};

#endif