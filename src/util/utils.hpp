
#ifndef __UTILS_H
#define __UTILS_H

#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace libvmtrace
{
namespace util
{
	constexpr auto HEXDUMP_COLS = 16;
	std::string hex_encode(uint8_t* key, unsigned int k);
	std::string hex_encode(char* key, unsigned int k);
	void hex_decode(std::string key, uint8_t* out, unsigned int k);

	void hexdump(void* mem, unsigned int len);
	std::string hexdumptostring(void *mem, unsigned int len);
	std::string exec(const char* cmd);
	std::string escape_json(const std::string &s);

	// http://bits.mdminhazulhaque.io/cpp/find-and-replace-all-occurrences-in-cpp-string.html
	void find_and_replace(std::string& source, std::string const& find, std::string const& replace);

	template<typename TimeT = std::chrono::milliseconds>
	struct measure
	{
		template<typename F, typename ...Args>
		static typename TimeT::rep execution(F&& func, Args&&... args)
		{
			auto start = std::chrono::steady_clock::now();
			std::forward<decltype(func)>(func)(std::forward<Args>(args)...);
			auto duration = std::chrono::duration_cast< TimeT>
			(std::chrono::steady_clock::now() - start);
			return duration.count();
		}
	};

	template <typename T>
	std::string int_to_hex(T i)
	{
		std::stringstream stream;
		stream << "0x" 
			<< std::setfill ('0') << std::setw(sizeof(T)*2) 
			<< std::hex << i;
		return stream.str();
	}
}
}

#endif
