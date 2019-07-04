#ifndef __UTILS_H
#define __UTILS_H
#define HEXDUMP_COLS 16

#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>

using namespace std;

string  hex_encode(uint8_t* key,unsigned int k);
string  hex_encode(char* key,unsigned int k);
void  hex_decode(string key,uint8_t* out,unsigned int k);

void hexdump(void *mem, unsigned int len);
string hexdumptostring(void *mem, unsigned int len);
string exec(const char* cmd);
string escape_json(const string &s);

//http://bits.mdminhazulhaque.io/cpp/find-and-replace-all-occurrences-in-cpp-string.html
void find_and_replace(string& source, string const& find, string const& replace);

template<typename TimeT = chrono::milliseconds>
struct measure
{
	template<typename F, typename ...Args>
	static typename TimeT::rep execution(F&& func, Args&&... args)
	{
		auto start = chrono::steady_clock::now();
		forward<decltype(func)>(func)(forward<Args>(args)...);
		auto duration = chrono::duration_cast< TimeT>
		(chrono::steady_clock::now() - start);
		return duration.count();
	}
};

template< typename T > string int_to_hex( T i )
{
  stringstream stream;
  stream << "0x" 
		 << setfill ('0') << setw(sizeof(T)*2) 
		 << hex << i;
  return stream.str();
}

#endif