#include <string>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sstream>
#include <iomanip>

#include "util/utils.hpp"

string hex_encode(uint8_t* key,unsigned int k)
{
	ostringstream str;
	str << setw(2) << setfill('0')  << hex;
	for(unsigned int i=0;i<k;i++)
	{
		str << setw(2) << setfill('0')  << hex << (int)key[i] << " ";
	}
	return str.str();
}

string hex_encode(char* key,unsigned int k)
{
	ostringstream str;
	for(unsigned int i=0;i<k;i++)
	{
		str << setw(2) << setfill('0')  << hex << (int)key[i] << " ";
	}
	return str.str();
}

void hex_decode(string key,uint8_t* out,unsigned int k)
{
	istringstream hex_chars_stream(key);
	//unsigned char ret[key.length()];
	unsigned int char_val,cntr=0;
	while (hex_chars_stream >> hex >> char_val)
	{
		out[cntr++]=(unsigned char)char_val;
	}
}


void hexdump(void *mem, unsigned int len) {
	unsigned int i, j;

	for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
	{
		/* print offset */
		if(i % HEXDUMP_COLS == 0)
		{
			printf("0x%06x: ", i);
		}

		/* print hex data */
		if(i < len)
		{
			printf("%02x ", 0xFF & ((char*)mem)[i]);
		}
		else /* end of block, just aligning for ASCII dump */
		{
			printf("   ");
		}

		/* print ASCII dump */
		if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
		{
			for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
			{
				if(j >= len) /* end of block, not really printing */
				{
					putchar(' ');
				}
				else if(isprint(((char*)mem)[j])) /* printable char */
				{
					putchar(0xFF & ((char*)mem)[j]);
				}
				else /* other char */
				{
					putchar('.');
				}
			}
			putchar('\n');
		}
	}
}

//return the hexdump as string instead of stdout :)
string hexdumptostring(void *aData, unsigned int aLength)
{
	//combination from http://www.i42.co.uk/stuff/hexdump.htm and https://github.com/gabime/spdlog/pull/236
	size_t aWidth = 16;
	ostringstream aStream;
	const char* const start = static_cast<const char*>(aData);
	const char* const end = start + aLength;
	const char* line = start;
	while (line != end)
	{
		aStream.width(4);
		aStream.fill('0');
		aStream << hex << line - start << " : ";
		size_t lineLength = min(aWidth, static_cast<size_t>(end - line));
		for (size_t pass = 1; pass <= 2; ++pass)
		{ 
			for (const char* next = line; next != end && next != line + aWidth; ++next)
			{
				char ch = *next;
				switch(pass)
				{
					case 1:
						aStream << (ch < 32 ? '.' : ch);
						break;
					case 2:
						if (next != line)
						aStream << " ";
						aStream.width(2);
						aStream.fill('0');
						aStream << hex << uppercase << static_cast<int>(static_cast<unsigned char>(ch));
						break;
				}
			}
			if (pass == 1 && lineLength != aWidth)
				aStream << string(aWidth - lineLength, ' ');
			aStream << " ";
		}
		aStream << endl;
		line = line + lineLength;
	}

	return aStream.str();
}

string exec(const char* cmd) {
	shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
	if (!pipe) return "ERROR";
	char buffer[128];
	string result = "";
	while(!feof(pipe.get())) {
		if(fgets(buffer, 128, pipe.get()) != NULL)
			result += buffer;
	}
	return result;
}

//http://bits.mdminhazulhaque.io/cpp/find-and-replace-all-occurrences-in-cpp-string.html
void find_and_replace(string& source, string const& find, string const& replace)
{
	for(string::size_type i = 0; (i = source.find(find, i)) != string::npos;)
	{
		source.replace(i, find.length(), replace);
		i += replace.length();
	}
}

// Taken from http://stackoverflow.com/questions/7724448/simple-json-string-escape-for-c/33799784#33799784
string escape_json(const string &s) {
	ostringstream o;
	for (auto c = s.cbegin(); c != s.cend(); c++) {
		if (*c == '"' || *c == '\\' || ('\x00' <= *c && *c <= '\x1f')) {
			o << "\\u"
			  << hex << setw(4) << setfill('0') << (int)*c;
		} else {
			o << *c;
		}
	}
	return o.str();
}