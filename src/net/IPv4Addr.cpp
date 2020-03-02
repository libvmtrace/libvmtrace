
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>
#include <net/IPv4Addr.hpp>

namespace libvmtrace
{
namespace net
{
	IPv4Addr::IPv4Addr(const struct in_addr* buf)
	{
		memcpy(&addr, buf, sizeof(struct in_addr));
	}

	IPv4Addr::IPv4Addr(const IPv4Addr& other)
	{
		memcpy(&addr, &other.addr, sizeof(struct in_addr));
	}

	IPv4Addr::operator std::string() const 
	{
		char addr_str[128];
		char* tmp = inet_ntoa(addr);
		if (tmp)
			strcpy(addr_str, tmp);
		return std::string(addr_str);
	}
	
	std::ostream& operator<<(std::ostream& strm, const IPv4Addr& p)
	{
		char addr_str[128];
		char* tmp = inet_ntoa(p.addr);
		if (tmp)
			strcpy(addr_str, tmp);

		return strm << addr_str;
	}

	bool operator==(const IPv4Addr& lhs, const IPv4Addr& rhs)
	{
		if (memcmp((void*)&lhs.addr, (void*)&rhs.addr, sizeof(struct in_addr)) == 0)
			return true;
		return false;
	}
}
}


