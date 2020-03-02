
#ifndef IPV4ADDR
#define IPV4ADDR

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <iostream>

namespace libvmtrace
{
namespace net
{
class IPv4Addr
{
public:
	IPv4Addr(const IPv4Addr& addr );
	IPv4Addr(const struct in_addr* buf);

	operator std::string() const;    
	friend bool operator==(const IPv4Addr& lhs, const IPv4Addr& rhs);
	friend std::ostream& operator<<(std::ostream&, const IPv4Addr&);

private:
	struct in_addr addr;
};

bool operator==(const IPv4Addr& lhs, const IPv4Addr& rhs);
std::ostream& operator<<(std::ostream& strm, const IPv4Addr* p);
}
}


#endif

