
#include <net/NetworkConnection.hpp>

using namespace libvmtrace::net;

namespace libvmtrace
{
namespace net
{
	bool operator==(const NetworkConnection& lhs, const NetworkConnection& rhs)
	{
		if (lhs.server == rhs.server && 
			lhs.client == rhs.client &&
			lhs.sport == rhs.sport &&
			lhs.cport == rhs.cport) 
			return true;

		if (lhs.server == rhs.client && 
			lhs.client == rhs.server &&
			lhs.sport == rhs.cport &&
			lhs.cport == rhs.sport) 
			return true;
		
		return false;
	}
}
}

std::ostream& operator<<(std::ostream& strm, const NetworkConnection* t)
{
	strm << "Server: " << t->GetSource() << ":" << t->GetSourcePort() << " ->  ";
	strm << "Client: " << t->GetDestination() << ":" << t->GetDestinationPort() << std::endl;
	return strm;
}

