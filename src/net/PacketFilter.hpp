
#ifndef _PACKET_FILTER_H
#define _PACKET_FILTER_H

#include <net/Packet.hpp>

namespace libvmtrace
{
namespace net
{
	class PacketFilter
	{
	public:
		virtual bool filter(Packet*) = 0;
		virtual void callback(Packet*) = 0;
		virtual ~PacketFilter() = 0 ;
	};

	inline PacketFilter::~PacketFilter() {}
}
}

#endif
