
#ifndef _NETMONITOR_H
#define _NETMONITOR_H

#include <iostream>
#include <sys/epoll.h>
#include <net/NetDev.hpp>
#include <net/NetFilter.hpp>

namespace libvmtrace
{
namespace net
{
	class NetMonitor : public NetFilter
	{
	public:
		NetMonitor(const std::string& dev, const std::string& filter);
		void Init(void);
		void Loop(void);
		void Stop(void);
		void ProcessPacket(Packet*);

		void RegisterFilter(PacketFilter* pf);
		void DeRegisterFilter(PacketFilter* pf);

		~NetMonitor(void);

	private:
		int stop_;
		struct nfq_handle *h;
		struct nfq_q_handle *qh;
		std::list<PacketFilter*> filters;
		std::list<PacketFilter*> delete_filters;
	};
}
}

#endif
