
#ifndef _NETFILTER_H
#define _NETFILTER_H

namespace libvmtrace
{
namespace net
{
	class NetFilter
	{
	public:
		virtual void Init(void) = 0;
		virtual void Loop(void) = 0;

		virtual void RegisterFilter(PacketFilter* pf) = 0;
		virtual void DeRegisterFilter(PacketFilter* pf) = 0;
	};
}
}

#endif

