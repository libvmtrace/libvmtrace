
#include <iostream>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <chrono>
#include <thread>

#include <sys/epoll.h>

#include <net/NetDev.hpp>
#include <net/NetProxy.hpp>
#include <net/Packet.hpp>

namespace libvmtrace
{
namespace net
{
	NetProxy::NetProxy(const std::string& in_dev, const std::string& out_dev)
		: in(in_dev, true, ""), out(out_dev, true, ""),	stop(0)
	{
		in.setOutDevice(&out);
		out.setOutDevice(&in);
	}

	void NetProxy::Init(void)
	{
		epfd = epoll_create(10);
		if (epfd == -1)
		{
			std::cerr << "EPOLL init failed" << std::endl;
			throw -1;
		}

		fd_in = in.Listen();    
		ev.events = EPOLLIN;
		ev.data.fd = fd_in;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd_in, &ev) < 0)
		{
			std::cerr << "Could not monitor fd" << std::endl;
			throw -1;
		}

		fd_out = out.Listen();    
		ev.events = EPOLLIN;
		ev.data.fd = fd_out;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd_out, &ev) < 0)
		{
			std::cerr << "Could not monitor fd" << std::endl;
			throw -1;
		}
	}

	void NetProxy::Loop(void)
	{
		while(stop == 0) 
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	void NetProxy::Stop(void)
	{
		stop = 1;
	}

	NetProxy::~NetProxy(void)
	{
	}

	void NetProxy::RegisterFilter(PacketFilter* pf)
	{
		out.registerFilter(pf);
		in.registerFilter(pf);
	}

	void NetProxy::DeRegisterFilter(PacketFilter* pf)
	{
		out.deregisterFilter(pf);
		in.deregisterFilter(pf);
	}
}
}

