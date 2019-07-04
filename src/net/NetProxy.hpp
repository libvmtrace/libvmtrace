#ifndef NETPROXY_H
#define NETPROXY_H

#include "net/PacketFilter.hpp"
#include "net/NetFilter.hpp"

class NetProxy : public NetFilter {
public:
    NetProxy(const string& input_dev, const string& output_dev);
    void Init(void);
    void Loop(void);
    void Stop(void);
    void RegisterOutgoingFilter(PacketFilter* pf) { in.registerFilter(pf);}; 
    void DeRegisterOutgoingFilter(PacketFilter* pf) { in.deregisterFilter(pf);}; 
    void RegisterIncomingFilter(PacketFilter* pf) { out.registerFilter(pf);}; 
    void DeRegisterIncomingFilter(PacketFilter* pf) { out.deregisterFilter(pf);}; 

    void RegisterFilter(PacketFilter* pf);
    void DeRegisterFilter(PacketFilter* pf);

    ~NetProxy(void);

private:
    NetProxy(const NetProxy&); 

    NetDev in, out;
    int fd_in, fd_out;
    struct epoll_event ev, ev2, events[3];
    int epfd;
    int stop;
};
#endif
// vim: tabstop=4 shiftwidth=2 expandtab 

