#ifndef _NETMONITOR_H
#define _NETMONITOR_H
#include <iostream>
#include <sys/epoll.h>
#include "NetDev.hpp"
#include "NetFilter.hpp"

class NetMonitor : public NetFilter {
public:
    NetMonitor(const string& dev, const string& filter);
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
    list<PacketFilter*> filters;
    list<PacketFilter*> delete_filters;
 


};

#endif
// vim: tabstop=4 shiftwidth=4 expandtab 
