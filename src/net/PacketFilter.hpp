#ifndef _PACKET_FILTER_H
#define _PACKET_FILTER_H

#include "net/Packet.hpp"

class PacketFilter {
public:
    virtual bool filter(Packet*) = 0;
    virtual void callback(Packet*) = 0;
    virtual ~PacketFilter() = 0 ;
};

inline PacketFilter::~PacketFilter() {}
//inline PacketFilter::~PacketFilter() {}
#endif
// vim: tabstop=4 shiftwidth=4 expandtab 
