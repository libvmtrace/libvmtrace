#ifndef NETDEV_H
#define NETDEV_H
#include <iostream>
#include <list>
#include <pcap/pcap.h>
#include <thread>
#include <mutex>
#include <condition_variable>


#include "net/Packet.hpp"
#include "net/PacketFilter.hpp"

//#define SNAP_LEN 65535
#define SNAP_LEN 2000

#define READER_THREADS 1
#define SENDER_THREADS 1

using namespace std;


class NetDev {
public:
    NetDev(const string& Name);
    NetDev(const string& Name, bool only_incoming, const std::string& filter);
    ~NetDev();
    int Listen() throw();
    Packet* readPacket(void);
    void Stop_Listen();
    string getName(void) const { return Name; } ;
    void process(Packet* p);
    void registerFilter(PacketFilter* pf);
    void deregisterFilter(PacketFilter* pf);

    void addPacket(Packet *);
    void ProcessPacket();

    bool stop() { if (stop_process_packets_ == 1) { return true; }; return false; }
    void setOutDevice(NetDev* nd) { outDevice_ = nd; }

private:
    NetDev(const NetDev&) {}
    NetDev& operator=(NetDev& nd);

    string Name;
    pcap_t* p;
    int fd[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen;
    int capbuf;
    list<PacketFilter*> filters;
    bool only_incoming;
    thread* packet_reader_[READER_THREADS];
    std::string filter_;

    
    
    list<Packet*> incoming;
    list<PacketFilter*> delete_filters;
    std::mutex* incoming_mutex;

    list<Packet*> process_packets_;    
    std::mutex process_packets_mutex_;
    std::condition_variable process_packets_signal_;
    int stop_process_packets_;
    thread process_packet_[SENDER_THREADS];

    NetDev* outDevice_;

};


#endif
// vim: tabstop=4 shiftwidth=4 expandtab 

