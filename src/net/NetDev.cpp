#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <sys/epoll.h>

#include <list>
#include <thread>
#include <chrono>
#include <mutex>
#include <ctime>
#include <condition_variable>
#include <iomanip>

#include "net/NetDev.hpp"
#include "net/Packet.hpp"
#include "net/PacketFilter.hpp"
#include "util/utils.hpp"


static void process_packet(NetDev*);


static void read_loop(NetDev* nd, std::string Name, bool only_incoming, const std::string filter) {
    struct pcap_pkthdr* header;
    const u_char* data;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 netp =0;        /* ip                        */   
    
    pcap_t* p;

    if ( (p = pcap_create(Name.c_str(), errbuf)) == NULL) {
        throw std::runtime_error(string("can't open ") + Name ) ; 
    }

    if (pcap_set_promisc(p, 1)) {
        throw std::runtime_error(string("pcap_set_promisc failed") );
    }
    if (pcap_set_snaplen(p, SNAP_LEN)) {
        throw std::runtime_error("pcap_set_snaplen failed");
    }
    if (pcap_set_buffer_size(p, 1024*1024)) {
        throw std::runtime_error("pcap_set_buffer_size");
    }
    if (pcap_activate(p)) { 
        throw std::runtime_error(string("pcap_activate ") + strerror(errno));
    }

    if (only_incoming && pcap_setdirection(p, PCAP_D_IN)) {
        throw std::runtime_error(string("pcap_setdirection ") + strerror(errno));
    }
    if (filter.size() > 0 ) {
        if(pcap_compile(p,&fp,filter.c_str(),0,netp) == -1) {
            throw std::runtime_error(string("pcap_compile ") + strerror(errno));
        }
        if(pcap_setfilter(p,&fp) == -1) {
            throw std::runtime_error(string("pcap_setfilter ") + strerror(errno));
        }
    }
    cout << "start listening on " << Name << " with filter [ " << filter << " ] " <<endl;
    while (!nd->stop()) {
        if (pcap_next_ex(p, &header, &data) == 1) {
            Packet* p = new Packet((unsigned char*)data, header->len);
            nd->addPacket(p);
        }
    }
    pcap_close(p);
}



NetDev::NetDev(const string& Name):
    Name(Name),
    only_incoming(false),
    filter_("")
{
   stop_process_packets_ = 0;
   incoming_mutex = new std::mutex();
   for (size_t i =0; i<SENDER_THREADS; i++)
    process_packet_[i] = std::thread(process_packet, this);
   outDevice_ = nullptr;
}

NetDev::NetDev(const string& Name, bool only_incoming, const std::string& filter):
    Name(Name),
    only_incoming(only_incoming),
    filter_(filter)
{
    stop_process_packets_ = 0;
    incoming_mutex = new std::mutex();
    for (size_t i =0; i<SENDER_THREADS; i++)
        process_packet_[i] = std::thread(process_packet, this);
    outDevice_ = nullptr;

}

NetDev::~NetDev(void) {
    stop_process_packets_ = 1;
    process_packets_signal_.notify_all();


    for (size_t i =0; i<READER_THREADS; i++)
        packet_reader_[i]->join();

    if (incoming_mutex)
        delete incoming_mutex;
    process_packet_[0].join();

}

int NetDev::Listen() throw() {
    pipe(fd);
    

    //worker = new std::thread (pcap_loop, p, -1, cb, (u_char*)this);
    for (size_t i =0; i<READER_THREADS; i++)
        packet_reader_[i] = new std::thread (read_loop, this, Name,
                only_incoming, filter_ );


    return fd[0];
}

void NetDev::Stop_Listen() {
    //FIXME: destory worker
 //       if (p) pcap_close(p);
 //       if (fd > 0) close(fd);
}

void NetDev::addPacket(Packet* p) {
    if (outDevice_ == nullptr) {
        incoming_mutex->lock();
        incoming.push_back(p);
        incoming_mutex->unlock();
        write(fd[1], "0", 1);
    } else {
        outDevice_->process(p);
    }
	
}


Packet* NetDev::readPacket(void) 
{
    Packet* p;
    incoming_mutex->lock();
    if (incoming.empty()) {
        p = NULL;
    } else {
        p =  incoming.front();    
        incoming.pop_front();
    }
    incoming_mutex->unlock();
    return p;
}


void NetDev::process(Packet* p) {

    { 
        std::lock_guard<std::mutex> lk(process_packets_mutex_);
        process_packets_.push_back(p);
    }
    process_packets_signal_.notify_one();
}

void NetDev::registerFilter(PacketFilter* pf) {
    filters.push_back(pf);
}

void NetDev::deregisterFilter(PacketFilter* pf) {
    delete_filters.push_back(pf);
}

std::ostream& operator<<(std::ostream &strm, const NetDev &nd) {
    return strm << nd.getName();
    
}

static void process_packet(NetDev* nd) {
    nd->ProcessPacket();
}

void NetDev::ProcessPacket() {
    std::list<Packet*>* l = &process_packets_;
    
    pcap_t* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ( (pcap = pcap_create(Name.c_str(), errbuf)) == NULL) {
        throw std::runtime_error(string("can't open ") + Name ) ; 
    }
    if (pcap_activate(pcap)) { 
        throw std::runtime_error(string("pcap_activate ") + strerror(errno));
    }

    cout << "initialized net outprocesser " << endl; 
    while(stop_process_packets_ == 0) { 
        Packet* p = nullptr;
        {
            std::unique_lock<std::mutex> lk(process_packets_mutex_);
            process_packets_signal_.wait(lk, [l] {  return l->size() > 0; });

            p = process_packets_.front();
            process_packets_.pop_front();
        }
        p->process();
        
        if ( p == nullptr)
            continue;
    
        for(std::list<PacketFilter*>::iterator it=filters.begin(); it!=filters.end(); ++it) {
            if((*it)->filter(p)) {
                (*it)->callback(p);
            }
        }
        // TODO: delete filters
        if (pcap_inject(pcap, p->getData(), p->getSize())==-1) {
            cerr << "Could not inject packet (" << p->getSize()<< ")" ;
            cerr << p << endl;
            pcap_perror(pcap,0);
        }
        delete p;

    }
    pcap_close(pcap);
}
// vim: tabstop=4 shiftwidth=4 expandtab 
