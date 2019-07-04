#include <iostream>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdexcept>
#include <iomanip>
#include <netinet/in.h>
#include <sys/epoll.h>

#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>


#include "net/NetDev.hpp"
#include "net/Packet.hpp"
#include "net/PacketFilter.hpp"

#include "net/NetMonitor.hpp"
#include "util/utils.hpp"

static NetMonitor* nm = nullptr;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    int id= 0, len=0;
    struct nfqnl_msg_packet_hdr *ph;
    //struct ip_hdr *ip;
    uint8_t *payload=NULL;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    len = nfq_get_payload(nfa, &payload);
    if (len < 0) {
        fprintf(stderr, "Error getting payload\n");
        return len;
    }

    Packet p(payload, len);
    nm->ProcessPacket(&p);
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
}

void NetMonitor::ProcessPacket(Packet* p) {
    if (p == NULL)
        return;
    p->process();

    for(std::list<PacketFilter*>::iterator it=filters.begin(); it!=filters.end();++it) {
        if((*it)->filter(p)) {
            (*it)->callback(p);
        }
    }
    for(std::list<PacketFilter*>::iterator it=delete_filters.begin(); it!=delete_filters.end();++it) {
        filters.remove(*it);
    }
    delete_filters.clear();
}


NetMonitor::NetMonitor(const string& dev, const string& filter):
    stop_(0)
{
    nm=this;
}

NetMonitor::~NetMonitor(void) {
    nm=nullptr;
}

void NetMonitor::Init(void) {
    int queue_num = 0;

    //printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    //printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    //printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    //printf("binding this socket to queue '%d'\n", queue_num);
    qh = nfq_create_queue(h, queue_num, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    //printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

}


void NetMonitor::Loop(void) {
    char buf[4096] __attribute__ ((aligned));
    int fd, rv=0;
    if (!h)
    {
        Init();
    }
    
    fd = nfq_fd(h);
    while (!stop_) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
            nfq_handle_packet(h, buf, rv);
    }
    cout << "NetMonitor is going to die" << endl;


}

void NetMonitor::RegisterFilter(PacketFilter* pf) {
    filters.push_back(pf);
}
void NetMonitor::DeRegisterFilter(PacketFilter* pf) {
    delete_filters.push_back(pf);
}
void NetMonitor::Stop() {
    stop_ = 1;
    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

}

// vim: tabstop=4 shiftwidth=4 expandtab
