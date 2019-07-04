#include <iostream>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <chrono>
#include <thread>

#include <sys/epoll.h>

#include "net/NetDev.hpp"
#include "net/NetProxy.hpp"
#include "net/Packet.hpp"

using namespace std;


NetProxy::NetProxy(const string& in_dev, const string& out_dev):
    in(in_dev, true, ""),
    out(out_dev, true, ""),
    stop(0)
{
    in.setOutDevice(&out);
    out.setOutDevice(&in);
}

void NetProxy::Init(void) {
	
    epfd = epoll_create(10);
	if (epfd == -1) {
		cerr << "EPOLL init failed" << endl;
        throw -1;
	}
	
    fd_in = in.Listen();    
    ev.events = EPOLLIN;
	ev.data.fd = fd_in;
    if ( epoll_ctl(epfd, EPOLL_CTL_ADD, fd_in, &ev) < 0) {
		cerr << "Could not monitor fd" << endl;
		throw -1;
	}

    fd_out = out.Listen();    
    ev.events = EPOLLIN;
	ev.data.fd = fd_out;
	if ( epoll_ctl(epfd, EPOLL_CTL_ADD, fd_out, &ev) < 0) {
		cerr << "Could not monitor fd" << endl;
		throw -1;
	}

}


void NetProxy::Loop(void) {
    
    while(stop==0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        
    }
#if 0
	int i, nfds;
    char tmp;
    while(stop==0) {
        nfds = epoll_wait(epfd, events, sizeof(events), -1);
        for (i = 0; i<nfds; i++) {
            Packet* p  = NULL;
            if (events[i].data.fd == fd_in) {
                read(fd_in, &tmp, 1);
                while ((p = in.readPacket()) != NULL) {
                    out.process(p); 
                }
            } else {
                read(fd_out, &tmp, 1);
                while ((p = out.readPacket()) != NULL) {
                    in.process(p); 
                }
            }
        }
    }
#endif
}

void NetProxy::Stop(void) {
    stop=1;
}

NetProxy::~NetProxy(void) {
}


void NetProxy::RegisterFilter(PacketFilter* pf) {
    out.registerFilter(pf);
    in.registerFilter(pf);

}
void NetProxy::DeRegisterFilter(PacketFilter* pf) {
    out.deregisterFilter(pf);
    in.deregisterFilter(pf);
}

/*
int main() {
    string indev = "wlan0";
    string outdev = "eth0";
    NetProxy np = NetProxy(indev, outdev);
    np.Init();
    PacketFilter* pf = new TLSFilter(&np);
    np.RegisterIncomingFilter(pf);

    np.Forward();

}
*/
	
// vim: tabstop=4 shiftwidth=4 expandtab 
