#ifndef _TCPCONNECTION_H
#define _TCPCONNECTION_H

#include <iostream>

#include "net/IPv4Addr.hpp"
#include "net/Packet.hpp"
#include "IPv4Addr.hpp"

class NetworkConnection {
public:
	NetworkConnection(const uint16_t family, const uint16_t type, const IPv4Addr& src, const IPv4Addr& dst, uint16_t sport, uint16_t dport):
		family(family),
		type(type),
		server(src),
		client(dst),
		sport(sport),
		cport(dport),
		server_seq(0),
		client_seq(0)
	{ }


	friend std::ostream& operator<<(ostream, const NetworkConnection*);
	friend bool operator==(const NetworkConnection& lhs, const NetworkConnection& rhs);

	IPv4Addr GetSource() const
	{
		return server;
	}

	IPv4Addr GetDestination() const
	{
		return client;
	}

	uint16_t GetSourcePort() const
	{
		return sport;
	}

	uint16_t GetDestinationPort() const
	{
		return cport;
	}


protected:
	uint16_t family, type;
	const IPv4Addr server, client;
	uint16_t sport, cport;
	tcp_seq server_seq, client_seq;
};


#endif

// vim: tabstop=4 shiftwidth=4 expandtab 
