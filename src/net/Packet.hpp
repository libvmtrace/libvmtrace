#ifndef PACKET_H
#define PACKET_H

#include <iostream>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <net/IPv4Addr.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

namespace libvmtrace
{
namespace net
{
	/* ethernet headers are always exactly 14 bytes [1] */
	constexpr auto SIZE_ETHERNET = 14;
	 
	/* Ethernet addresses are 6 bytes */
	constexpr auto ETHER_ADDR_LEN = 6;
	
	constexpr auto TH_FIN = 1;
	constexpr auto TH_SYN = 2;
	constexpr auto TH_ACK = 0x10; 

	struct TCP_Pseudo {
		struct in_addr src_ip; /* source ip */
		struct in_addr dst_ip; /* destination ip */
		uint8_t zeros; /* = 0 */
		uint8_t protocol; /* = 6 */
		uint16_t len; /* length of TCPHeader */
	} __attribute__ ((packed));

	/* Ethernet header */
	struct ethernet_frame {
		u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
		u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
		u_short ether_type;                     /* IP? ARP? RARP? etc */
	};
		
	/* IP header */
	struct ip_pack {
		u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
		u_char  ip_tos;                 /* type of service */
		u_short ip_len;                 /* total length */
		u_short ip_id;                  /* identification */
		u_short ip_off;                 /* fragment offset field */
		u_char  ip_ttl;                 /* time to live */
		u_char  ip_p;                   /* protocol */
		u_short ip_sum;                 /* checksum */
		struct  in_addr ip_src,ip_dst;  /* source and dest address */
	};
	 
	/* TCP header */
	typedef u_int tcp_seq;
	 
	struct tcp_pack {
		u_short th_sport;               /* source port */
		u_short th_dport;               /* destination port */
		tcp_seq th_seq;                 /* sequence number */
		tcp_seq th_ack;                 /* acknowledgement number */
		u_char  th_offx2;               /* data offset, rsvd */
		u_char  th_flags;
		u_short th_win;                 /* window */
		u_short th_sum;                 /* checksum */
		u_short th_urp;                 /* urgent pointer */
	};


	struct udp_pack {
		u_short uh_sport;               /* source port */
		u_short uh_dport;               /* destination port */
		u_short uh_len;               /* source port */
		u_short uh_sum;               /* destination port */
	};

	class Packet
	{
	public:
		Packet(unsigned char* data, size_t size);
		~Packet();

		const IPv4Addr get_ipv4_src() const ;
		const IPv4Addr get_ipv4_dst() const ;
		uint16_t get_sport() const ;
		uint16_t get_dport() const ;

		unsigned char* getData() { return data; }
		size_t getSize() { return size; };

		bool is_syn() const;
		bool is_synack() const;
		bool is_tcp() const { if (tcp_pack) { return true; }  return false; }
		bool is_ip() const { if (ip_pack) { return true; }  return false; }
		bool is_fin() const
		{ 
			if (tcp_pack && tcp_pack->th_flags & TH_FIN)
				return true;

			return false;
		}

		unsigned char* get_payload(void) { return payload; }
		unsigned int get_payload_size (void)
		{ 
			if (tcp_pack)
				return payload_size; 
			
			return 0;
		}

		tcp_seq get_seq_number(void)
		{
			if (tcp_pack)
				return htonl(tcp_pack->th_seq); 
			
			return 0;
		};

		void process();
		uint16_t compute_tcp_checksum();
		uint16_t compute_udp_checksum();

		std::string ToJson();
	private:
		size_t size;
		unsigned char* data;

		u_short ether_type;
		u_char ip_prot;
		uint8_t incoming;
		struct in_addr ip_src, ip_dst;
		uint16_t sport, dport, port;
		uint32_t seq, ack;
		uint16_t ip_len;

		struct ethernet_frame* ether_frame;

		struct ip_pack* ip_pack;
		unsigned int ip_size;

		struct tcp_pack* tcp_pack;
		unsigned int tcp_size;

		unsigned char* payload;
		unsigned int payload_size;

		struct udp_pack* udp_pack;
	};
}
}

std::ostream& operator<<(std::ostream& strm, const libvmtrace::net::Packet* p);

#endif

