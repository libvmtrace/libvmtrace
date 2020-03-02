
#include <stdio.h>
#include <string.h>
#include <stdexcept>
#include <arpa/inet.h>
#include <sstream>
#include <map>

#include <net/Packet.hpp>
#include <net/IPv4Addr.hpp>
#include <util/utils.hpp>

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

namespace libvmtrace
{
namespace net
{
	// Thanks to http://seclists.org/bugtraq/1999/Mar/57
	unsigned short in_cksum(unsigned short* addr,int len)
	{
		int nleft = len;
		unsigned short* w = addr;
		int sum = 0;
		unsigned short answer = 0;

		while (nleft > 1)
		{
			sum += *w++;
			nleft -= 2;
		}
		if (nleft == 1)
		{
			*(u_char *)(&answer) = *(u_char *)w ;
			sum += answer;
		}

		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
		answer = ~sum;
		return answer;
	}

	Packet::Packet(unsigned char* data, size_t size)
	{
		this->size = size;
		this->data = new unsigned char[this->size];
		memset(this->data, 0, size);
		memcpy(this->data, data, size);
		ether_frame = NULL;
		ip_pack = NULL;
		tcp_pack = NULL;
		udp_pack = NULL;
	}

	Packet::~Packet()
	{
		delete[] this->data;
	}

	const IPv4Addr Packet::get_ipv4_src() const 
	{
		if (ip_pack == NULL)
			throw std::runtime_error("Not an IP Packet");

		return IPv4Addr(&ip_pack->ip_src);
	}

	const IPv4Addr Packet::get_ipv4_dst() const
	{
		if (ip_pack == NULL)
			throw std::runtime_error("Not an IP Packet");

		return IPv4Addr(&ip_pack->ip_dst);
	}

	uint16_t Packet::get_sport() const
	{
		if (tcp_pack == NULL)
			throw std::runtime_error("Not a TCP Packet");

		return ntohs(tcp_pack->th_sport);
	}

	uint16_t Packet::get_dport() const
	{
		if (tcp_pack == NULL)
			throw std::runtime_error("Not a TCP Packet");

		return ntohs(tcp_pack->th_dport);
	}

	bool Packet::is_syn() const
	{
		if (tcp_pack == NULL)
			return false;

		if ((tcp_pack->th_flags & TH_SYN) &&
			(tcp_pack->th_flags & TH_ACK) == 0)
			return true;

		return false;
	}

	bool Packet::is_synack() const
	{
		if (tcp_pack == NULL)
			return false;

		if (tcp_pack->th_flags & TH_SYN &&
			tcp_pack->th_flags & TH_ACK)
			return true;

		return false;
	}

	uint16_t Packet::compute_udp_checksum()
	{
		uint32_t sum = 0;
		size_t nbytes;

		size_t udp_data_size = htons(udp_pack->uh_len) - sizeof(struct udp_pack);
		size_t udp_size = sizeof(struct udp_pack) + udp_data_size;

		nbytes = sizeof(struct TCP_Pseudo) + udp_size;

		uint8_t *tcp = new unsigned char[nbytes]();

		struct TCP_Pseudo* pseudo = (struct TCP_Pseudo*)tcp;
		memcpy(&pseudo->src_ip, &ip_pack->ip_src, sizeof(struct in_addr));
		memcpy(&pseudo->dst_ip, &ip_pack->ip_dst, sizeof(struct in_addr));
		pseudo->zeros=0;
		pseudo->protocol=ip_pack->ip_p;
		pseudo->len = htons(sizeof(struct TCP_Pseudo) + udp_pack->uh_len);
		//pseudo->len = 0xffff;
		pseudo->len = htons(udp_size);

		memcpy(tcp+sizeof(struct TCP_Pseudo), udp_pack, htons(udp_pack->uh_len));

		struct udp_pack* up = (struct udp_pack*)(tcp+sizeof(struct TCP_Pseudo));
		up->uh_sum = 0;

		sum = in_cksum((unsigned short *)tcp, nbytes);

		delete[] tcp;
		return sum;
	}

	uint16_t Packet::compute_tcp_checksum()
	{
		uint32_t sum = 0;
		size_t nbytes;

		int tcp_opt_len = tcp_size - 20;
		int tcp_data_len = ntohs(ip_pack->ip_len) - ip_size - tcp_size;
		int totaltcp_len = sizeof(struct TCP_Pseudo) + sizeof(struct tcp_pack) + tcp_opt_len + tcp_data_len;

		//nbytes = sizeof(struct TCP_Pseudo) + tcp_size +  payload_size;
		nbytes = totaltcp_len;

		uint8_t *tcp = new unsigned char[nbytes]();

		struct TCP_Pseudo* pseudo = (struct TCP_Pseudo*)tcp;
		memcpy(&pseudo->src_ip, &ip_pack->ip_src, sizeof(struct in_addr));
		memcpy(&pseudo->dst_ip, &ip_pack->ip_dst, sizeof(struct in_addr));
		pseudo->zeros=0;
		pseudo->protocol=ip_pack->ip_p;
		pseudo->len = htons(sizeof(struct tcp_pack) + tcp_opt_len + payload_size);

		memcpy(tcp+sizeof(struct TCP_Pseudo), tcp_pack, tcp_size+payload_size);

		struct tcp_pack* tp = (struct tcp_pack*)(tcp+sizeof(struct TCP_Pseudo));
		tp->th_sum = 0;

		sum = in_cksum((unsigned short *)tcp, nbytes);

		delete[] tcp;
		return sum;
	}

	std::ostream& operator<<(std::ostream& strm, const libvmtrace::net::Packet* p)
	{
		if (p->is_ip())
		{
				const IPv4Addr s = p->get_ipv4_src();
				const IPv4Addr d = p->get_ipv4_dst();
				if (p->is_tcp())
					strm << s << ":" << p->get_sport() << " -> " << d << ":" << p->get_dport();
				else
					strm << s << " -> " << d ;
		}

		return strm;
	}

	void Packet::process(void)
	{
		ip_pack = (struct ip_pack*)data;
		ip_size = IP_HL(ip_pack) * 4;
		
		if (ip_size < 20)
		{
			std::cerr << "Invalid IP packet" << std::endl;
			ip_pack = NULL;
			return;
		}
		
		// IP Protocol TCP
		if (ip_pack->ip_p == 0x06) 
		{
			tcp_pack = (struct tcp_pack*) (data + ip_size);
			tcp_size = TH_OFF(tcp_pack) * 4;

			if (tcp_size < 20)
			{
				std::cerr << "Invalid TCP packet" << std::endl;
				tcp_pack = NULL;
				return;
			}
			
			payload = (unsigned char*)tcp_pack + tcp_size;
			payload_size = size -  ip_size - tcp_size;
		}
		else if (ip_pack->ip_p == 0x11) // IP protocol UDP
			udp_pack = (struct udp_pack*)(data +  ip_size);
	}

	std::string Packet::ToJson()
	{
		rapidjson::StringBuffer s;
		rapidjson::Writer<rapidjson::StringBuffer> writer(s);
		writer.StartObject();

		std::map<std::string, std::string> map;
		{
			const IPv4Addr s = get_ipv4_src();
			const IPv4Addr d = get_ipv4_dst();

			std::string temp = s;
			writer.Key("srcip");
			writer.String(temp.c_str());
			temp = d;
			writer.Key("dstip");
			writer.String(temp.c_str());
		}

		writer.Key("packet_size");
		writer.Uint(size);

		if (is_ip())
		{
				writer.Key("srcport");
				writer.Uint(get_sport());

				writer.Key("dstport");
				writer.Uint(get_dport());
		}

		writer.EndObject();
		return s.GetString();
	}
}
}

#undef IP_HL
#undef TH_OFF

