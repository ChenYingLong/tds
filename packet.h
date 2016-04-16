/*
 * packet.h
 *
 *  Created on: 2015-11-21
 *      Author: Yao Yuan
 */

#ifndef _NG_PACKET_H_
#define _NG_PACKET_H_

#include <pcap.h>
#include <stdint.h>
//#include "common.h"

#define PROTOCOL_UNKNOWN	-1
#define PROTOCOL_TCP    	1
#define PROTOCOL_UDP		2

//在测试中发现一个包的最大长度是4096bytes
#define PACK_MAX_SIZE 0x1000

////////////////////////////////////////////////////////////////////////////////
//
// TCP header.
// Per RFC 793, September, 1981.
//
#define TCP_HEADER_LEN	20
struct tcphdr {
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	u_long th_seq; /* sequence number */
	u_long th_ack; /* acknowledgement number */
	u_char th_x2 :4; /* (unused) */
	u_char th_off :4; /* data offset */
	u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG)

	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

struct ipv4_hdr {
#define IP_HDR_FIX_LEN 20		    // the length of fix part in ip header
	u_char ip_hl :4; /* header length */
	u_char ip_v :4; /* version */
	u_char ip_tos; /* type of service */
	u_short ip_len; /* total length */
	u_short ip_id; /* identification */
	u_short ip_off; /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1FFF               /* mask for fragmenting bits */
	u_char ip_ttl; /* time to live */
	u_char ip_p; /* protocol */
	u_short ip_sum; /* checksum */
	u_long ip_src, ip_dst; /* source and dest address */
};

#define UDP_HEADER_LEN	8
struct udphdr {
	u_short sport; /* source port */
	u_short dport; /* destination port */
	u_short length; /* length */
	u_short checksum; /* checksum */
};

class Packet {
public:
	Packet(const struct pcap_pkthdr *h, const uint8_t *sp);
	~Packet();

	int parsePacketHead();
	uint8_t * getPacketData();

public:
	struct pcap_pkthdr pcapHeader;
	struct ipv4_hdr ipHeader;
	struct tcphdr tcpHeader;
	uint8_t * packetData;
	uint8_t * tcpBody;
	uint32_t tcpBodySize;
};

class TDSPkt
{

public:
	TDSPkt(int);
	~TDSPkt();
	uint8_t *getpkt() { return tdspkt; };
	int getbuffersize() { return m_nSize; }
private:
	TDSPkt() {};
	uint8_t *tdspkt;
	int m_nSize;
};
typedef TDSPkt* TDSPktPtr;


#endif
