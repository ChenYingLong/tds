/*
 * packet.cpp
 *
 *  Created on: 2015-11-21
 *      Author: Yao Yuan
 */

#include <string.h>
#include <stdint.h>
#include <WinSock2.h>
#ifdef WIN32

#else
#include <arpa/inet.h>
#endif

#include "packet.h"
#include "trace.h"

const int RUNT_LEN = 34;//Refer http://www.erg.abdn.ac.uk/users/gorry/course/lan-pages/mac.html
const int OVERSIZE_LEN = 1518;

TDSPkt::TDSPkt(int nSize)
{
	if (nSize > 0)
	{
		tdspkt = new unsigned char[nSize];
		m_nSize = nSize;
	}
	else
	{
		tdspkt = NULL;
		m_nSize = 0;
	}
}
TDSPkt::~TDSPkt()
{
	if (tdspkt != NULL)
	{
		delete[] tdspkt;
		tdspkt = NULL;
	}
}
////////////////////////////////////////////////////////////////////////////////
// class Packet implementation
//
Packet::Packet(const struct pcap_pkthdr *h, const uint8_t *sp)
{
	pcapHeader = *h;
	packetData = new unsigned char[h->caplen + 1];
	if (packetData)
	{
		memcpy(packetData, sp, h->caplen);
		packetData[h->caplen] = 0;	// for safe string opertion like strstr
	}
}

Packet::~Packet()
{
	if (packetData != NULL)
	{
		delete[] packetData;
		packetData = NULL;
	}
}

int Packet::parsePacketHead()
{
	uint32_t capLen = pcapHeader.caplen;

	if (capLen < RUNT_LEN || capLen > OVERSIZE_LEN)
	{
		TRACE_WARNING("The packet length(%d) is not valid!\n", capLen);
		return PROTOCOL_UNKNOWN;
	}

	uint32_t offset = 14;

	short ethType = *(short*)(packetData + 12);

#define ETH_TYPE_IP		8
#define ETH_TYPE_VLAN		0x81
	if (ethType != ETH_TYPE_IP && ethType != ETH_TYPE_VLAN)
	{ // Not an (IP or 802.1q) Packet
		TRACE_WARNING("The type(%04X) of packet is not ETH or ETH_VLAN!\n", ethType);
		return PROTOCOL_UNKNOWN;
	}

	uint8_t protocol;

	if (ethType == ETH_TYPE_VLAN)
	{
		if (offset + IP_HDR_FIX_LEN > capLen)
		{
			TRACE_WARNING("The packet(VLAN) length(%d) is not valid!\n", capLen);
			return PROTOCOL_UNKNOWN;
		}
		//TRACE_WARNING("ETH_TYPE_VLAN \n");
		offset += 4;
		protocol = *(packetData + 27);
	}
	else
	{
		protocol = *(packetData + 23);
	}

	memcpy((void*)&ipHeader, packetData + offset, IP_HDR_FIX_LEN);
	uint32_t ipHeadLen = (*(packetData + offset) & 0xF) * 4;	//IHL
	uint32_t ipBodyLen = ntohs(ipHeader.ip_len);
	ipBodyLen -= ipHeadLen;
	offset += ipHeadLen;						//14+IHL

	//	uint32 tcpBodyLen = ipBodyLen;
	if (ipBodyLen > capLen - offset)
	{
		ipBodyLen = capLen - offset;
		/*	if (ipBodyLen < 0) {
				TRACE_WARNING("ipBodyLen(%d) < 0\n", ipBodyLen);
				return PROTOCOL_UNKNOWN;
				}*/
	}
	/*	if (tcpBodyLen + offset < RUNT_LEN
				|| tcpBodyLen + offset > OVERSIZE_LEN) {
				TRACE_WARNING("error packet, tcpbodylen=%d, offset=%d\n", tcpBodyLen,
				offset);
				return PROTOCOL_UNKNOWN;
				}
				*/
	ipHeader.ip_src = ntohl(ipHeader.ip_src);
	ipHeader.ip_dst = ntohl(ipHeader.ip_dst);

	if (protocol == 0x6)
	{ // TCP
		if (offset + TCP_HEADER_LEN > capLen)
		{
			TRACE_WARNING("The packet(tcp) length(%d) is not valid!\n", capLen);
			return PROTOCOL_UNKNOWN;
		}
		memcpy((void*)&tcpHeader, packetData + offset, TCP_HEADER_LEN);
		tcpHeader.th_sport = ntohs(tcpHeader.th_sport);
		tcpHeader.th_dport = ntohs(tcpHeader.th_dport);
		tcpHeader.th_seq = ntohl(tcpHeader.th_seq);
		tcpHeader.th_ack = ntohl(tcpHeader.th_ack);

		uint32_t tcpHeadLen = (*(packetData + offset + 12) >> 4) * 4; //TCPHdrLen
		offset += tcpHeadLen;  //EthFrmLen(14)+IHL+THL
		if (ipBodyLen < tcpHeadLen)
		{
			TRACE_WARNING("The packet(tcp) is not valid, capLen=%d, ipBodyLen=%d, tcpHeadLen=%d\n",
						  capLen, ipBodyLen, tcpHeadLen);
			return PROTOCOL_UNKNOWN;
		}
		tcpBody = packetData + offset;
		tcpBodySize = ipBodyLen - tcpHeadLen;
		return PROTOCOL_TCP;
	}
	else if (protocol == 0x11)
	{ // UDP
		if (offset + UDP_HEADER_LEN > capLen)
		{
			TRACE_WARNING("The packet(udp) length(%d) is not valid!\n", capLen);
			return PROTOCOL_UNKNOWN;
		}
		struct udphdr hdrUDP;
		memcpy((void*)&hdrUDP, packetData + offset, UDP_HEADER_LEN);
		hdrUDP.sport = ntohs(hdrUDP.sport);
		hdrUDP.dport = ntohs(hdrUDP.dport);
		return PROTOCOL_UDP;
	}
	else
	{
		return PROTOCOL_UNKNOWN; //not TCP packets;
	}
}

uint8_t *Packet::getPacketData()
{
	return packetData;
}
