/*
tdsconn.h
1.判断数据的流向(cliect-->host  or  host-->client)
2.组包(当一个包跨多个流时，组成一个完整的包)
3.调用解析类来解析已经组好的包
*/
#pragma once
#include "TDSAnalysis.h"
#include <map>
#include <vector>
#include <memory>
#include "InfoTypeDef.h"


class PKTBuffer
{
public:
	PKTBuffer(uint32_t nSize);
	~PKTBuffer();

	unsigned char * getbuffer() { return m_pbuffer; }
	uint32_t getbuffersize() { return m_nSize; }

private:
	PKTBuffer();
	unsigned char * m_pbuffer;
	uint32_t m_nSize;
};
class TcpConn
{
public:
	uint64_t startTime;
	uint64_t lastTime;
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint16_t dstPort;
	uint16_t srcPort;

	TcpConn(){};
	~TcpConn(){};
	uint32_t m_connType;
	void setStartTime(uint64_t ms) { startTime = ms; };
	void setLastTime(uint64_t ms) { lastTime = ms; };

	void setIntSrcAddr(uint32_t addr) { srcAddr = addr; };
	void setIntDstAddr(uint32_t addr) { dstAddr = addr; };

	void setSrcPort(uint16_t port) { srcPort = port; };
	void setDstPort(uint16_t port) { dstPort = port; };
};

class TDSConn : public TcpConn
{
public:
	TDSConn(uint32_t srcaddr, uint16_t srcport, uint32_t destaddr, uint16_t destport, const uint64_t& ms);
	~TDSConn();
	TDSConn();
	virtual void process(bool c2sFlag, uint8_t* bpTCP, int tcpBodyLen, uint32_t sequence, uint32_t ack,
		const uint64_t& currentUsec, struct pcap_pkthdr& pkthdr);

private:
	
	void init();

	bool processC2S(uint8_t* bpTCP, int tcpBodyLen, uint32_t sequence, uint32_t ack, const uint64_t& currentUsec);
	bool processS2C(uint8_t* bpTCP, int tcpBodyLen, uint32_t sequence, uint32_t ack, const uint64_t& currentUsec);

private:
	uint64_t m_C2SStartTime;
	uint64_t m_C2SEndTime;
	uint64_t m_S2CStartTime;
	uint64_t m_S2CEndTime;

	uint32_t m_C2SStartSeq;
	uint32_t m_C2SNextSeq;
	uint32_t m_C2SAckSeq;
	uint32_t m_C2STdsPktLen;
	uint32_t m_C2STdsRecvLen;

	uint32_t m_S2CStartSeq;
	uint32_t m_S2CNextSeq;
	uint32_t m_S2CAckSeq;
	uint32_t m_S2CTdsPktLen;
	uint32_t m_S2CTdsRecvLen;

	//组包容器
	std::vector<std::shared_ptr<PKTBuffer> > m_C2SPktVec;
	std::vector<std::shared_ptr<PKTBuffer> > m_S2CPktVec;

	static TDSAnalysis m_TDSParse;
	const uint32_t CONNECT_TYPE_TDS = TDS73;
};

