#include <pcap.h>
#include "tdsconn.h"
#include "trace.h"
#include "packet.h"

TDSAnalysis TDSConn::m_TDSParse = TDSAnalysis();
PKTBuffer::PKTBuffer()
{}

PKTBuffer::PKTBuffer(uint32_t nSize)
{
	if (nSize > 0)
	{
		m_pbuffer = new unsigned char[nSize];
		m_nSize = nSize;
	}
	else
	{
		m_pbuffer = NULL;
		m_nSize = 0;
	}
}

PKTBuffer::~PKTBuffer()
{
	if (m_pbuffer != NULL)
	{
		delete[] m_pbuffer;
		m_pbuffer = NULL;
	}
}


TDSConn::TDSConn()
{}


TDSConn::~TDSConn()
{}

TDSConn::TDSConn(uint32_t srcaddr, uint16_t srcport, uint32_t destaddr, uint16_t destport, const uint64_t& ms)
{
	m_connType = CONNECT_TYPE_TDS;

	setStartTime(ms);
	setLastTime(ms);
	setIntSrcAddr(srcaddr);
	setSrcPort(srcport);
	setIntDstAddr(destaddr);
	setDstPort(destport);

	init();
}

void TDSConn::init()
{
	m_C2SStartTime = 0;
	m_C2SEndTime = 0;
	m_S2CStartTime = 0;
	m_S2CEndTime = 0;

	m_C2SStartSeq = 0;
	m_C2SNextSeq = 0;
	m_C2SAckSeq = 0;
	m_C2STdsPktLen = 0;
	m_C2STdsRecvLen = 0;

	m_S2CStartSeq = 0;
	m_S2CNextSeq = 0;
	m_S2CAckSeq = 0;
	m_S2CTdsPktLen = 0;
	m_S2CTdsRecvLen = 0;
}


void TDSConn::process(bool c2sFlag, uint8_t* bpTCP, int tcpBodyLen, uint32_t sequence, uint32_t ack,
					  const uint64_t& currentUsec, struct pcap_pkthdr& pkthdr)
{
	if (tcpBodyLen > 0)
	{//数据包
		if (tcpBodyLen < 8)
		{
			TRACE_INFO("tcp body len = %d, pcap caplen = %u.\n", tcpBodyLen, pkthdr.caplen);
		}

		if (c2sFlag)
		{//client to server
			processC2S(bpTCP, tcpBodyLen, sequence, ack, currentUsec);
		}
		else
		{//server to client
			processS2C(bpTCP, tcpBodyLen, sequence, ack, currentUsec);
		}

	}
	else
	{//非数据包
		TRACE_DETAIL("tcp body len = %d, pcap caplen = %u.\n", tcpBodyLen, pkthdr.caplen);
	}
}


bool TDSConn::processC2S(uint8_t* bpTCP, int tcpBodyLen, uint32_t sequence, uint32_t ack, const uint64_t& currentUsec)
{
	if (0 == m_C2SStartSeq)
	{
		m_C2SStartSeq = sequence;
		m_C2SNextSeq = sequence + tcpBodyLen;
		m_C2SAckSeq = ack;

		//setStartTime(currentUsec);
		m_C2SStartTime = currentUsec;
		m_C2SEndTime = currentUsec;

		if (tcpBodyLen < 8)
		{//小于TDS头的长度
			TRACE_INFO("C2S recv first tcp body len: %u < 8 bytes len.\n", tcpBodyLen);
			return false;
		}

		uint16_t tdslen = 0;
		memcpy(&tdslen, bpTCP + 2, sizeof(tdslen));
		tdslen = ntohs(tdslen);
		if (tdslen == tcpBodyLen)
		{//完整的tds包，弹出至TDS包解析
			TRACE_DETAIL("C2S recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
			TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
			memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
			m_TDSParse.processpkt(tdspkt);
		}
		else if (tdslen > tcpBodyLen)
		{//不完整，还有后续包
			m_C2STdsPktLen = tdslen;
			m_C2STdsRecvLen = tcpBodyLen;
			std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
			memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

			m_C2SPktVec.clear();
			m_C2SPktVec.push_back(pPkt);

			TRACE_INFO("C2S recv first tds len: %u > tcp body len is: %u.\n", tdslen, tcpBodyLen);
		}
		else
		{//出错
			TRACE_WARNING("C2S recv tds len: %u < tcp body len is: %u!\n", tdslen, tcpBodyLen);
		}
	}
	else
	{//0 != m_C2SStartSeq
		if (sequence == m_C2SNextSeq)
		{//顺序包，正常处理
			if (tcpBodyLen < 8)
			{
				m_C2SStartSeq = sequence;
				m_C2SNextSeq = sequence + tcpBodyLen;
				m_C2SAckSeq = ack;
				m_C2SEndTime = currentUsec;
				TRACE_INFO("C2S recv tcp body len: %u < 8 bytes len.\n", tcpBodyLen);
				return false;
			}
			if (m_C2STdsPktLen > 0)
			{//上一个包为tcp pdu
				uint32_t nRecvLen = m_C2STdsRecvLen + tcpBodyLen;
				if (m_C2STdsPktLen == nRecvLen)
				{//tds包收全，弹出至TDS包解析
					TRACE_DETAIL("C2S recv total tds len: %u, current tcp body len is: %u.\n", m_C2STdsPktLen, tcpBodyLen);
					TDSPktPtr tdspkt(new TDSPkt(m_C2STdsPktLen));
					uint32_t nSize = 0;
					for (size_t i = 0; i < m_C2SPktVec.size(); i++)
					{
						memcpy(tdspkt->getpkt() + nSize, m_C2SPktVec[i]->getbuffer(), m_C2SPktVec[i]->getbuffersize());
						nSize += m_C2SPktVec[i]->getbuffersize();
					}
					memcpy(tdspkt->getpkt() + nSize, bpTCP, tcpBodyLen);
					//post tds pkt 
					m_TDSParse.processpkt(tdspkt);

					m_C2STdsPktLen = 0;
					m_C2STdsRecvLen = 0;
				}
				else if (m_C2STdsPktLen > nRecvLen)
				{//暂未收全，继续收
					TRACE_INFO("C2S recv part of tds len: %u, current tcp body len is: %u.\n", m_C2STdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);
					m_C2SPktVec.push_back(pPkt);

					m_C2STdsRecvLen += tcpBodyLen;
				}
				else
				{//出错(可能是粘包)
					TRACE_WARNING("C2S recv tds pkt len: %u < total recv len is: %u!\n", m_C2STdsPktLen, nRecvLen);
					//粘包处理
					uint32_t nLeftLen = nRecvLen - m_C2STdsPktLen;

					TDSPktPtr tdspkt(new TDSPkt(m_C2STdsPktLen));
					uint32_t nSize = 0;
					for (size_t i = 0; i < m_C2SPktVec.size(); i++)
					{
						memcpy(tdspkt->getpkt() + nSize, m_C2SPktVec[i]->getbuffer(), m_C2SPktVec[i]->getbuffersize());
						nSize += m_C2SPktVec[i]->getbuffersize();
					}
					memcpy(tdspkt->getpkt() + nSize, bpTCP, tcpBodyLen - nLeftLen);
					//post tds pkt 弹出前面完整包
					m_TDSParse.processpkt(tdspkt);

					//处理余下的数据
					//余下的可能是无用的数据，要检查有没有此包类型，长度是否合理等，如果不合理，直接丢弃？
					uint16_t left_tdslen = 0;

					memcpy(&left_tdslen, bpTCP + tcpBodyLen - nLeftLen + 2, sizeof(left_tdslen));
					left_tdslen = ntohs(left_tdslen);

                    if (nLeftLen < 8)
                    {//不足一个包的长度
                        TRACE_WARNING("C2S recv tds pkt len < %u\n", nRecvLen);
                        return false;
                    }
                    if (left_tdslen > PACK_MAX_SIZE)
                    { // 长度大于PACK_MAX_SIZE，不是TDS包
                        TRACE_ERROR("C2S recv tds left pkt len: %u > PACK_MAX_SIZE: %u!\n", left_tdslen, PACK_MAX_SIZE);
                        return false;
                    }

					if (left_tdslen == nLeftLen)
					{//余下的数据为完整TDS包
						TRACE_DETAIL("C2S recv tds left len: %u == tcp body left len is: %u.\n", left_tdslen, nLeftLen);
						TDSPktPtr tdspkt(new TDSPkt(nLeftLen));
						memcpy(tdspkt->getpkt(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);
						m_TDSParse.processpkt(tdspkt);

						m_C2STdsPktLen = 0;
						m_C2STdsRecvLen = 0;
					}
					else if (left_tdslen > nLeftLen)
					{//余下的数据为部分TDS包
						m_C2STdsPktLen = left_tdslen;
						m_C2STdsRecvLen = nLeftLen;
						std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(nLeftLen));
						memcpy(pPkt->getbuffer(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);

						m_C2SPktVec.clear();
						m_C2SPktVec.push_back(pPkt);
					}
					else
					{//出错啦 
						TRACE_ERROR("C2S recv tds left pkt len: %u < tcp body left len is: %u!\n", left_tdslen, nLeftLen);

						m_C2STdsPktLen = 0;
						m_C2STdsRecvLen = 0;
					}
				}
			}
			else
			{//m_C2STdsPktLen == 0
				uint16_t tdslen = 0;
				memcpy(&tdslen, bpTCP + 2, sizeof(tdslen));
				tdslen = ntohs(tdslen);
				TRACE_DETAIL("C2S recv tds len: %u, tcp body len is: %u.\n", tdslen, tcpBodyLen);
				if (tdslen == tcpBodyLen)
				{//完整的tds包，弹出至TDS包解析
					TRACE_DETAIL("C2S recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
					TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
					memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
					m_TDSParse.processpkt(tdspkt);

				}
				else if (tdslen > tcpBodyLen)
				{//不完整，还有后续包
					m_C2STdsPktLen = tdslen;
					m_C2STdsRecvLen = tcpBodyLen;
					TRACE_INFO("C2S recv first part of tds len: %u, current tcp body len is: %u.\n", m_C2STdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

					m_C2SPktVec.clear();
					m_C2SPktVec.push_back(pPkt);
				}
				else
				{//出错
					TRACE_WARNING("C2S recv tds len: %u < tcp body len is: %u!\n", tdslen, tcpBodyLen);
				}

			}

			m_C2SStartSeq = sequence;
			m_C2SNextSeq = sequence + tcpBodyLen;
			m_C2SAckSeq = ack;
			m_C2SEndTime = currentUsec;
		}
		else
		{//sequence != m_C2SNextSeq
			if (sequence < m_C2SNextSeq)
			{//重发包，忽略
				TRACE_INFO("C2S recv sequence: %u < next seq is: %u.\n", sequence, m_C2SNextSeq);
			}
			else
			{//丢包，后包先到，此处暂不处理
				TRACE_WARNING("C2S recv sequence: %u > next seq is: %u!\n", sequence, m_C2SNextSeq);
			}
		}
	}

	return true;
}
bool TDSConn::processS2C(uint8_t* bpTCP, int tcpBodyLen, uint32_t sequence, uint32_t ack, const uint64_t& currentUsec)
{
	if (0 == m_S2CStartSeq)
	{
		m_S2CStartSeq = sequence;
		m_S2CNextSeq = sequence + tcpBodyLen;
		m_S2CAckSeq = ack;

		//setStartTime(currentUsec);
		m_S2CStartTime = currentUsec;
		m_S2CEndTime = currentUsec;

		if (tcpBodyLen < 8)
		{//小于TDS头的长度
			TRACE_INFO("S2C recv first tcp body len: %u < 8 bytes len.\n", tcpBodyLen);
			return false;
		}

		uint16_t tdslen = 0;
		//memcpy(&tdslen, bpTCP, sizeof(tdslen));
		memcpy(&tdslen, bpTCP + 2, sizeof(tdslen));//tds第二三字节为长度
		tdslen = ntohs(tdslen);
		if (tdslen == tcpBodyLen)
		{//完整的tds包，弹出至TDS包解析
			TRACE_DETAIL("S2C recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
			TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
			memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
			m_TDSParse.processpkt(tdspkt);
		}
		else if (tdslen > tcpBodyLen)
		{//不完整，还有后续包
			m_S2CTdsPktLen = tdslen;
			m_S2CTdsRecvLen = tcpBodyLen;
			std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
			memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

			m_S2CPktVec.clear();
			m_S2CPktVec.push_back(pPkt);

			TRACE_INFO("S2C recv first tds len: %u > tcp body len is: %u.\n", tdslen, tcpBodyLen);
		}
		else
		{//出错
			TRACE_WARNING("S2C recv tds len: %u < tcp body len is: %u!\n", tdslen, tcpBodyLen);
		}
	}
	else
	{
		if (sequence == m_S2CNextSeq)
		{//顺序包，正常处理
			if (tcpBodyLen < 8)
			{
				m_S2CStartSeq = sequence;
				m_S2CNextSeq = sequence + tcpBodyLen;
				m_S2CAckSeq = ack;
				m_S2CEndTime = currentUsec;
				TRACE_INFO("S2C recv tcp body len: %u < 8 bytes len.\n", tcpBodyLen);
				return false;
			}
			if (m_S2CTdsPktLen > 0)
			{//上一个包为tcp pdu
				uint32_t nRecvLen = m_S2CTdsRecvLen + tcpBodyLen;
				if (m_S2CTdsPktLen == nRecvLen)
				{//tds包收全，弹出至TDS包解析
					TRACE_DETAIL("S2C recv total tds len: %u, current tcp body len is: %u.\n", m_S2CTdsPktLen, tcpBodyLen);
					TDSPktPtr tdspkt(new TDSPkt(m_S2CTdsPktLen));
					uint32_t nSize = 0;
					for (size_t i = 0; i < m_S2CPktVec.size(); i++)
					{
						memcpy(tdspkt->getpkt() + nSize, m_S2CPktVec[i]->getbuffer(), m_S2CPktVec[i]->getbuffersize());
						nSize += m_S2CPktVec[i]->getbuffersize();
					}
					memcpy(tdspkt->getpkt() + nSize, bpTCP, tcpBodyLen);
					//post tds pkt 
					m_TDSParse.processpkt(tdspkt);

					m_S2CTdsPktLen = 0;
					m_S2CTdsRecvLen = 0;
				}
				else if (m_S2CTdsPktLen > nRecvLen)
				{//暂未收全，继续收
					TRACE_INFO("S2C recv part of tds len: %u, current tcp body len is: %u.\n", m_S2CTdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);
					m_S2CPktVec.push_back(pPkt);

					m_S2CTdsRecvLen += tcpBodyLen;
				}
				else
				{//出错(可能是粘包)
					TRACE_WARNING("S2C recv tds pkt len: %u < total recv len is: %u!\n", m_S2CTdsPktLen, nRecvLen);
					//粘包处理
					uint32_t nLeftLen = nRecvLen - m_S2CTdsPktLen;

					TDSPktPtr tdspkt(new TDSPkt(m_S2CTdsPktLen));
					uint32_t nSize = 0;
					for (size_t i = 0; i < m_S2CPktVec.size(); i++)
					{
						memcpy(tdspkt->getpkt() + nSize, m_S2CPktVec[i]->getbuffer(), m_S2CPktVec[i]->getbuffersize());
						nSize += m_S2CPktVec[i]->getbuffersize();
					}
					memcpy(tdspkt->getpkt() + nSize, bpTCP, tcpBodyLen - nLeftLen);
					//post tds pkt 弹出前面完整包
					m_TDSParse.processpkt(tdspkt);

					//处理余下的数据
					uint16_t left_tdslen = 0;
					memcpy(&left_tdslen, bpTCP + tcpBodyLen - nLeftLen + 2, sizeof(left_tdslen));
					left_tdslen = ntohs(left_tdslen);

                    if (nLeftLen < 8)
                    {// 不足一个包的长度
                        TRACE_WARNING("C2S recv tds pkt len < %u\n", nRecvLen);
                        return false;
                    }
					if (left_tdslen > PACK_MAX_SIZE)
					{//长度大于PACK_MAX_SIZE，不是TDS包
						TRACE_ERROR("S2C recv tds left pkt len: %u > PACK_MAX_SIZE: %u!\n", left_tdslen, PACK_MAX_SIZE);
						return false;
					}
					
					if (left_tdslen == nLeftLen)
					{//余下的数据为完整TDS包
						TRACE_DETAIL("S2C recv tds left len: %u == tcp body left len is: %u.\n", left_tdslen, nLeftLen);
						TDSPktPtr tdspkt(new TDSPkt(nLeftLen));
						memcpy(tdspkt->getpkt(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);
						m_TDSParse.processpkt(tdspkt);

						m_S2CTdsPktLen = 0;
						m_S2CTdsRecvLen = 0;
					}
					else if (left_tdslen > nLeftLen)
					{//余下的数据为部分TDS包
						m_S2CTdsPktLen = left_tdslen;
						m_S2CTdsRecvLen = nLeftLen;
						std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(nLeftLen));
						memcpy(pPkt->getbuffer(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);

						m_S2CPktVec.clear();
						m_S2CPktVec.push_back(pPkt);
					}
					else
					{//出错啦 
						TRACE_ERROR("S2C recv tds left pkt len: %u < tcp body left len is: %u!\n", left_tdslen, nLeftLen);

						m_S2CTdsPktLen = 0;
						m_S2CTdsRecvLen = 0;
					}
				}
			}
			else
			{
				uint16_t tdslen = 0;
				memcpy(&tdslen, bpTCP + 2, sizeof(tdslen));
				tdslen = ntohs(tdslen);

				TRACE_DETAIL("S2C recv tds len: %u, tcp body len is: %u.\n", tdslen, tcpBodyLen);
				if (tdslen == tcpBodyLen)
				{//完整的tds包，弹出至TDS包解析
					TRACE_DETAIL("S2C recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
					TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
					memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
					m_TDSParse.processpkt(tdspkt);

				}
				else if (tdslen > tcpBodyLen)
				{//不完整，还有后续包
					m_S2CTdsPktLen = tdslen;
					m_S2CTdsRecvLen = tcpBodyLen;
					TRACE_INFO("S2C recv first part of tds len: %u, current tcp body len is: %u.\n", m_S2CTdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

					m_S2CPktVec.clear();
					m_S2CPktVec.push_back(pPkt);
				}
				else
				{//出错
					TRACE_WARNING("S2C recv tds len: %u < tcp body len is: %u!\n", tdslen, tcpBodyLen);
				}

			}

			m_S2CStartSeq = sequence;
			m_S2CNextSeq = sequence + tcpBodyLen;
			m_S2CAckSeq = ack;
			m_S2CEndTime = currentUsec;
		}
		else
		{//sequence != m_S2CNextSeq
			if (sequence < m_S2CNextSeq)
			{//重发包，忽略
				TRACE_INFO("S2C recv sequence: %u < next seq is: %u.\n", sequence, m_S2CNextSeq);
			}
			else
			{//丢包，后包先到，此处暂不处理
				TRACE_WARNING("S2C recv sequence: %u > next seq is: %u!\n", sequence, m_S2CNextSeq);
			}
		}
	}

	return true;
}

