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
	{//���ݰ�
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
	{//�����ݰ�
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
		{//С��TDSͷ�ĳ���
			TRACE_INFO("C2S recv first tcp body len: %u < 8 bytes len.\n", tcpBodyLen);
			return false;
		}

		uint16_t tdslen = 0;
		memcpy(&tdslen, bpTCP + 2, sizeof(tdslen));
		tdslen = ntohs(tdslen);
		if (tdslen == tcpBodyLen)
		{//������tds����������TDS������
			TRACE_DETAIL("C2S recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
			TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
			memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
			m_TDSParse.processpkt(tdspkt);
		}
		else if (tdslen > tcpBodyLen)
		{//�����������к�����
			m_C2STdsPktLen = tdslen;
			m_C2STdsRecvLen = tcpBodyLen;
			std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
			memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

			m_C2SPktVec.clear();
			m_C2SPktVec.push_back(pPkt);

			TRACE_INFO("C2S recv first tds len: %u > tcp body len is: %u.\n", tdslen, tcpBodyLen);
		}
		else
		{//����
			TRACE_WARNING("C2S recv tds len: %u < tcp body len is: %u!\n", tdslen, tcpBodyLen);
		}
	}
	else
	{//0 != m_C2SStartSeq
		if (sequence == m_C2SNextSeq)
		{//˳�������������
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
			{//��һ����Ϊtcp pdu
				uint32_t nRecvLen = m_C2STdsRecvLen + tcpBodyLen;
				if (m_C2STdsPktLen == nRecvLen)
				{//tds����ȫ��������TDS������
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
				{//��δ��ȫ��������
					TRACE_INFO("C2S recv part of tds len: %u, current tcp body len is: %u.\n", m_C2STdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);
					m_C2SPktVec.push_back(pPkt);

					m_C2STdsRecvLen += tcpBodyLen;
				}
				else
				{//����(������ճ��)
					TRACE_WARNING("C2S recv tds pkt len: %u < total recv len is: %u!\n", m_C2STdsPktLen, nRecvLen);
					//ճ������
					uint32_t nLeftLen = nRecvLen - m_C2STdsPktLen;

					TDSPktPtr tdspkt(new TDSPkt(m_C2STdsPktLen));
					uint32_t nSize = 0;
					for (size_t i = 0; i < m_C2SPktVec.size(); i++)
					{
						memcpy(tdspkt->getpkt() + nSize, m_C2SPktVec[i]->getbuffer(), m_C2SPktVec[i]->getbuffersize());
						nSize += m_C2SPktVec[i]->getbuffersize();
					}
					memcpy(tdspkt->getpkt() + nSize, bpTCP, tcpBodyLen - nLeftLen);
					//post tds pkt ����ǰ��������
					m_TDSParse.processpkt(tdspkt);

					//�������µ�����
					//���µĿ��������õ����ݣ�Ҫ�����û�д˰����ͣ������Ƿ����ȣ����������ֱ�Ӷ�����
					uint16_t left_tdslen = 0;

					memcpy(&left_tdslen, bpTCP + tcpBodyLen - nLeftLen + 2, sizeof(left_tdslen));
					left_tdslen = ntohs(left_tdslen);

                    if (nLeftLen < 8)
                    {//����һ�����ĳ���
                        TRACE_WARNING("C2S recv tds pkt len < %u\n", nRecvLen);
                        return false;
                    }
                    if (left_tdslen > PACK_MAX_SIZE)
                    { // ���ȴ���PACK_MAX_SIZE������TDS��
                        TRACE_ERROR("C2S recv tds left pkt len: %u > PACK_MAX_SIZE: %u!\n", left_tdslen, PACK_MAX_SIZE);
                        return false;
                    }

					if (left_tdslen == nLeftLen)
					{//���µ�����Ϊ����TDS��
						TRACE_DETAIL("C2S recv tds left len: %u == tcp body left len is: %u.\n", left_tdslen, nLeftLen);
						TDSPktPtr tdspkt(new TDSPkt(nLeftLen));
						memcpy(tdspkt->getpkt(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);
						m_TDSParse.processpkt(tdspkt);

						m_C2STdsPktLen = 0;
						m_C2STdsRecvLen = 0;
					}
					else if (left_tdslen > nLeftLen)
					{//���µ�����Ϊ����TDS��
						m_C2STdsPktLen = left_tdslen;
						m_C2STdsRecvLen = nLeftLen;
						std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(nLeftLen));
						memcpy(pPkt->getbuffer(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);

						m_C2SPktVec.clear();
						m_C2SPktVec.push_back(pPkt);
					}
					else
					{//������ 
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
				{//������tds����������TDS������
					TRACE_DETAIL("C2S recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
					TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
					memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
					m_TDSParse.processpkt(tdspkt);

				}
				else if (tdslen > tcpBodyLen)
				{//�����������к�����
					m_C2STdsPktLen = tdslen;
					m_C2STdsRecvLen = tcpBodyLen;
					TRACE_INFO("C2S recv first part of tds len: %u, current tcp body len is: %u.\n", m_C2STdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

					m_C2SPktVec.clear();
					m_C2SPktVec.push_back(pPkt);
				}
				else
				{//����
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
			{//�ط���������
				TRACE_INFO("C2S recv sequence: %u < next seq is: %u.\n", sequence, m_C2SNextSeq);
			}
			else
			{//����������ȵ����˴��ݲ�����
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
		{//С��TDSͷ�ĳ���
			TRACE_INFO("S2C recv first tcp body len: %u < 8 bytes len.\n", tcpBodyLen);
			return false;
		}

		uint16_t tdslen = 0;
		//memcpy(&tdslen, bpTCP, sizeof(tdslen));
		memcpy(&tdslen, bpTCP + 2, sizeof(tdslen));//tds�ڶ����ֽ�Ϊ����
		tdslen = ntohs(tdslen);
		if (tdslen == tcpBodyLen)
		{//������tds����������TDS������
			TRACE_DETAIL("S2C recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
			TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
			memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
			m_TDSParse.processpkt(tdspkt);
		}
		else if (tdslen > tcpBodyLen)
		{//�����������к�����
			m_S2CTdsPktLen = tdslen;
			m_S2CTdsRecvLen = tcpBodyLen;
			std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
			memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

			m_S2CPktVec.clear();
			m_S2CPktVec.push_back(pPkt);

			TRACE_INFO("S2C recv first tds len: %u > tcp body len is: %u.\n", tdslen, tcpBodyLen);
		}
		else
		{//����
			TRACE_WARNING("S2C recv tds len: %u < tcp body len is: %u!\n", tdslen, tcpBodyLen);
		}
	}
	else
	{
		if (sequence == m_S2CNextSeq)
		{//˳�������������
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
			{//��һ����Ϊtcp pdu
				uint32_t nRecvLen = m_S2CTdsRecvLen + tcpBodyLen;
				if (m_S2CTdsPktLen == nRecvLen)
				{//tds����ȫ��������TDS������
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
				{//��δ��ȫ��������
					TRACE_INFO("S2C recv part of tds len: %u, current tcp body len is: %u.\n", m_S2CTdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);
					m_S2CPktVec.push_back(pPkt);

					m_S2CTdsRecvLen += tcpBodyLen;
				}
				else
				{//����(������ճ��)
					TRACE_WARNING("S2C recv tds pkt len: %u < total recv len is: %u!\n", m_S2CTdsPktLen, nRecvLen);
					//ճ������
					uint32_t nLeftLen = nRecvLen - m_S2CTdsPktLen;

					TDSPktPtr tdspkt(new TDSPkt(m_S2CTdsPktLen));
					uint32_t nSize = 0;
					for (size_t i = 0; i < m_S2CPktVec.size(); i++)
					{
						memcpy(tdspkt->getpkt() + nSize, m_S2CPktVec[i]->getbuffer(), m_S2CPktVec[i]->getbuffersize());
						nSize += m_S2CPktVec[i]->getbuffersize();
					}
					memcpy(tdspkt->getpkt() + nSize, bpTCP, tcpBodyLen - nLeftLen);
					//post tds pkt ����ǰ��������
					m_TDSParse.processpkt(tdspkt);

					//�������µ�����
					uint16_t left_tdslen = 0;
					memcpy(&left_tdslen, bpTCP + tcpBodyLen - nLeftLen + 2, sizeof(left_tdslen));
					left_tdslen = ntohs(left_tdslen);

                    if (nLeftLen < 8)
                    {// ����һ�����ĳ���
                        TRACE_WARNING("C2S recv tds pkt len < %u\n", nRecvLen);
                        return false;
                    }
					if (left_tdslen > PACK_MAX_SIZE)
					{//���ȴ���PACK_MAX_SIZE������TDS��
						TRACE_ERROR("S2C recv tds left pkt len: %u > PACK_MAX_SIZE: %u!\n", left_tdslen, PACK_MAX_SIZE);
						return false;
					}
					
					if (left_tdslen == nLeftLen)
					{//���µ�����Ϊ����TDS��
						TRACE_DETAIL("S2C recv tds left len: %u == tcp body left len is: %u.\n", left_tdslen, nLeftLen);
						TDSPktPtr tdspkt(new TDSPkt(nLeftLen));
						memcpy(tdspkt->getpkt(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);
						m_TDSParse.processpkt(tdspkt);

						m_S2CTdsPktLen = 0;
						m_S2CTdsRecvLen = 0;
					}
					else if (left_tdslen > nLeftLen)
					{//���µ�����Ϊ����TDS��
						m_S2CTdsPktLen = left_tdslen;
						m_S2CTdsRecvLen = nLeftLen;
						std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(nLeftLen));
						memcpy(pPkt->getbuffer(), bpTCP + tcpBodyLen - nLeftLen, nLeftLen);

						m_S2CPktVec.clear();
						m_S2CPktVec.push_back(pPkt);
					}
					else
					{//������ 
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
				{//������tds����������TDS������
					TRACE_DETAIL("S2C recv tds len: %u == tcp body len is: %u.\n", tdslen, tcpBodyLen);
					TDSPktPtr tdspkt(new TDSPkt(tcpBodyLen));
					memcpy(tdspkt->getpkt(), bpTCP, tcpBodyLen);
					m_TDSParse.processpkt(tdspkt);

				}
				else if (tdslen > tcpBodyLen)
				{//�����������к�����
					m_S2CTdsPktLen = tdslen;
					m_S2CTdsRecvLen = tcpBodyLen;
					TRACE_INFO("S2C recv first part of tds len: %u, current tcp body len is: %u.\n", m_S2CTdsPktLen, tcpBodyLen);
					std::shared_ptr<PKTBuffer> pPkt(new PKTBuffer(tcpBodyLen));
					memcpy(pPkt->getbuffer(), bpTCP, tcpBodyLen);

					m_S2CPktVec.clear();
					m_S2CPktVec.push_back(pPkt);
				}
				else
				{//����
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
			{//�ط���������
				TRACE_INFO("S2C recv sequence: %u < next seq is: %u.\n", sequence, m_S2CNextSeq);
			}
			else
			{//����������ȵ����˴��ݲ�����
				TRACE_WARNING("S2C recv sequence: %u > next seq is: %u!\n", sequence, m_S2CNextSeq);
			}
		}
	}

	return true;
}

