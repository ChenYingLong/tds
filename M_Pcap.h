/*
M_Pcap.h
ץ��sdk�Ϳ�ʼ���������ϵ�һ��
*/
#pragma once
#include <pcap.h>
#include "tdsconn.h"
#include <string>
#include <sstream>
#define TCP_CONN_HASH_SIZE 0x100000 //65536

#define KEY_TYPE uint64_t
static inline KEY_TYPE hashForTcpConn(uint32_t laddr, uint16_t lport, uint32_t faddr, uint16_t fport)
{
	//hashData
	//32λip֮��--client ip��16λ--16λclient port
	KEY_TYPE hashData = 0;

	if (lport == 1433)
	{
		hashData += (faddr - lport);
		hashData <<= 32;
		hashData += (faddr & 0xFFFF);
		hashData <<= 16;
		hashData += fport;

	}
	else if (fport == 1433)
	{
		hashData += (laddr - fport);
		hashData <<= 32;
		hashData += (laddr & 0xFFFF);
		hashData <<= 16;
		hashData += lport;

	}
	else
		printf("error!!!");
	return hashData;
}

class M_Pcap
{
	struct pcap_pkthdr *pkt_info;//����Ϣ:���ȡ�ʱ���
	pcap_t *fp;
	const uint8_t *pkt_data;		//tdsԴ����(����tcpͷ��)
	u_int TDS_ID;				//��¼�ǵڼ���tds��
	std::map<KEY_TYPE, std::shared_ptr<TDSConn>> tdsConnMap;//�����·
	std::map<KEY_TYPE, uint32_t> finTimeNum;//�ж���·�Ͽ�ʱʹ�ã��Ĵ����ֺ��ɾ������·
public:
	M_Pcap();
	~M_Pcap();
	bool initPcap();			//��ʼ��Pcap������ץ�����˵�
	bool getNextTds();			//��ȡ��һ��tds��,tds_dataָ�������
	void startParseTds();		//��ʼ����tds
};