/*
M_Pcap.h
抓包sdk和开始解包的类组合到一起
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
	//32位ip之差--client ip低16位--16位client port
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
	struct pcap_pkthdr *pkt_info;//流信息:长度、时间等
	pcap_t *fp;
	const uint8_t *pkt_data;		//tds源数据(包含tcp头等)
	u_int TDS_ID;				//记录是第几个tds包
	std::map<KEY_TYPE, std::shared_ptr<TDSConn>> tdsConnMap;//存放链路
	std::map<KEY_TYPE, uint32_t> finTimeNum;//判断链路断开时使用，四次握手后就删除该链路
public:
	M_Pcap();
	~M_Pcap();
	bool initPcap();			//初始化Pcap，设置抓包过滤等
	bool getNextTds();			//获取下一个tds流,tds_data指向此数据
	void startParseTds();		//开始解析tds
};