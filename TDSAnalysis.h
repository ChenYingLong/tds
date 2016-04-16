/*
TDSAnalysis.h
解析TDS包
*/
#ifndef __TDSANALYSIS_H__
#define __TDSANALYSIS_H__
#include <iostream>
#include <pcap.h>
#include "packet.h"
using namespace std;

#define IPTOSBUFFERS 12
#define CHARSBUFFERS 100

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;

#define LENOTHER		54

typedef struct ethernet_header
{
	char dst_mac[6];
	char src_mac[6];
	unsigned short type;
}ethernet_header;

/* 4 bytes IP address */
typedef struct ip_address{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	unsigned char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	unsigned char  tos;            // Type of service 
	unsigned short tlen;           // Total length 
	unsigned short identification; // Identification
	unsigned short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	unsigned char  ttl;            // Time to live
	unsigned char  proto;          // Protocol
	unsigned short crc;            // Header checksum
	unsigned int  saddr;      // Source address
	unsigned int  daddr;      // Destination address
	unsigned int   op_pad;         // Option + Padding
}ip_header;

/*TCP header*/
typedef struct tcp_header{
	unsigned short sport;
	unsigned short dport;
	unsigned int seqnum;
	unsigned int acknum;
	unsigned short hl_flag;
	unsigned short win;
	unsigned short crc;
	unsigned short pointer;
	unsigned int op_pad;
}tcp_header;

/*TDS header*/
typedef struct tds_header{
	unsigned char type;
	unsigned char status;
	unsigned short size;
	unsigned short channel;
	unsigned char packet_number;
	unsigned char window;
}tds_header;

/*Login Packet*/
typedef struct login_packet{
	unsigned int tlen;      //total packet size
	unsigned int version;   //TDS Version	0x00000070 for TDS7, 0x01000071 for TDS8
	unsigned int psz;       //packet size (default 4096)
	unsigned int client_version ;   //client program version
	unsigned int client_pid;        //PID of client
	unsigned int connection_id;   //connection id (usually 0)
	unsigned char opt_flag1;//option flags1
	unsigned char opt_flag2;//option flags2
	unsigned char sql_flag;//sql type flags 
	unsigned char res_flag;//reserved flags 
	unsigned int time_zone;//time zone 
	unsigned int collation;//collation information
	unsigned short pos_htn;//position of client hostname 
	unsigned short htn_len;//hostname length
	unsigned short pos_usn;	//position of username
	unsigned short usn_len;//username length
	unsigned short pos_pwd;	//position of password
	unsigned short pwd_len;//password length
	unsigned short pos_apn;	//position of app name
	unsigned short apn_len;//app name length
	unsigned short pos_svn;//position of server name
	unsigned short svn_len;//server name length
	unsigned short a;
	unsigned short b;
	unsigned short pos_lbn;//position of library name
	unsigned short lbn_len;//library name length
	unsigned short pos_lan;//position of language
	unsigned short lan_len;//language name
	unsigned short pos_dbn;	//position of database name
	unsigned short dbn_len;//database name length
	unsigned char clt_mac[6];//MAC address of client
	unsigned short pos_aup;//position of auth portion
	unsigned short aut_len;//NT authentication length
	unsigned short next_pos;//next position (same of total packet size)
	unsigned short c;
}login_packet;

#define F_SQLBATCH	"result/sqlbatch.txt"
#define F_PRELOGIN	"result/prelogin.txt"
#define F_REPLY		"result/reply.txt"
#define F_ATTENTION	"result/attention.txt"
#define F_RPC		"result/rpc.txt"
#define F_TABULAR_RESULT		"result/tabular_result.txt"
#define F_UNKNOWN	"result/unkwon.txt"
#define F_SSPI		"result/sspi.txt"

class TDSAnalysis
{
public:
	TDSAnalysis();
	~TDSAnalysis();
	
	void processpkt(TDSPktPtr);
	static const u_long TDS_VERSION = 0x730B0003;		//TDS版本
private:
	bool parseTdsHead();		//解析tds头部
	/*解析各种包的主函数*/
	void fn_TDS_QUERY();//0x01解析sql_batch
	void fn_TDS_REPLY();		//0x04
	void fn_TDS7_PRELOGIN();	//0x12预登陆解析
	void fn_TDS_ATTENTION();	//0x06解析Attention包
	void fn_TDS_BULK();			//0x07，目前还没有发现此包
	void fn_TDS_RPC();			//0x03解析RPC请求包
	void fn_TDS7_SSPI();		//0x11SSPI包
	

	/*TOKEN类型解析*/
	void fn_COLMETADATA_TOKEN(ofstream& fileOut);
	/*一些工具函数*/
	void writeTdsHead(ofstream& fileOut);	//把头部写入文件
	void writeUnknowPack();		//一些未知的包

	tds_header tds_head;
	const u_char *tds_data;		//tds源数据(包含tcp头等)
};

//ms server2008r2 TDS版本为7.3B
//ms server2008   TDS版本为7.3A
//ms server2008以后 TDS版本为7.4

#endif
