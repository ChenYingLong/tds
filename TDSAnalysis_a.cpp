/*******************************************
TDSAnalysis_a.cpp
包含已经能正确解析的type函数
********************************************/

#include <fstream> 
#include <iomanip>
#include <stdio.h>

#include "TDSAnalysis.h"
#include "InfoTypeDef.h"

TDSAnalysis::TDSAnalysis() 
{
};
TDSAnalysis::~TDSAnalysis() {};
/*把tds头部写入文件*/
void TDSAnalysis::writeTdsHead(ofstream& fileOut)
{
	//fileOut << dec;
	//fileOut << "时间:" << tds_info->ts.tv_sec << "分" << tds_info->ts.tv_usec << endl;
	const u_char*tds = tds_data;
	/*
	fileOut << "Source:" << (int)tds[26] << "." << (int)tds[27] << "." << (int)tds[28] << "." << (int)tds[29] << endl;
	fileOut << "Destination:" << (int)tds[30] << "." << (int)tds[31] << "." << (int)tds[32] << "." << (int)tds[33] << endl;
	fileOut << "nSource Port:" << ((int)(tds[34] << 8) + tds[35]) << endl;
	fileOut << "Destination Port:" << ((int)(tds[36] << 8) + tds[37]) << endl;
	*/
	fileOut.fill('0');
	fileOut.setf(ios::showpoint);
	fileOut << hex;
	fileOut << "PacketHeader:\n";
	fileOut << "Type:    " << setw(2) << (int)tds_head.type << endl;
	fileOut << "Status:  " << setw(2) << (int)tds_head.status << endl;
	fileOut << "Length:  " << setw(4) << (int)tds_head.size << endl;
	fileOut << "SPID:    " << setw(4) << tds_head.channel << endl;
	fileOut << "PacketID:" << setw(2) << (int)tds_head.packet_number << endl;
	fileOut << "Window:  " << setw(2) << (int)tds_head.window << endl;
}
void TDSAnalysis::writeUnknowPack()
{
	std::ofstream fileOut;
	fileOut.open(F_UNKNOWN, std::ios::out | ios::app);
	const u_char *tds = tds_data;
	writeTdsHead(fileOut);
	fileOut << "<PacketData>\n";
	const u_char* writeData = (tds + 8);
	for (int i = 0; i < tds_head.size - 8; i++)
		fileOut << setw(2) << (int)writeData[i];
	fileOut << "\n</PacketData>\n\n";
}
//解析tds头部
bool TDSAnalysis::parseTdsHead()
{
	const u_char *tds = tds_data;
	tds_head.type = tds[0];
	tds_head.status = tds[1];
	tds_head.size = (tds[2] << 8) + tds[3];
	tds_head.channel = (tds[4] << 8) + tds[5];
	tds_head.packet_number = tds[6];
	tds_head.window = tds[7];
	return true;
}
/************************************************************************/
/* ATENTION包数据解析													*/
/************************************************************************/
void TDSAnalysis::fn_TDS_ATTENTION()
{
	const u_char *tds = tds_data;
	std::ofstream fileOut;
	fileOut.open(F_ATTENTION, std::ios::out | ios::app);
	writeTdsHead(fileOut);
	//attention包没有data部分
	fileOut << endl;
	fileOut.close();
}
/************************************************************************/
/* sql_batch数据解析													*/
/************************************************************************/
void TDSAnalysis::fn_TDS_QUERY()
{
	const u_char *tds = tds_data;
	//LONG32 total_Length = 0;
	std::ofstream fileOut;
	fileOut.open(F_SQLBATCH, std::ios::out | ios::app);

	//包头
	writeTdsHead(fileOut);

	//allHeaderLen是All_HEADERS的长度
	//当一个消息跨多个包时，第一个包有All_HEADERS，其余的包没有All_HEADERS
	//
    int allHeaderLen = tds[8] + (tds[9] << 8) + (tds[10] << 16) + (tds[11] << 24);

    int headerLen = tds[12] + (tds[13] << 8) + (tds[14] << 16) + (tds[15] << 24);
	int i = 7;
	//包数据
	fileOut << "<PacketData>\n";
	fileOut << "	<SQLBatch>\n";
	
    if (allHeaderLen == 22 && headerLen == 18)//在测试和文档上，allHeaderLen长度为22,headerLen=18，否则就没有allHeaderLen 
    {
        fileOut << "	  <All_HEADERS>\n";
        fileOut << "		<TotalLength>\n";
        fileOut << "		" << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << setw(2) << (int)tds[i + 4] << "\n";

        fileOut << "		</TotalLength>\n";
        i += 4;
        fileOut << "		<Header>\n";
        fileOut << "			<HeaderLength>\n";
        fileOut << "			" << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << setw(2) << (int)tds[i + 4] << "\n";
        i += 4;
        fileOut << "			</HeaderLength>\n";
        fileOut << "			<HeaderType>\n";
        fileOut << "			" << setw(2) << (int)tds[1 + i] << setw(2) << (int)tds[2 + i] << "\n";
        i += 2;
        fileOut << "			</HeaderType>\n";
        fileOut << "			<HeaderData>\n";
        fileOut << "			<MARS>\n";
        fileOut << "				<TransactionDescriptor>\n";
        fileOut << "				" << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << setw(2) << (int)tds[i + 4] << setw(2) << (int)tds[i + 5] << setw(2) << (int)tds[i + 6] << setw(2) << (int)tds[i + 7] << setw(2) << (int)tds[i + 8] << "\n";
        i += 8;
        fileOut << "				</TransactionDescriptor>\n";
        fileOut << "				<OutstandingRequestCount>\n";
        fileOut << "				" << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << setw(2) << (int)tds[i + 4] << "\n";
        i += 4;
        fileOut << "				</OutstandingRequestCount>\n";
        fileOut << "			</MARS>\n";
        fileOut << "			</HeaderData>\n";
        fileOut << "		</Header>\n";
        fileOut << "	  </All_HEADERS>\n";
    }
    else
        allHeaderLen = 0;
	fileOut << "	  <SQLText>\n";
	
	fileOut.write((const char *)(tds + allHeaderLen + 8), tds_head.size - 8 - allHeaderLen);

	fileOut << "\n	  </SQLText>\n";
	fileOut << "	</SQLBatch>\n";
	fileOut << "</PacketData>\n\n";
	fileOut.close();
}

void TDSAnalysis::processpkt(TDSPktPtr tdsPtr)
{
	tds_data = tdsPtr->getpkt();
	parseTdsHead();
	switch (tds_head.type)
	{
		case TDS_QUERY:			//type:0x01
			fn_TDS_QUERY();
			break;
		case TDS_RPC:			//type:0x03
			fn_TDS_RPC();
			break;
		case TDS_REPLY:			//type:0x04
			fn_TDS_REPLY();
			break;
		case TDS7_PRELOGIN:		//type:0x12
			fn_TDS7_PRELOGIN();
			break;
		case TDS_ATTENTION:		//type:0x06
			fn_TDS_ATTENTION();
			break;
		case TDS_BULK:			//type:0x07，目前还没有发现此包
			fn_TDS_BULK();
			break;
		case TDS7_SSPI:			//type:0x11，目前还没有发现此包
			fn_TDS7_SSPI();
		default:
			writeUnknowPack();
			cout << "UnKnow Pack: " << hex << (int)tds_head.type << endl;
			break;
	}
}