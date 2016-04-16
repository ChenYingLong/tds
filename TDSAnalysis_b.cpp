/*******************************************
TDSAnalysis_b.cpp
还未能正确解析的type函数
********************************************/
#include <fstream> 
#include <iomanip>
#include <stdio.h>

#include "TDSAnalysis.h"
#include "InfoTypeDef.h"




/************************************************************************/
/* 主机端返回的数据解析													*/
/************************************************************************/
void TDSAnalysis::fn_TDS_REPLY()
{

	std::ofstream fileOut;
	fileOut.open(F_REPLY, std::ios::out | ios::app);

	writeTdsHead(fileOut);
	const u_char *tds = tds_data;
	switch (tds[8])//Token type
	{
	case TDS_COLMETADATA_TOKEN:
		fn_COLMETADATA_TOKEN(fileOut);
		break;
	default:
		cout << "Unknown TokenType:6" << setw(2) << (int)tds[8] << endl;
		break;
	}
	/*
	for (int i = 0; i < tds_info->caplen - tds_data_off - 8; i++)
		fileOut << setw(2) << (int)writeData[i];
	//fileOut.write(writeData , tds_info->caplen - tds_data_off-8);
	int tmpLen = tds_info->caplen - tds_data_off;
	while (tmpLen < tds_head.size)
	{
		if (!getNextTds())
		{
			fileOut.close();
			return;
		};
		//无tds数据
		if (tds_info->caplen <= tds_data_off)
			continue;
		tds = tds_data + tds_data_off;
		tmpLen += tds_info->caplen - tds_data_off;
		for (int i = 0; i < tds_info->caplen - tds_data_off; i++)
			fileOut << " " << (int)tds[i];
		//fileOut.write((const char *)tds, tds_info->caplen - tds_data_off);
	}
	fileOut << "  <TableResponse>\n";
	fileOut << "\n</PacketData>\n\n";
	*/
	fileOut.close();
}

/************************************************************************/
/* 预登陆数据解析       												*/
/************************************************************************/
void TDSAnalysis::fn_TDS7_PRELOGIN()
{
	const u_char *tds = tds_data;
	LONG32 total_Length = 0;
	std::ofstream fileOut;
	fileOut.open(F_PRELOGIN, std::ios::out | ios::app);
	//包头
	writeTdsHead(fileOut);

	fileOut << "<PacketData>\n";
	fileOut << "	<Prelogin>\n";
	int i = 8;
	int tokenType = (int)tds[i];
	if (tokenType == 0x16 || tokenType == 0x14 || tokenType == 0x10)
	{//这几个type还不知道怎么解析
		fileOut << "		ssl加密\n";
		for (i; i < tds_head.size; i++)
			fileOut << setw(2) << (int)tds[i];
	}
	else
	{
		while (tokenType != 0xff)
		{
			fileOut << "		<TokenType>\n";
			fileOut << "		" << setw(2) << tokenType << "\n";
			fileOut << "		</TokenType>\n";
			fileOut << "		<TokenPosition>\n";
			fileOut << "		" << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << "\n";
			fileOut << "		</TokenPosition>\n";
			fileOut << "		<TokenLeng>\n";
			fileOut << "		" << setw(2) << (int)tds[i + 3] << setw(2) << (int)tds[i + 4] << "\n";
			fileOut << "		</TokenLeng>\n";
			i += 5;
			tokenType = (int)tds[i];
		}
		fileOut << "		<TokenType>\n";
		fileOut << "		" << setw(2) << tokenType << "\n";
		fileOut << "		</TokenType>\n";

		fileOut << "		<PreloginData>\n";
		fileOut << "			";
		for (i++; i < tds_head.size; i++)
			fileOut << setw(2) << (int)tds[i];
	}
	fileOut << "		\n</PreloginData>\n";

	fileOut << "	</Prelogin>\n";
	fileOut << "</PacketData>\n\n\n";

	fileOut.close();
}

/************************************************************************/
/* RPC数据解析			 												*/
/************************************************************************/
void TDSAnalysis::fn_TDS_RPC()
{
	const u_char *tds = tds_data;
	//LONG32 total_Length = 0;
	std::ofstream fileOut;
	fileOut.open(F_RPC, std::ios::out | ios::app);
	//包头
	writeTdsHead(fileOut);
	int i = 8;
	fileOut << "<PacketData>\n";
	fileOut << "	<RPCRequest>\n";
	//当一个消息跨多个包时，第一个包有All_HEADERS，其余的包没有All_HEADERS
	//
	int allHeaderLen = tds[8] + (tds[9] << 8) + (tds[10] << 16) + (tds[11] << 24);
	int headerLen = tds[12] + (tds[13] << 8) + (tds[14] << 16) + (tds[15] << 24);
	if (allHeaderLen == 22 && headerLen == 18)//在测试和文档上，allHeaderLen长度为22,headerLen=18，否则就没有allHeaderLen 
	{
		fileOut << "	  <All_HEADERS>\n";
		fileOut << "		<TotalLength>\n";

		fileOut << "		" << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << endl;
		fileOut << "		</TotalLength>\n";
		i += 4;
		fileOut << "		<Header>\n";
		fileOut << "			<HeaderLength>\n";
		fileOut << "		    " << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << endl;
		i += 4;
		fileOut << "			</HeaderLength>\n";
		fileOut << "			<HeaderType>\n";
		fileOut << "			" << setw(2) << (int)tds[i] << setw(2) << (int)tds[1 + i] << endl;
		i += 2;
		fileOut << "			</HeaderType>\n";
		fileOut << "			<HeaderData>\n";
		fileOut << "			<MARS>\n";
		fileOut << "				<TransactionDescriptor>\n";
		fileOut << "				" << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << setw(2) << (int)tds[i + 4] << setw(2) << (int)tds[i + 5] << setw(2) << (int)tds[i + 6] << setw(2) << (int)tds[i + 7] << endl;
		i += 8;
		fileOut << "				</TransactionDescriptor>\n";
		fileOut << "				<OutstandingRequestCount>\n";
		fileOut << "				" << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << setw(2) << (int)tds[i + 3] << endl;
		i += 4;
		fileOut << "				</OutstandingRequestCount>\n";
		fileOut << "			</MARS>\n";
		fileOut << "			</HeaderData>\n";
		fileOut << "		</Header>\n";
		fileOut << "	  </All_HEADERS>\n";
	}
	
	fileOut << "		<RPCReqBatch>\n";
	fileOut << "			<NameLenProcID>\n";

	if (tds[i] == 0xff && tds[i + 1] == 0xff)
	{
		fileOut << "			  <ProcIDSwitch>\n";
		fileOut << "			    " << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << endl;
		fileOut << "			  </ProcIDSwitch>\n";
		i += 2;
		fileOut << "			  <ProcID>\n";
		fileOut << "			    " << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << endl;
		fileOut << "			  </ProcID>\n";
		i += 2;
	}
	else
	{
		fileOut << "			  <ProcName>\n";
		fileOut << "			    <US_UNICODE>\n";
		fileOut << "			      <USHORTLEN>\n";
		u_short ushortLen = tds[i] + (tds[i + 1] << 8);
		fileOut << "			        " << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << endl;
		i += 2;
		fileOut << "			      </USHORTLEN>\n";
		fileOut << "			      <BYTES>";
		//fileOut.write((const char*)tds, ushortLen * 2);
		for (int tmpi = 0; tmpi < ushortLen * 2; tmpi += 2)
			fileOut << (char)tds[i + tmpi];
		i += 2 * ushortLen;
		fileOut << "			      </BYTES>\n";

		fileOut << "			    </US_UNICODE>\n";
		fileOut << "			  </ProcName>\n";
	}

	fileOut << "			</NameLenProcID>\n";

	fileOut << "			<OptionFlags>\n";
	fileOut << "			  " << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << endl;
	fileOut << "			</OptionFlags>\n";
	i += 2;
	//TDS7.4版本还添加了一些其它的，此处未加入
	while (i < tds_head.size)
	{
		//<ParameterData>
		fileOut << "<ParameterData>" << endl;
		//name length
		fileOut << "	<Name Length>:";
		uint8_t byteLen = tds[i];
		fileOut << setw(2) << (int)byteLen << endl;
		i += 1;

		//name
		if (byteLen > 0)
		{
			fileOut << "	<NAME>:";
			//fileOut.write((const char*)(tds + i), 2 * byteLen);
			for (int tmpi = 0; tmpi < byteLen * 2; tmpi += 2)
				fileOut << (char)tds[i + tmpi];
			i += 2 * byteLen;
			fileOut << endl;
		}

		fileOut << "	<StatusFlags>:";
		fileOut << setw(2) << (int)tds[i] << endl;
		i += 1;

		//TDS7.3之后
		//TYPE_INFO
		fileOut << "	<TYPE_INFO>" << endl;
		fileOut << "		<TYPE>:";
		uint8_t type = tds[i];
		fileOut << setw(2) << (int)type << endl;
		i += 1;
		//其它的type还没有考虑
		if (type == 0xE7 || type == 0xAF || type == 0x23 || type == 0x63 || type == 0xEF || type == 0xA7)
		{
			//Maximal length
			fileOut << "		<Maximal length>:";
			fileOut << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << endl;
			i += 2;
			//COLLATION
			fileOut << "		<COLLATION>:";
			for (int tmpi = 0; tmpi < 5; tmpi++)//5字节的COLLATION
			{
				fileOut << setw(2) << (int)tds[i + tmpi];
			}
			i += 5;
			fileOut << endl;

			uint16_t valueLen = tds[i] + (tds[i + 1] << 8);
			fileOut << "	<VALUE>\n";
			fileOut << "	  <Length>:";
			fileOut << setw(2) << (int)tds[i] << setw(2) << (int)tds[i + 1] << endl;
			i += 2;

			fileOut << "	  <DATA>:";
			//fileOut.write((const char*)(tds + i), valueLen);
			for (int tmpi = 0; tmpi < valueLen; tmpi += 2)
				fileOut << (char)tds[i + tmpi];
			i += valueLen;
			fileOut << endl;
		}
		else
		{
			fileOut << "unknow type" << endl;
			break;
		}
	}
	fileOut << "		</RPCReqBatch>\n";
	fileOut << "	</RPCRequest>\n";
	fileOut << "</PacketData>\n\n\n";

	fileOut.close();
}

/*Security Support Provider Interface */
void TDSAnalysis::fn_TDS7_SSPI()
{
	const u_char *tds = tds_data;
	//LONG32 total_Length = 0;
	std::ofstream fileOut;
	fileOut.open(F_SSPI, std::ios::out | ios::app);
	//包头
	//int tdsPtr = 0;

	writeTdsHead(fileOut);

	fileOut << "<PacketData>\n";
	const u_char* writeData = (tds + 8);

	for (int i = 0; i < tds_head.size - 8; i++)
		fileOut << setw(2) << (int)writeData[i];
	//fileOut.write(writeData , tds_info->caplen - tds_data_off-8);

	fileOut << "</PacketData>\n\n";
}

/************************************************************************/
/* BulkLoadBCP	 														*/
/*测试时还没有发现此包*/
/************************************************************************/
void TDSAnalysis::fn_TDS_BULK()
{
	cout << "......................... " << endl;
}