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
	const u_char *tds = tds_data ;
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
	const u_char *tds = tds_data ;
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
	int i = 7;
	fileOut << "<PacketData>\n";
	fileOut << "	<RPCRequest>\n";
	fileOut << "	  <All_HEADERS>\n";
	fileOut << "		<TotalLength>\n";
	//total_Length = tds[i + 1] + (tds[i + 2] << 8) + (tds[i + 2] << 16) + (tds[i + 2] << 24);
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

	fileOut << "		<RPCReqBatch>\n";

	fileOut << "			<NameLenProcID>\n";

	if (tds[i + 1] == 0xff && tds[i + 2] == 0xff)
	{
		fileOut << "			  <ProcIDSwitch>\n";
		fileOut << "			    " << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << "\n";
		fileOut << "			  </ProcIDSwitch>\n";
		i += 2;
		fileOut << "			  <ProcID>\n";
		fileOut << "			    " << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << endl;
		fileOut << "			  </ProcID>\n";
		i += 2;
	}
	else
	{
		fileOut << "			  <ProcName>\n";
		fileOut << "			    <US_UNICODE>\n";
		fileOut << "			      <USHORTLEN>\n";
		u_short ushortLen = tds[i + 1] + (tds[i + 2] << 8);
		fileOut << "			        " << setw(2) << (int)tds[i + 1] << setw(2) << (int)tds[i + 2] << endl;
		i += 2;
		fileOut << "			      </USHORTLEN>\n";
		fileOut << "			      <BYTES>";
		for (int j = i + 1; j < 2 * ushortLen + i + 1; j++)
			fileOut << tds[j++];
		i += 2 * ushortLen;
		fileOut << "			      </BYTES>\n";

		fileOut << "			    </US_UNICODE>\n";
		fileOut << "			  </ProcName>\n";
	}

	fileOut << "			</NameLenProcID>\n";

	fileOut << "			<OptionFlags>\n";
	fileOut << "			  <fWithRecomp>" << (tds[i + 1] & 0x01) << "</fWithRecomp>\n";
	fileOut << "			  <fNoMetaData>" << (tds[i + 1] & 0x02) << "</fNoMetaData>\n";
	fileOut << "			  <fReuseMetaData>" << (tds[i + 1] & 0x08) << "</fReuseMetaData>\n";
	fileOut << "			</OptionFlags>\n";
	i += 1;
	//TDS7.4版本还添加了一些其它的，此处未加入
	fileOut << "			<ParameterData>\n";
	fileOut << "			  <ParamMetaData>\n";
	fileOut << "			    <B_UNICODE>\n";
	fileOut << "			      <BYTELEN>\n";
	int byteLen = int(tds[i + 1]);
	fileOut << "			        " << setw(2) << byteLen << endl;
	i += 1;
	fileOut << "			      </BYTELEN>\n";
	fileOut << "			      <BYTES>";
	for (int j = i + 1; j < 2 * byteLen + i + 1; j++)
		fileOut << tds[j++];
	i += 2 * byteLen;
	fileOut << "			      </BYTES>\n";
	fileOut << "			    </B_UNICODE>\n";

	fileOut << "			    <StatusFlags>\n";
	fileOut << "				  <fByRefValue>" << (tds[i + 1] & 0x01) << "</fByRefValue>\n";
	fileOut << "				  <fDefaultValue>" << (tds[i + 1] & 0x02) << "</fDefaultValue>\n";
	fileOut << "				  <fEncrypted>" << (tds[i + 1] & 0x10) << "</fEncrypted>\n";
	fileOut << "			    </StatusFlags>\n";
	i += 1;

	//TDS7.3之后
	fileOut << "			    <TYPE_INFO>\n";
	fileOut << "			      <VARLENTYPE>\n";
	fileOut << "			        <BYTELEN_TYPE>\n";
	fileOut << "			          " << setw(2) << (int)tds[i + 1] << endl;
	fileOut << "			        </BYTELEN_TYPE>\n";
	i += 1;
	fileOut << "			      </VARLENTYPE>\n";

	fileOut << "			      <TYPE_VARLEN>\n";
	fileOut << "			        <BYTELEN>\n";
	fileOut << "			          " << setw(2) << (int)tds[i + 1] << endl;
	fileOut << "			        </BYTELEN>\n";
	i += 1;
	fileOut << "			      </TYPE_VARLEN>\n";
	fileOut << "			    </TYPE_INFO>\n";
	fileOut << "			  </ParamMetaData>\n";

	fileOut << "			  <ParamLenData>\n";
	fileOut << "			    <TYPE_VARBYTE>\n";
	fileOut << "			        <BYTELEN>\n";
	byteLen = int(tds[i + 1]);
	fileOut << "			          " << setw(2) << byteLen << endl;
	fileOut << "			        </BYTELEN>\n";
	i += 1;
	fileOut << "			      <BYTES>";
	for (int j = i + 1; j < 2 * byteLen + i + 1; j++)
		fileOut << tds[j++];
	i += 2 * byteLen;
	fileOut << "			      </BYTES>\n";

	fileOut << "			    </TYPE_VARBYTE>\n";
	fileOut << "			  </ParamLenData>\n";
	fileOut << "			</ParameterData>\n";
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