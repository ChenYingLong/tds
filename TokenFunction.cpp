#include <iomanip>
#include <fstream>
#include <pcap.h>
#include "TDSAnalysis.h"
#include "InfoTypeDef.h"
using namespace std;


void TDSAnalysis::fn_COLMETADATA_TOKEN(ofstream& fileOut)
{
	const u_char *tds = tds_data;

	fileOut<<"<PacketData>\n";
	fileOut<<"	<TableResponse>\n";
	fileOut<<"		<COLMETADATA>\n";
	int tdsPtr = 8;
	int tokenType = (int)tds[tdsPtr];
	fileOut<<"			<TokenType>\n";
	fileOut<<"				"<<setw(2)<<(int)tds[tdsPtr]<<endl;
	fileOut<<"			</TokenType>\n";
	tdsPtr+=1;
	fileOut<<"			<Count>\n";
	fileOut<<"				"<<setw(2)<<(int)tds[tdsPtr]<<setw(2)<<(int)tds[tdsPtr+1]<<endl;
	fileOut<<"			</Count>\n";
	tds+=2;

	if (tds[tdsPtr] == 0xFF && tds[tdsPtr + 1] == 0xFF)
	{
		fileOut << "				NoMetaData\n";
		fileOut << "			</ColumnData>\n";
		fileOut << "		</COLMETADATA>\n";
		fileOut << "	</TableResponse>\n";
		fileOut << "</PacketData>\n";
	}
	if (TDS_VERSION == TDS74)
	{ 
		//tds7.4版本还添加了CekTable
	}
	fileOut<<"			<ColumnData>>\n";
	fileOut<<"				<UserType>\n";
	if (TDS_VERSION < TDS72)
	{
		//tds7.2之前的版本UserType为两个字节，7.2及以后为四个字节
	}
	fileOut<<"					"<<setw(2)<<(int)tds[tdsPtr]<<setw(2)<<(int)tds[tdsPtr+1]<<setw(2)<<(int)tds[tdsPtr+2]<<setw(2)<<(int)tds[tdsPtr+3]<<endl;
	fileOut<<"				</UserType>\n";
	tds+=4;
	fileOut<<"				<Flags>\n";
	fileOut<<"					"<<setw(2)<<(int)tds[tdsPtr]<<setw(2)<<(int)tds[tdsPtr+1]<<endl;
	fileOut<<"				</Flags>\n";
	tds+=2;
	fileOut<<"				<TYPE_INFO>\n";
	fileOut<<"					<VARLENTYPE>\n";
	//u_char
	fileOut<<"						<USHORTLEN_TYPE>\n";
	fileOut<<"							"<<setw(2)<<(int)tds[tdsPtr]<<endl;
	fileOut<<"						</USHORTLEN_TYPE>\n";
	fileOut<<"					</VARLENTYPE>\n";
	tds+=1;
	fileOut<<"					<TYPE_VARLEN>\n";
	fileOut<<"						<USHORTCHARBINLEN>\n";
	fileOut<<"							"<<setw(2)<<(int)tds[tdsPtr]<<setw(2)<<(int)tds[tdsPtr+1]<<endl;
	fileOut<<"						</USHORTCHARBINLEN>\n";
	fileOut<<"					</TYPE_VARLEN>\n";
	tds+=2;
	fileOut << "				<COLLATION>\n";
	fileOut << "				<COLLATION>\n";
	fileOut<<"				    </COLLATION>\n";

	fileOut<<"				</TYPE_INFO>\n";

	fileOut<<"			</ColumnData>\n";
	fileOut<<"		</COLMETADATA>\n";
	fileOut<<"	</TableResponse>\n";
	fileOut<<"</PacketData>\n";
}
