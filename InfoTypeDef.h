/*
InfoTypeDef.h
定义TDS所有版本标识
定义TDS包类型标识
定义TDS Token类型标识
*/

#ifndef __INFOTYPEDEF_H__
#define __INFOTYPEDEF_H__

//tds protocol versions
#define TDS70         0x70000000
#define TDS71         0x71000000
#define TDS71rev1     0x71000001
#define TDS72         0x72090002
#define TDS73A        0x730A0003
#define TDS73         TDS73A
#define TDS73B        0x730B0003
#define TDS74         0x74000004
//*# */packet types
#define TDS_QUERY         1
#define TDS_LOGIN         2
#define TDS_RPC           3
#define TDS_REPLY         4
#define TDS_ATTENTION     6
#define TDS_BULK          7
#define TDS7_TRANS        14  //transaction management
#define TDS_NORMAL        15
#define TDS7_LOGIN        16	//在测试中并没发现此包类型
#define TDS7_SSPI         17
#define TDS7_PRELOGIN     18

//tds Token Define
#define TDS_ALTMETADATA_TOKEN       0x88
#define TDS_ALTROW_TOKEN            0xD3
#define TDS_COLINFO_TOKEN           0xA5
#define TDS_COLMETADATA_TOKEN       0x81
#define TDS_DONE_TOKEN              0xFD
#define TDS_DONEINPROC_TOKEN        0xFF
#define TDS_DONEPROC_TOKEN          0xFE
#define TDS_ENVCHANGE_TOKEN         0xE3
#define TDS_ERROR_TOKEN             0xAA
#define TDS_FEATUREEXTACK_TOKEN     0xAE
#define TDS_FEDAUTHINFO_TOKEN       0xEE
#define TDS_INFO_TOKEN              0xAB
#define TDS_LOGINACK_TOKEN          0xAD
#define TDS_NBCROW_TOKEN            0xD2
#define TDS_OFFSET_TOKEN            0x78 //(removed in TDS 7.2)
#define TDS_ORDER_TOKEN             0xA9
#define TDS_RETURNSTATUS_TOKEN      0x79
#define TDS_RETURNVALUE_TOKEN       0xAC
#define TDS_ROW_TOKEN               0xD1
#define TDS_SESSIONSTATE_TOKEN      0xE4
#define TDS_SSPI_TOKEN              0xED
#define TDS_TABNAME_TOKEN           0xA4
#define TDS_TVPROW_TOKEN            0x01


#endif