// M_TDS_Parase.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "M_Pcap.h"

int main(int argc, char **argv)
{
	M_Pcap mcap;

	mcap.startParseTds();
	return 0;
}
