#include "M_Pcap.h"

M_Pcap::M_Pcap()
{
	remove(F_SQLBATCH);
	remove(F_ATTENTION);
	remove(F_PRELOGIN);
	remove(F_REPLY);
	remove(F_RPC);
	remove(F_UNKNOWN);
	remove(F_SSPI);
};
M_Pcap::~M_Pcap() {};
//返回0初始化成功
bool M_Pcap::initPcap()
{
	pcap_if_t *alldevs, *d;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "port 1433";	// the filter
	struct bpf_program fcode;
	int netmask = 0xffffff;
	printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
	printf("   Usage: pktdump_ex [-s source]\n\n"
		   "   Examples:\n"
		   "      pktdump_ex -s file.acp\n"
		   "      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

	printf("\nNo adapter selected: printing the device list:\n");
	/* The user didn't provide a pac ket source: Retrieve the local device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return false;
	}
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return false;
	}
	printf("Enter the interface number (1-%d):", i);
	//std::cin>>inum;
	inum = 3;//目前设置为3
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return false;
	}
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,	// name of the device
		65536,							// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,								// promiscuous mode (nonzero means promiscuous)
		1000,							// read timeout
		errbuf							// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return false;
	}
	if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) < 0)
	{
		printf("Error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}
	if (pcap_setfilter(fp, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter\n");

		pcap_close(fp);
		return false;
	}
	TDS_ID = 0;
	return true;
}
bool M_Pcap::getNextTds()
{
	int res;
	while ((res = pcap_next_ex(fp, &pkt_info, &pkt_data)) == 0);
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return false;
	}
	TDS_ID++;
	cout <<"ID:"<< TDS_ID << "\n";
	return true;
}
void M_Pcap::startParseTds()
{
	if (!initPcap())
	{
		cout << "init pcap failed";
		return;
	}
	
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint16_t srcPort;
	uint16_t dstPort;

	KEY_TYPE linkID;
	
	bool isC2S = true;
	int tcpLen = 0;
	int tcpBodyOffset = 0;
	int tcpBodyLen = 0;
	uint32_t seq = 0;
	uint32_t ack = 0;
	int kk = 0;
	std::shared_ptr<TDSConn> tdsConn = NULL;

	while (true)
	{
        cout << "----------tdsConnMap.size()--" << tdsConnMap.size() << "---------------- - \n";
        //std::map<KEY_TYPE, std::shared_ptr<TDSConn>>::iterator it;
        //for (it = tdsConnMap.begin(); it != tdsConnMap.end(); ++it)
        //	cout << it->first << "---";
        //cout << endl;
        cout << "----------finTimeNum.size()--" << finTimeNum.size() << "---------------- - \n";
        //std::map<KEY_TYPE, uint32_t>::iterator it1;
        //for (it1 = finTimeNum.begin(); it1 != finTimeNum.end(); ++it1)
        //	cout << it1->first << "---value:"<<it1->second<<endl;
		if (!getNextTds())return;

		srcAddr = htonl(*((uint32_t*)(pkt_data + 26)));
		dstAddr = htonl(*((uint32_t*)(pkt_data + 30)));
		srcPort = htons(*((uint16_t*)(pkt_data + 34)));
		dstPort = htons(*((uint16_t*)(pkt_data + 36)));

		isC2S = ((dstPort == 1433) ? true : false);

		
		linkID = hashForTcpConn(srcAddr, srcPort, dstAddr, dstPort);
	
		
		if (finTimeNum.find(linkID) != finTimeNum.end())
		{
			finTimeNum[linkID]++;
			//cout << "----------finTimeNum.num--" << finTimeNum[linkID] << "---------------- - \n";
			if (finTimeNum[linkID] == 4)
			{
				tdsConnMap.erase(linkID);
				finTimeNum.erase(linkID);
				continue;
			}
		}
		if ((pkt_data[47] & 0x01) == 1 && !tdsConnMap.empty())
		{
			if (finTimeNum.find(linkID) == finTimeNum.end())
			{
				finTimeNum.insert(make_pair(linkID, 1));
			}
		}
		
		if (tdsConnMap.find(linkID) == tdsConnMap.end())
		{
			//TDSConn newTdsConn(srcAddr, srcPort, dstAddr, dstPort, pkt_info->ts.tv_usec);
			std::shared_ptr<TDSConn> conn_ptr(new TDSConn(srcAddr, srcPort, dstAddr, dstPort, pkt_info->ts.tv_usec));
			tdsConnMap.insert(make_pair(linkID, conn_ptr));
			tdsConn = conn_ptr;
		}
		else
		{
			tdsConn = tdsConnMap[linkID];
		}
		//tcp头的长度
		tcpLen = (pkt_data[46] >> 2);
		tcpBodyOffset = 34 + tcpLen;

		seq = htonl(*((uint32_t*)(pkt_data + 38)));
		tcpBodyLen = pkt_info->caplen - tcpBodyOffset;

		tdsConn->process(isC2S, (uint8_t *)(pkt_data + tcpBodyOffset), tcpBodyLen, seq, ack, pkt_info->ts.tv_usec, *pkt_info);
	}
}
