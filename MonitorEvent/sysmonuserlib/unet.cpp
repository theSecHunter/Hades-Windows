#include <Windows.h>
#include "unet.h"

#include <iphlpapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <sysinfo.h>

UNet::UNet()
{
}

UNet::~UNet()
{

}

static char TcpState[][32] =
{
	"???",
	"CLOSED",
	"LISTENING",
	"SYN_SENT",
	"SEN_RECEIVED",
	"ESTABLISHED",
	"FIN_WAIT",
	"FIN_WAIT2",
	"CLOSE_WAIT",
	"CLOSING",
	"LAST_ACK",
	"TIME_WAIT"
};

DWORD EnumTCPTable()
{
	PMIB_TCPTABLE pTcpTable = NULL;
	DWORD dwSize = 0; DWORD dwRetVal = 0;

	struct   in_addr rip;
	struct   in_addr lip;
	char  szrip[32] = { 0 };
	char  szlip[32] = { 0 };

	// 获得pTcpTable所需要的真实长度,dwSize
	if (GetTcpTable(pTcpTable, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER)
	{
		pTcpTable = (MIB_TCPTABLE*)malloc((UINT)dwSize);
		if (!pTcpTable)
			return 0;
	}
	else
		return 0;

	if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR)
	{
		for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
		{
			rip.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
			lip.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
			// 监听端口，远程主机端口为0，但函数返回是有值的，不知道它是怎么考虑的
			if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN)
				pTcpTable->table[i].dwRemotePort = 0;

			//dwLocalPort，dwRemotePort 是网络字节
			//_snprintf(szlip, sizeof(szlip), "%s:%d", inet_ntoa(lip), htons((u_short)pTcpTable->table[i].dwLocalPort));
			//_snprintf(szrip, sizeof(szrip), "%s:%d", inet_ntoa(rip), htons((u_short)pTcpTable->table[i].dwRemotePort));
			// printf("  TCP\t%-24s%-24s%s\n", szlip, szrip, TcpState[pTcpTable->table[i].dwState]);
		}
	}
	else
	{
		// printf("\tCall to GetTcpTable failed.\n");

		LPVOID lpMsgBuf;

		if (FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwRetVal,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR)&lpMsgBuf,
			0,
			NULL))
		{
			//printf("\tError: %s", lpMsgBuf);
		}
		LocalFree(lpMsgBuf);
	}

	if (pTcpTable) {
		free(pTcpTable);
		pTcpTable = NULL;
	}
	return dwRetVal;
}
DWORD EnumUDPTable()
{
	PMIB_UDPTABLE pUdpTable = NULL;
	DWORD dwSize = 0; DWORD dwRetVal = 0;

	// struct   in_addr rip;
	struct   in_addr lip;
	// char  szrip[32] = {0};
	char  szlip[32] = { 0 };

	//获得pUdpTable所需要的真实长度,dwSize
	if (GetUdpTable(pUdpTable, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER)
	{
		pUdpTable = (MIB_UDPTABLE*)malloc((UINT)dwSize);
		if (!pUdpTable)
			return 0;
	}
	else
		return dwRetVal;

	//printf("Active Connections\n\n");
	//printf("  Proto\t%-24s%-24s\n", "Local Addr", "Local Port");

	if ((dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE)) == NO_ERROR)
	{
		for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++)
		{
			// rip.S_un.S_addr = pUdpTable->table[i].dwRemoteAddr;
			lip.S_un.S_addr = pUdpTable->table[i].dwLocalAddr;
			//监听端口，远程主机端口为0，但函数返回是有值的，不知道它是怎么考虑的
			// if (pUdpTable->table[i].dwState == MIB_Udp_STATE_LISTEN)   
			// pUdpTable->table[i].dwRemotePort = 0;

			//dwLocalPort，dwRemotePort 是网络字节
			//_snprintf(szlip, sizeof(szlip), "%s:%d", inet_ntoa(lip), htons((u_short)pUdpTable->table[i].dwLocalPort));
			// _snprintf(szrip,sizeof(szrip),"%s:%d",inet_ntoa(rip),htons((u_short)pTcpTable->table[i].dwRemotePort));
			// printf("  TCP\t%-24s%-24s%s\n",szlip,szrip,TcpState[pTcpTable->table[i].dwState]);
			//printf("  UDP\t%-24s\n", szlip);
		}
	}
	else
	{

		LPVOID lpMsgBuf;

		if (FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwRetVal,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR)&lpMsgBuf,
			0,
			NULL))
		{
			//printf("\tError: %s", lpMsgBuf);
		}
		LocalFree(lpMsgBuf);
	}
	// GlobalFree(pUdpTable);
	if (pUdpTable != NULL) {
		free(pUdpTable);
		pUdpTable = NULL;
	}
	return dwRetVal;
}

DWORD EnumTCPTablePid(UNetTcpNode* outbuf)
{
	PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
	DWORD dwSize(0);
	struct   in_addr rip;
	struct   in_addr lip;
	char  szrip[32] = { 0 };
	char  szlip[32] = { 0 };
	char PidString[20] = { '\0' };
	if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER)
	{
		//重新分配缓冲区
		pTcpTable = (MIB_TCPTABLE_OWNER_PID*)new char[dwSize];
		if (!pTcpTable)
			return 0;
	}

	if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
	{
		if (pTcpTable)
			delete[] pTcpTable;
		return 0;
	}

	//TCP连接的数目
	DWORD nNum = 0;
	if (pTcpTable)
		nNum = pTcpTable->dwNumEntries; 

	for (int i = 0; i < nNum; i++)
	{

		rip.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
		lip.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;

		//监听端口，远程主机端口为0，但函数返回是有值的，不知道它是怎么考虑的
		if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN)
			pTcpTable->table[i].dwRemotePort = 0;

		//dwLocalPort，dwRemotePort 是网络字节
		_snprintf_s(szlip, sizeof(szlip), "%s:%d", inet_ntoa(lip), htons((u_short)pTcpTable->table[i].dwLocalPort));
		_snprintf_s(szrip, sizeof(szrip), "%s:%d", inet_ntoa(rip), htons((u_short)pTcpTable->table[i].dwRemotePort));
		_ultoa_s(pTcpTable->table[i].dwOwningPid, PidString, 10);

		RtlCopyMemory(outbuf[i].szlip, szlip, sizeof(szlip));
		RtlCopyMemory(outbuf[i].szrip, szrip, sizeof(szrip));
		RtlCopyMemory(outbuf[i].TcpState, TcpState[pTcpTable->table[i].dwState], 32);
		RtlCopyMemory(outbuf[i].PidString, PidString, sizeof(PidString));

	}

	if (pTcpTable)
		delete[] pTcpTable;
	return nNum;
}
DWORD EnumUDPTablePid(UNetUdpNode* outbuf)
{
	PMIB_UDPTABLE_OWNER_PID pUdpTable(NULL);
	DWORD dwSize(0);
	struct   in_addr lip;
	char  szrip[32] = { 0 };
	char  szlip[32] = { 0 };
	char PidString[20] = { '\0' };
	if (GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER)
	{
		//重新分配缓冲区
		pUdpTable = (MIB_UDPTABLE_OWNER_PID*)new char[dwSize];
		if (!pUdpTable)
			return 0;
	}
	if (GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
	{
		if (pUdpTable)
			delete[] pUdpTable;
		return 0;
	}

	//UDP连接的数目
	DWORD nNum = 0;
	if (pUdpTable)
		nNum = (int)pUdpTable->dwNumEntries;

	for (int i = 0; i < nNum; i++)
	{

		lip.S_un.S_addr = pUdpTable->table[i].dwLocalAddr;
		//dwLocalPort，dwRemotePort 是网络字节
		_snprintf_s(szlip, sizeof(szlip), "%s:%d", inet_ntoa(lip), htons((u_short)pUdpTable->table[i].dwLocalPort));
		_ultoa_s(pUdpTable->table[i].dwOwningPid, PidString, 10);

		RtlCopyMemory(outbuf[i].szrip, szlip, sizeof(szlip));
		RtlCopyMemory(outbuf[i].PidString, PidString, sizeof(PidString));

	}

	if (pUdpTable)
		delete[] pUdpTable;

	return nNum;
}

bool UNet::uf_EnumNetwork(LPVOID outbuf)
{
	if (!outbuf)
		return false;

	PUNetNode netnode = (PUNetNode)outbuf;
	if (!netnode)
		return false;

	netnode->tcpnumber = EnumTCPTablePid(netnode->tcpnode);
	netnode->udpnumber = EnumUDPTablePid(netnode->udpnode);

	return true;
}