#include <Windows.h>
#include "ArkNetwork.h"
#include "devctrl.h"
#include <iostream>

#pragma comment (lib,"Ws2_32.lib")

#include <winsock.h>

using namespace std;

#define CTL_DEVCTRL_ARK_GETSYNETWORKDDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1060, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct g_networkobj;

typedef struct _NSI_STATUS_ENTRY
{
	ULONG  dwState;
	char bytesfill[8];
}NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;

typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
{
	char	bytesfill0[2];
	USHORT	Port;
	ULONG	dwIP;
	char	bytesfill[20];
}INTERNAL_TCP_TABLE_SUBENTRY, * PINTERNAL_TCP_TABLE_SUBENTRY;

typedef struct _INTERNAL_TCP_TABLE_ENTRY
{
	INTERNAL_TCP_TABLE_SUBENTRY localEntry;
	INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;
}INTERNAL_TCP_TABLE_ENTRY, * PINTERNAL_TCP_TABLE_ENTRY;

typedef struct _NSI_PROCESSID_INFO
{
	ULONG dwUdpProId;
	ULONG UnknownParam2;
	ULONG UnknownParam3;
	ULONG dwTcpProId;
	ULONG UnknownParam5;
	ULONG UnknownParam6;
	ULONG UnknownParam7;
	ULONG UnknownParam8;
}NSI_PROCESSID_INFO, * PNSI_PROCESSID_INFO;

typedef struct _INTERNAL_UDP_TABLE_ENTRY
{
	char bytesfill0[2];
	USHORT Port;
	ULONG dwIP;
	char bytesfill[20];
}INTERNAL_UDP_TABLE_ENTRY, * PINTERNAL_UDP_TABLE_ENTRY;

typedef struct _SYSTPCINFO
{
	NSI_STATUS_ENTRY			socketStatus;
	NSI_PROCESSID_INFO			processinfo;
	INTERNAL_TCP_TABLE_ENTRY	TpcTable;
}SYSTPCINFO;

typedef struct _SYSUDPINFO
{
	NSI_PROCESSID_INFO			processinfo;
	INTERNAL_UDP_TABLE_ENTRY	UdpTable;
}SYSUDPINFO;

typedef struct _SYSNETWORKINFONODE
{
	DWORD			tcpcout;
	DWORD			udpcout;
	SYSTPCINFO		systcpinfo[1000];
	SYSUDPINFO		sysudpinfo[1000];
}SYSNETWORKINFONODE, * PSYSNETWORKINFONODE;

ArkNetwork::ArkNetwork()
{

}

ArkNetwork::~ArkNetwork()
{

}

int ArkNetwork::nf_GetNteworkProcessInfo()
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	char*	outBuf = NULL;
	bool	status = false;
	const DWORD64 Networkinfosize = sizeof(SYSNETWORKINFONODE);
	outBuf = new char[Networkinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, Networkinfosize);
	do {

		if (false == g_networkobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSYNETWORKDDATA,
			NULL,
			inSize,
			outBuf,
			Networkinfosize,
			dwSize)
			)
		{
			break;
		}

		if (dwSize <= 0)
			break;

		int i = 0; 
		PSYSNETWORKINFONODE networkinfo = (PSYSNETWORKINFONODE)outBuf;
		if (!networkinfo)
			return -1;

		// Tcp
		for (i = 0; i < networkinfo->tcpcout; ++i)
		{
			cout << "Pid: " << networkinfo->systcpinfo[i].processinfo.dwTcpProId \
				<< " - LocalIp: " << networkinfo->systcpinfo[i].TpcTable.localEntry.dwIP << ":" << ntohs(networkinfo->systcpinfo[i].TpcTable.localEntry.Port) \
				<< " - RemoteIp: " << networkinfo->systcpinfo[i].TpcTable.remoteEntry.dwIP << ":" << ntohs(networkinfo->systcpinfo[i].TpcTable.remoteEntry.Port) \
				<< " - Status: " << networkinfo->systcpinfo[i].socketStatus.dwState << endl;
		}

		for (i = 0; i < networkinfo->udpcout; ++i)
		{
			cout << "Pid: " << networkinfo->sysudpinfo[i].processinfo.dwUdpProId \
				<< " - LocalIp: " << networkinfo->sysudpinfo[i].UdpTable.dwIP << ":" << ntohs(networkinfo->sysudpinfo[i].UdpTable.Port) << endl;
		}

		status = true;

	} while (FALSE);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return status;
}
