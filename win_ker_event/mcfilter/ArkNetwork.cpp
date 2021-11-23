#include <Windows.h>
#include "ArkNetwork.h"
#include "devctrl.h"
#include <iostream>
#include "sysinfo.h"

#pragma comment (lib,"Ws2_32.lib")
#include <winsock.h>

using namespace std;

#define CTL_DEVCTRL_ARK_GETSYNETWORKDDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1060, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct g_networkobj;

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
