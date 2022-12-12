#include <Windows.h>
#include "ArkNetwork.h"
#include "ArkDrvlib.h"
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

int ArkNetwork::nf_GetNteworkProcessInfo(LPVOID outBuf, const DWORD64 Networkinfosize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!outBuf)
		return false;
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
			return false;
		}

		if (dwSize <= 0)
			return false;

	} while (FALSE);

	return true;
}
