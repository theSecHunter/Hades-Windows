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

const int ArkNetwork::nf_GetNteworkProcessInfo(LPVOID pData, const DWORD64 NetworkinfoSize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!pData)
		return false;
	do {

		if (false == g_networkobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSYNETWORKDDATA,
			NULL,
			inSize,
			pData,
			NetworkinfoSize,
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
