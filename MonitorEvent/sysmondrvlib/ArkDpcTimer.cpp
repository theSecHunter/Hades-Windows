#include <Windows.h>
#include "ArkDpcTimer.h"
#include "ArkDrvlib.h"
#include <iostream>
#include "sysinfo.h"

using namespace std;

#define CTL_DEVCTRL_ARK_GETDPCTIMERDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1020, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct devobj;

ArkDpcTimer::ArkDpcTimer()
{
}

ArkDpcTimer::~ArkDpcTimer()
{

}

const bool ArkDpcTimer::nf_GetDpcTimerData(LPVOID pData, const DWORD DpcTimerinfoSize)
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	if (!pData)
		return false;

	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETDPCTIMERDATA,
			NULL,
			inSize,
			pData,
			DpcTimerinfoSize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(DPC_TIMERINFO))
			return true;

	} while (FALSE);

	return false;
}