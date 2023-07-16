#include <Windows.h>
#include "ArkSysDriverDevInfo.h"
#include "ArkDrvlib.h"
#include <iostream>
#include "sysinfo.h"

using namespace std;

#define CTL_DEVCTRL_ARK_DRIVERDEVENUM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1080, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct devobj;

AkrSysDriverDevInfo::AkrSysDriverDevInfo()
{
}

AkrSysDriverDevInfo::~AkrSysDriverDevInfo()
{
}

const bool AkrSysDriverDevInfo::nf_EnumSysMod(LPVOID pData, const DWORD proessinfoSize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!pData)
		return false;
	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_DRIVERDEVENUM,
			NULL,
			inSize,
			pData,
			proessinfoSize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(PPROCESS_MOD))
			return true;

	} while (false);

	return false;
}

const bool AkrSysDriverDevInfo::nf_GetDriverInfo()
{
	return true;
}

const bool AkrSysDriverDevInfo::nf_DumpDriverInfo()
{
	return true;
}