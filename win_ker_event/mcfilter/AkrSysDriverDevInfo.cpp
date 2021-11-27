#include <Windows.h>
#include "AkrSysDriverDevInfo.h"
#include "devctrl.h"
#include <iostream>

using namespace std;

typedef struct _PROCESS_MOD
{
	ULONG	DllBase;
	ULONG	EntryPoint;
	ULONG	SizeOfImage;
	WCHAR	FullDllName[260];
	WCHAR	BaseDllName[260];
}PROCESS_MOD, * PPROCESS_MOD;

#define CTL_DEVCTRL_ARK_DRIVERDEVENUM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1080, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct devobj;

AkrSysDriverDevInfo::AkrSysDriverDevInfo()
{

}

AkrSysDriverDevInfo::~AkrSysDriverDevInfo()
{

}

bool AkrSysDriverDevInfo::nf_EnumSysMod(LPVOID outBuf, const DWORD proessinfosize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!outBuf)
		return false;
	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_DRIVERDEVENUM,
			NULL,
			inSize,
			outBuf,
			proessinfosize,
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

bool AkrSysDriverDevInfo::nf_GetDriverInfo()
{
	return true;
}

bool AkrSysDriverDevInfo::nf_DumpDriverInfo()
{
	return true;
}