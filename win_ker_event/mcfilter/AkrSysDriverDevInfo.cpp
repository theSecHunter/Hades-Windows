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

bool AkrSysDriverDevInfo::nf_EnumSysMod()
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	char* outBuf = NULL;
	bool	status = false;
	// 默认当前系统有1000个线程
	const DWORD proessinfosize = sizeof(PROCESS_MOD) * 1024 * 2;
	outBuf = new char[proessinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, proessinfosize);
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
			status = false;
			break;
		}

		if (dwSize > 0)
		{
			PPROCESS_MOD modptr = (PPROCESS_MOD)outBuf;
			if (modptr)
			{
				int i = 0; 
				for (i = 0; i < 1024 * 2; ++i)
				{
					if (0 == modptr[i].EntryPoint && 0 == modptr[i].SizeOfImage && 0 == modptr[i].DllBase)
						continue;

					wcout << "DllName: " << modptr[i].FullDllName << " - DllBase: " << modptr[i].DllBase << endl;

				}
			}

			status = true;
		}

	} while (false);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return status;
}

bool AkrSysDriverDevInfo::nf_GetDriverInfo()
{
}

bool AkrSysDriverDevInfo::nf_DumpDriverInfo()
{

}