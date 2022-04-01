#include <Windows.h>
#include "ArkFsd.h"
#include "drvlib.h"
#include <iostream>

#define CTL_DEVCTRL_ARK_GETSYSFSDDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1040, METHOD_BUFFERED, FILE_ANY_ACCESS)

using namespace std;

static DevctrlIoct g_devobj;

ArkFsd::ArkFsd()
{

}

ArkFsd::~ArkFsd()
{

}

bool ArkFsd::nf_GetFsdInfo(LPVOID outBuf, const DWORD Fsdinfosize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!outBuf)
		return false;

	do {

		if (false == g_devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSYSFSDDATA,
			NULL,
			inSize,
			outBuf,
			Fsdinfosize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(ULONG64))
			return true;

	} while (FALSE);

	return false;
}

