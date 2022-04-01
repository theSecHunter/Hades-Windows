#include <Windows.h>
#include "ArkIdt.h"
#include "drvlib.h"
#include "sysinfo.h"
#include <iostream>

using namespace std;

#define CTL_DEVCTRL_ARK_INITIDT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_GETIDTDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1011, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct devobj;

ArkIdt::ArkIdt()
{
}

ArkIdt::~ArkIdt()
{

}

bool ArkIdt::nf_init()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	DWORD outBuf = 0;
	DWORD outSize = sizeof(DWORD);

	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_INITIDT,
			NULL,
			inSize,
			&outBuf,
			outSize,
			dwSize))
		{
			break;
		}

		if (outBuf == 1)
			return true;
	} while (false);


	return false;
}

bool ArkIdt::nf_GetIdtData(LPVOID outBuf, const DWORD idtinfosize)
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	if (!outBuf)
		return false;

	do {
		
		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETIDTDATA,
			NULL,
			inSize,
			outBuf,
			idtinfosize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(IDTINFO))
			return true;

	} while (false);

	return false;
}