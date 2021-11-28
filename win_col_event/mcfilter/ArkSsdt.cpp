#include <Windows.h>
#include "devctrl.h"
#include "ArkSsdt.h"
#include "sysinfo.h"

#include <iostream>

using namespace std;

static DevctrlIoct devobj;

#define CTL_DEVCTRL_ARK_INITSSDT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_GETSSDTDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_ANY_ACCESS)

ArkSsdt::ArkSsdt()
{

}

ArkSsdt::~ArkSsdt()
{

}

bool ArkSsdt::nf_init()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	DWORD outBuf = 0;
	DWORD outSize = sizeof(DWORD);

	do {
		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_INITSSDT,
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

bool ArkSsdt::nf_GetSysCurrentSsdtData(LPVOID outBuf, const DWORD ssdtinfosize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!outBuf || !ssdtinfosize)
		return false;
	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSSDTDATA,
			NULL,
			inSize,
			outBuf,
			ssdtinfosize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(SSDTINFO))
			return true;

	} while (false);

	return false;
}