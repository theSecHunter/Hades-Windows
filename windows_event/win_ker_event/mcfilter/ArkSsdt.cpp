#include <Windows.h>
#include "devctrl.h"
#include "ArkSsdt.h"
#include "sysinfo.h"

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

		if (false == devobj.devctrl_sendioct(CTL_DEVCTRL_ARK_INITSSDT, NULL, inSize, &outBuf, outSize, dwSize))
			break;

		if (outBuf == 1)
			return true;
	
	} while (false);


	return false;

}

bool ArkSsdt::nf_GetSysCurrentSsdtData()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	char* outBuf = NULL;
	const DWORD ssdtinfosize = sizeof(SSDTINFO) * 0x200;
	outBuf = new char(ssdtinfosize);
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, ssdtinfosize);

	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSSDTDATA,
			NULL,
			inSize,
			&outBuf,
			ssdtinfosize,
			dwSize)
			)
		{
			break;
		}

		if (dwSize > 0)
		{
			OutputDebugString(L"Get SsdtInfo Success");
		}
			
	} while (false);

	if (outBuf)
	{
		delete outBuf;
		outBuf = NULL;
	}

	return false;
}