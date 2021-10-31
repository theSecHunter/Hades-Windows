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

bool ArkSsdt::nf_GetSysCurrentSsdtData()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	char* outBuf = NULL;
	const DWORD ssdtinfosize = sizeof(SSDTINFO) * 0x200;
	outBuf = new char[ssdtinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, ssdtinfosize);
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
			break;
		}

		if (dwSize > 0)
		{
			SSDTINFO* ssdtinfo = (SSDTINFO*)outBuf;
			if (!ssdtinfo)
			{
				OutputDebugString(L"Kernel Get Ssdt Failuer");
				return false;
			}

			OutputDebugString(L"Get SsdtInfo Success");
			
			cout << "SystemCurrent Ssdt Info:" << endl;
			int i = 0;
			for (i = 0; i < 0x200; ++i)
			{
				if (!ssdtinfo[i].sstd_memoffset)
					break;
							
				cout << hex << "Index: " << ssdtinfo[i].ssdt_id << " - offset: " << ssdtinfo[i].sstd_memoffset << " - SsdtAddr: " << ssdtinfo[i].sstd_memaddr << endl;
			}
			cout << "SystemCurrent Ssdt End:" << endl;
		}

		if (outBuf)
		{
			delete outBuf;
			outBuf = NULL;
		}

		return true;
			
	} while (false);

	return false;
}