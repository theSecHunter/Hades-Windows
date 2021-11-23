#include "ArkDpcTimer.h"
#include <Windows.h>
#include "devctrl.h"
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

bool ArkDpcTimer::nf_GetDpcTimerData()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	char* outBuf = NULL;
	bool  status = false;
	const DWORD DpcTimerinfosize = sizeof(DPC_TIMERINFO) * 0x200;
	outBuf = new char[DpcTimerinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, DpcTimerinfosize);
	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETDPCTIMERDATA,
			NULL,
			inSize,
			outBuf,
			DpcTimerinfosize,
			dwSize)
			)
		{
			break;
		}

		DPC_TIMERINFO* dpcinfo = NULL;

		if (dwSize > sizeof(DPC_TIMERINFO))
		{
			dpcinfo = (DPC_TIMERINFO*)outBuf;
			for (int i = 0; i < 0x100; ++i)
			{
				if(dpcinfo[i].dpc)
					cout << hex << "index: " << i << " - dpc: " << dpcinfo[i].dpc << " - time: " << dpcinfo[i].period << " - timer: " << dpcinfo[i].timeroutine << endl;
			}

			status = true;
		}

	} while (FALSE);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return 1;
}