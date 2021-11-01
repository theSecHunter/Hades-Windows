#include "ArkDpcTimer.h"
#include <Windows.h>
#include "devctrl.h"
#include <iostream>

using namespace std;

#define CTL_DEVCTRL_ARK_GETDPCTIMERDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1020, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct devobj;

typedef struct _DPC_TIMERINFO
{
	ULONG_PTR	dpc;
	ULONG_PTR	timerobject;
	ULONG_PTR	timeroutine;
	ULONG		period;
}DPC_TIMERINFO, * PDPC_TIMERINFO;

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

		if (dwSize > 0)
		{
			dpcinfo = (DPC_TIMERINFO*)outBuf;
			for (int i = 0; i < 0x100; ++i)
			{
				if(dpcinfo[i].dpc)
					cout << hex << "index: " << i << " - dpc: " << dpcinfo[i].dpc << " - time: " << dpcinfo[i].period << " - timer: " << dpcinfo[i].timeroutine << endl;
			}
		}

	} while (FALSE);

}