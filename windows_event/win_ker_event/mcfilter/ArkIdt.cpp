#include <Windows.h>
#include "ArkIdt.h"
#include "devctrl.h"
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

bool ArkIdt::nf_GetIdtData()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	char* outBuf = NULL;
	const DWORD idtinfosize = sizeof(IDTINFO) * 0x100;
	outBuf = new char[idtinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, idtinfosize);
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
			break;
		}

		if (dwSize > 0)
		{
			IDTINFO* idtinfo = (IDTINFO*)outBuf;
			if (!idtinfo)
			{
				OutputDebugString(L"Kernel Get Idt Failuer");
				return false;
			}

			OutputDebugString(L"Get IdtInfo Success");

			cout << "SystemCurrent Idt Info:" << endl;
			int i = 0;
			for (i = 0; i < 0x100; ++i)
			{
				if (!idtinfo[i].idt_isrmemaddr)
					break;

				cout << hex << "Index: " << idtinfo[i].idt_id << " - IdtAddr: " << idtinfo[i].idt_isrmemaddr << endl;
			}
			cout << "SystemCurrent Idt End:" << endl;
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