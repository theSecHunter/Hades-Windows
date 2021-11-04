#include <Windows.h>
#include "ArkFsd.h"
#include "devctrl.h"
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

bool ArkFsd::nf_GetFsdInfo()
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	char*	outBuf = NULL;
	bool	status = false;
	const DWORD Fsdinfosize = sizeof(ULONGLONG) * 0x1d * 2 + 1;
	outBuf = new char[Fsdinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, Fsdinfosize);
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
			break;
		}

		if (dwSize == 0)
			break;

		int  i = 0;
		int index = 0;
		ULONGLONG* MjAddrArry = (ULONGLONG*)outBuf;
		if (!MjAddrArry)
		{
			status = false;
			break;
		}
		cout << "FastFat MjFuction Start" << endl;
		for (i = 0; i < 0x1d; ++i)
		{
			cout << hex << "Mj_Id: " << i << " - MjAddr: " << MjAddrArry[index] << endl;
			index++;
		}
		cout << "FastFat MjFuction End" << endl;
		cout << "Ntfs MjFuction Start" << endl;
		for (i = 0; i < 0x1d; ++i) 
		{
			cout << hex << "Mj_Id: " << i << " - MjAddr: " << MjAddrArry[index] << endl;
			index++;
		}
		cout << "Ntfs MjFuction End" << endl;

		status = true;

	} while (FALSE);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return status;
}

