#include <Windows.h>
#include "ArkMouseKeyBoard.h"
#include "devctrl.h"
#include <iostream>

using namespace std;

#define CTL_DEVCTRL_ARK_GETSYSMOUSEKEYBOARDDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1050, METHOD_BUFFERED, FILE_ANY_ACCESS)

DevctrlIoct g_mousekeyboardobj;

ArkMouseKeyBoard::ArkMouseKeyBoard()
{

}

ArkMouseKeyBoard::~ArkMouseKeyBoard()
{

}

int ArkMouseKeyBoard::nf_GetMouseKeyInfoData()
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	char*	outBuf = NULL;
	bool	status = false;
	const DWORD MouseKeyboardinfosize = sizeof(ULONGLONG) * 0x1b * 3 + 1;
	outBuf = new char[MouseKeyboardinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, MouseKeyboardinfosize);
	do {

		if (false == g_mousekeyboardobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSYSMOUSEKEYBOARDDATA,
			NULL,
			inSize,
			outBuf,
			MouseKeyboardinfosize,
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
		cout << "Mouse MjFuction Start" << endl;
		for (i = 0; i < 0x1b; ++i)
		{
			cout << hex << "Mj_Id: " << i << " - MjAddr: " << MjAddrArry[index] << endl;
			index++;
		}
		cout << "Mouse MjFuction End" << endl;

		cout << "i8042 MjFuction Start" << endl;
		for (i = 0; i < 0x1b; ++i)
		{
			cout << hex << "Mj_Id: " << i << " - MjAddr: " << MjAddrArry[index] << endl;
			index++;
		}
		cout << "i8042 MjFuction End" << endl;

		cout << "kbd MjFuction Start" << endl;
		for (i = 0; i < 0x1b; ++i)
		{
			cout << hex << "Mj_Id: " << i << " - MjAddr: " << MjAddrArry[index] << endl;
			index++;
		}
		cout << "kbd MjFuction End" << endl;

		status = true;

	} while (FALSE);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return status;
}