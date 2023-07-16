#include <Windows.h>
#include "ArkMouseKeyBoard.h"
#include "ArkDrvlib.h"
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

const int ArkMouseKeyBoard::nf_GetMouseKeyInfoData(LPVOID pData, const DWORD MouseKeyboardinfoSize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!pData)
		return false;
	do {

		if (false == g_mousekeyboardobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSYSMOUSEKEYBOARDDATA,
			NULL,
			inSize,
			pData,
			MouseKeyboardinfoSize,
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