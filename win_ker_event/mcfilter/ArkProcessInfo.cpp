#include <Windows.h>
#include "ArkProcessInfo.h"
#include "devctrl.h"
#include "sysinfo.h"

#include <iostream>
#include <map>
#include <string>

using namespace std;

#define CTL_DEVCTRL_ARK_PROCESSINFO \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1070, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_PROCESSMOD \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1071, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_PROCESSDUMP \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1072, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_PROCESSKILL \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1073, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_PROCESSTHEAD \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1074, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_PROCESSENUM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1075, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct devobj;

ArkProcessInfo::ArkProcessInfo()
{

}

ArkProcessInfo::~ArkProcessInfo()
{

}

bool ArkProcessInfo::nf_GetProcessInfo()
{

}

bool ArkProcessInfo::nf_GetProcessMod(DWORD Pid, LPVOID outBuf, const DWORD proessinfosize)
{
	DWORD	inSize = sizeof(DWORD);
	DWORD	dwSize = 0;
	if (!outBuf)
		return false;

	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_PROCESSMOD,
			&Pid,
			inSize,
			outBuf,
			proessinfosize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(PPROCESS_MOD))
			return true;

	} while (false);

	return false;
}

bool ArkProcessInfo::nf_KillProcess()
{
	map<int, wstring> Process_list;
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	bool	status = false;

	inSize = sizeof(DWORD);
	DWORD KillPidIn = 0;
	DWORD KillPidOut = 0;

	cout << "Please Kill ProcessPid: ";
	scanf("%d", &KillPidIn);

	//devobj.devctrl_sendioct(
	//	CTL_DEVCTRL_ARK_PROCESSKILL,
	//	&KillPidIn,
	//	inSize,
	//	&KillPidOut,
	//	inSize,
	//	dwSize
	//);

	return status;
}

bool ArkProcessInfo::nf_DumpProcessMem()
{

}

bool ArkProcessInfo::nf_EnumProcess(LPVOID outBuf, const DWORD proessinfosize)
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	if (!outBuf)
		return false;
	do {

		if (false == devobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_PROCESSENUM,
			NULL,
			inSize,
			outBuf,
			proessinfosize,
			dwSize)
			)
		{
			return false;
		}

		if (dwSize >= sizeof(PHANDLE_INFO))
			return true;

	} while (false);

	return false;
}