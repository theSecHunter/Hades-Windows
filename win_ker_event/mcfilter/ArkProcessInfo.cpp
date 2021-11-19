#include <Windows.h>
#include "ArkProcessInfo.h"
#include "devctrl.h"

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

typedef struct _HANDLE_INFO {
	ULONG_PTR	ObjectTypeIndex;
	ULONG_PTR	HandleValue;
	ULONG_PTR	ReferenceCount;
	ULONG_PTR	GrantedAccess;
	ULONG_PTR	CountNum;
	ULONG_PTR	Object;
	ULONG		ProcessId;
	WCHAR		ProcessName[256 * 2];
	WCHAR		ProcessPath[256 * 2];
	//WCHAR		TypeName[256 * 2];
	//WCHAR		HandleName[256 * 2];
} HANDLE_INFO, * PHANDLE_INFO;

typedef struct _PROCESS_MOD
{
	ULONG	DllBase;
	ULONG	EntryPoint;
	ULONG	SizeOfImage;
	WCHAR	FullDllName[260];
	WCHAR	BaseDllName[260];
}PROCESS_MOD, * PPROCESS_MOD;

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

bool ArkProcessInfo::nf_GetProcessMod()
{

}

bool ArkProcessInfo::nf_KillProcess()
{
	map<int, wstring> Process_list;
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	bool	status = false;

	inSize = sizeof(char) * 4;
	char KillPid[4] = { 0, };
	DWORD KillPidOut = 0;

	cout << "Please Kill ProcessPid: ";
	scanf("%s", &KillPid);

	devobj.devctrl_sendioct(
		CTL_DEVCTRL_ARK_PROCESSKILL,
		&KillPid,
		inSize,
		(LPVOID)&KillPidOut,
		0,
		dwSize
	);

	return status;
}

bool ArkProcessInfo::nf_DumpProcessMem()
{

}

bool ArkProcessInfo::nf_EnumProcess()
{
	map<int, wstring> Process_list;
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	char* outBuf = NULL;
	bool	status = false;
	// 默认当前系统有1000个线程
	const DWORD proessinfosize = sizeof(HANDLE_INFO) * 1024 * 2;
	outBuf = new char[proessinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, proessinfosize);
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
			status = false;
			break;
		}

		PHANDLE_INFO phandleinfo = (PHANDLE_INFO)outBuf;
		if (phandleinfo && dwSize > 0 && phandleinfo[0].CountNum)
		{
			int i = 0, end = phandleinfo[0].CountNum;
			wstring catstr;
			for (i = 0; i < end; ++i)
			{
				wcout << "Pid: " << phandleinfo[i].ProcessId << " - Process: " << phandleinfo[i].ProcessPath << endl;// " - ProcessName: " << phandleinfo[i].ProcessName << endl;
				// 去重
				//catstr = phandleinfo[i].ProcessPath; 
				//catstr += L" - ";
				//catstr += phandleinfo[i].ProcessName;
				//Process_list[phandleinfo[i].ProcessId] = catstr;
				//catstr.clear();
			}

			//map<int, wstring>::iterator iter;
			//for (iter = Process_list.begin(); iter != Process_list.end(); iter++)
			//{
			//	wcout << "Pid: " << iter->first << " - Process: " << iter->second << endl;
			//}

			status = true;
		}

	} while (false);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return status;
}