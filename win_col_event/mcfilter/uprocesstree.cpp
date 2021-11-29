#include <Windows.h>
#include "uprocesstree.h"
#include <string>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <Psapi.h>
#include "sysinfo.h"


#pragma comment (lib,"Psapi.lib")

#define MAX_SERVICE_SIZE 1024 * 64
#define MAX_QUERY_SIZE   1024 * 8

using namespace std;

UProcess::UProcess()
{
}

UProcess::~UProcess()
{
}

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
BOOL GetProcessFullPath(DWORD dwPID, WCHAR* processpath)
{
	TCHAR		szImagePath[MAX_PATH];
	TCHAR		pszFullPath[MAX_PATH];
	HANDLE		hProcess;
	if (!pszFullPath)
		return FALSE;

	pszFullPath[0] = '\0';
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess)
		return FALSE;

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	lstrcatW(processpath, pszFullPath);
	return TRUE;
}

void GetProcessModule(const DWORD idProcess)
{
	PBOOL Wow64Process = NULL;
	HMODULE hMods = NULL;
	DWORD cbNeeded = 0;
	WCHAR szModName[MAX_PATH] = { 0, };
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, idProcess);
	if (!hProcess)
		return;
	IsWow64Process(hProcess, Wow64Process);
	EnumProcessModulesEx(hProcess, &hMods, sizeof(hMods), &cbNeeded, Wow64Process ? LIST_MODULES_32BIT : LIST_MODULES_64BIT);
	for (UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		GetModuleFileNameEx(hProcess, &hMods[i], szModName, _countof(szModName));
		// wprintf(TEXT("%s\n"), szModName);
		// wmemset(Autostr->ProcMoudleInfo[i], 0, sizeof(0x1024 * MAX_PATH));
		// 模块保存到数据中
	}
}
BOOL GetProceThread(const DWORD ProcPid)
{
	HANDLE lpthread = INVALID_HANDLE_VALUE;
	THREADENTRY32 t_32 = { 0 };
	lpthread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == lpthread)
	{
		return FALSE;
	}
	if (ERROR_NO_MORE_FILES == Thread32First(lpthread, &t_32))
	{
		CloseHandle(lpthread);
		return FALSE;
	}
	int count = 0;
	t_32.dwSize = sizeof(THREADENTRY32);
	
	string pri;

	do {
		if (t_32.th32OwnerProcessID == ProcPid)
		{
			// 父进程ID
			printf("\tProc_Pid: %u ", t_32.th32OwnerProcessID);
			// 优先级
			printf("\tThread_id: %d", t_32.tpBasePri);
			if (t_32.tpBasePri == 31)
				pri = "实时(real-time)";
			else if (t_32.tpBasePri >= 15)
				pri = "高(High)";
			else if (t_32.tpBasePri >= 11)
				pri = "高于标准(above normal)";
			else if (t_32.tpBasePri >= 8)
				pri = "标准(normal)";
			else if (t_32.tpBasePri >= 5)
				pri = "低于标准(below Normal)";
			else if (t_32.tpBasePri >= 0)
				pri = "最低(idle)";
		}
	} while (Thread32Next(lpthread, &t_32));
	return TRUE;
}
BOOL GetProcessPath(const DWORD pid, WCHAR* processpath)
{
	HANDLE hSnapshot = NULL;
	BOOL fOk;
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return false;
	}
	for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe))
	{
		if (pid != pe.th32ProcessID)
			continue;

		if (GetProcessFullPath(pe.th32ProcessID, processpath))
			return true;
		//ShowModule(pe.th32ProcessID,pe.szExeFile); //仅32位
	}

	return false;
}

BOOL UProcess::uf_GetProcessInfo(const DWORD pid, LPVOID outbuf)
{
	GetProceThread(pid);
	GetProcessModule(pid);
	return TRUE;
}

DWORD EnumProcess(LPVOID outbuf)
{
	TCHAR ProcessPath[MAX_PATH] = { 0, };
	// 初始化无效的句柄值
	HANDLE hprocess = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W p_32 = { 0 };
	DWORD procesnumber = 0;

	PUProcessEnum processbuf = (PUProcessEnum)outbuf;
	if (!processbuf)
		return FALSE;

	// 1.创建进程快照
	hprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hprocess)
	{
		p_32.dwSize = sizeof(PROCESSENTRY32W);
		// 计算当前循环次数
		int count = 0;
		// 开始遍历进程
		if (!Process32First(hprocess, &p_32))
		{
			CloseHandle(hprocess);
			return FALSE;
		}
		string pri;
		do
		{
			TCHAR bufs[MAX_PATH] = {};
			// 进程ID
			processbuf[procesnumber].pid = p_32.th32ProcessID;
			processbuf[procesnumber].th32ParentProcessID = p_32.th32ParentProcessID;
			processbuf[procesnumber].threadcout = p_32.cntThreads;

			// 基本优先级
			pri.clear();
			if (p_32.pcPriClassBase == 31)
				pri = "实时(real-time)";
			else if (p_32.pcPriClassBase >= 15)
				pri = "高(High)";
			else if (p_32.pcPriClassBase >= 11)
				pri = "高于标准(above normal)";
			else if (p_32.pcPriClassBase >= 8)
				pri = "标准(normal)";
			else if (p_32.pcPriClassBase >= 5)
				pri = "低于标准(below Normal)";
			else if (p_32.pcPriClassBase >= 0)
				pri = "最低(idle)";

			if (GetProcessPath(p_32.th32ProcessID, ProcessPath))
				lstrcpyW(processbuf[procesnumber].fullprocesspath, ProcessPath);

			strcpy(processbuf[procesnumber].priclassbase, pri.c_str());
			lstrcpyW(processbuf[procesnumber].szExeFile, p_32.szExeFile);


			procesnumber++;

		} while (Process32Next(hprocess, &p_32));
	}
	else
		return false;

	return procesnumber;
}
BOOL UProcess::uf_EnumProcess(LPVOID outbuf)
{
	if (!outbuf)
		return false;

	PUProcessNode procesNode = (PUProcessNode)outbuf;
	if (!procesNode)
		return false;

	procesNode->processcount = EnumProcess(procesNode->sysprocess);

	return true;
}