#include <Windows.h>
#include "uprocesstree.h"
#include <string>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <Psapi.h>
#include <sysinfo.h>
#include <atlstr.h>

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

// Ȩ��
enum MEMORYSTATE {
	e_stat_free = MEM_FREE,
	e_stat_reserve = MEM_RESERVE,
	e_stat_commit = MEM_COMMIT
};
// �����ڴ��ҳ����
enum MEMORYTYPE {
	e_type_image = MEM_IMAGE,
	e_type_mapped = MEM_MAPPED,
	e_type_private = MEM_PRIVATE,
};
typedef struct VMINFO {
	DWORD		address;
	DWORD		size;
	MEMORYSTATE state;
}VMINFO;

const bool DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//������
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//��ȡ���ش����ַ���
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100))//��ѯ Dos �豸��
				return FALSE;
			
			cchDevName = lstrlenW(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//����
			{
				lstrcpy(pszNtPath, szDrive);//����������
				lstrcat(pszNtPath, pszDosPath + cchDevName);//����·��

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
const bool GetProcessFullPath(DWORD dwPID, WCHAR* processpath)
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

	if (hProcess)
		CloseHandle(hProcess);

	lstrcatW(processpath, pszFullPath);
	return TRUE;
}

// ProcessInfo
const int GetProcessModules(DWORD processID)
{
	/*
	* Use:
	* 	
	{
		DWORD aProcesses[1024];
		DWORD cbNeeded;
		DWORD cProcesses;
		unsigned int i;
		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
			return 1;
		cProcesses = cbNeeded / sizeof(DWORD);
		for (i = 0; i < cProcesses; i++)
		{
			GetProcessModules(aProcesses[i]);
		}	
	}
	*/
	HMODULE hMods[1024];
	HANDLE hProcess = NULL;
	DWORD cbNeeded = 0;
	unsigned int i = 0;
	//hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
	//	PROCESS_VM_READ,
	//	FALSE, processID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (NULL == hProcess)
		return 1;
	std::wstring wszModNameEx = L"";
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH] = { 0, };
			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
				wszModNameEx = szModName;
			}
		}
	}
	if (hProcess)
		CloseHandle(hProcess);
	return 0;
}
void GetProcessModule(const DWORD idProcess)
{
	HMODULE hMods = NULL;
	WCHAR szModName[MAX_PATH] = { 0, };
	// const HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, idProcess);
	const HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, idProcess);
	if (!hProcess)
		return;
	BOOL Wow64Process = FALSE;
	IsWow64Process(hProcess, &Wow64Process);
	DWORD cbNeeded = 0;
	EnumProcessModulesEx(hProcess, &hMods, sizeof(hMods), &cbNeeded, Wow64Process ? LIST_MODULES_32BIT : LIST_MODULES_64BIT);
	for (UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		GetModuleFileNameEx(hProcess, &hMods[i], szModName, _countof(szModName));
		// wprintf(TEXT("%s\n"), szModName);
		// wmemset(Autostr->ProcMoudleInfo[i], 0, sizeof(0x1024 * MAX_PATH));
		// ģ�鱣�浽������
	}
	if (hProcess)
		CloseHandle(hProcess);
}
const bool GetProceThread(const DWORD ProcPid)
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
			// ������ID
			printf("\tProc_Pid: %u ", t_32.th32OwnerProcessID);
			// ���ȼ�
			printf("\tThread_id: %d", t_32.tpBasePri);
			if (t_32.tpBasePri == 31)
				pri = "ʵʱ(real-time)";
			else if (t_32.tpBasePri >= 15)
				pri = "��(High)";
			else if (t_32.tpBasePri >= 11)
				pri = "���ڱ�׼(above normal)";
			else if (t_32.tpBasePri >= 8)
				pri = "��׼(normal)";
			else if (t_32.tpBasePri >= 5)
				pri = "���ڱ�׼(below Normal)";
			else if (t_32.tpBasePri >= 0)
				pri = "���(idle)";
		}
	} while (Thread32Next(lpthread, &t_32));

	if (lpthread)
		CloseHandle(lpthread);
	return TRUE;
}
const bool GetProcessPath(const DWORD dwPID, WCHAR* processpath)
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
		if (dwPID != pe.th32ProcessID)
			continue;

		if (GetProcessFullPath(pe.th32ProcessID, processpath))
			return true;
		//ShowModule(pe.th32ProcessID,pe.szExeFile); //��32λ
	}
	if (hSnapshot)
		CloseHandle(hSnapshot);
	return false;
}
void GetQueryViryualMemoryStatue(HANDLE hProccess)
{
	int count = 0;
	CString str;
	MEMORY_BASIC_INFORMATION	mbi = { 0 };
	VMINFO						statue = { 0 };
	DWORD						dwAddress = 0;
	DWORD						dwSize = 0;
	SIZE_T						bRet = 0;
	while (1) {

		bRet = VirtualQueryEx(hProccess,
			(LPCVOID)dwAddress,
			&mbi,
			sizeof(MEMORY_BASIC_INFORMATION));
		if (!bRet)
			break;

		statue.address = dwAddress;
		statue.state = (MEMORYSTATE)mbi.State;
		dwSize = mbi.RegionSize;

		// ����ڴ�״̬, 
		// �ڴ�״̬�������������ڴ���û�к�����洢�����й���.
		// ���Ƿ�Ԥ��.
		// free   : ����,û��Ԥ��,û�к�����洢������
		// reserve: ����,��Ԥ��,û�к�����洢������
		// commit : �ύ,�Ѿ�������洢������
		switch (statue.state) {
		case e_stat_free:
			str.Format(L"free:          0x%08X", statue.address);
			break;
		case e_stat_reserve:
			str.Format(L"reserve:   0x%08X", statue.address);
			break;
		case e_stat_commit:
			str.Format(L"commit:   0x%08X", statue.address);
			break;
		}

		// ����ڴ��ַ�Ѿ��ύ�������ڴ�,������ύ����ÿһ���ڴ��.
		if (statue.state == e_stat_commit) {

			dwSize = 0;
			PVOID	dwAllocationBase = mbi.AllocationBase;
			DWORD64	dwBlockAddress = (DWORD64)dwAddress;
			while (1) {

				bRet = VirtualQueryEx(hProccess,
					(LPCVOID)dwBlockAddress,
					&mbi,
					sizeof(MEMORY_BASIC_INFORMATION));
				if (!bRet) {
					break;
				}


				// �жϱ����������ڴ���Ƿ���ͬһ��.(�����ǵķ�����׵�ַ�Ƿ����.)
				// �������,������ѭ��.
				if (mbi.AllocationBase != dwAllocationBase)
					break;
				// ���RVA
				str.Format(L"0x%08X", dwBlockAddress);

				// ����ڴ�����
				// �ڴ����ͱ�ʾ�����ڴ����Ժ��ַ�ʽ������洢�����й���
				// image  : �Ǵ�Ӱ���ļ���ӳ�����
				// mapped : �ڴ�ӳ��
				// private: ˽���ڴ�,���������޷�����.
				switch (mbi.Type) {
				case e_type_image:
					// m_ListCtr.SetItemText(count, 2, L"image");
					break;
				case e_type_mapped:
					// m_ListCtr.SetItemText(count, 2, L"mapped");
					break;
				case e_type_private:
					// m_ListCtr.SetItemText(count, 2, L"private");
					break;
				default:
					break;
				}

				// ����ڴ��ҳ����
				// �ڴ��ҳ�������ڱ�ʾ�ڴ��ҳ�ܹ����к��ַ���,���,д,ִ��,дʱ����.
				//if (mbi.Protect == 0)
				//	m_ListCtr.SetItemText(count, 3, L"---");
				//else if (mbi.Protect & PAGE_EXECUTE)
				//	m_ListCtr.SetItemText(count, 3, L"E--");
				//else if (mbi.Protect & PAGE_EXECUTE_READ)
				//	m_ListCtr.SetItemText(count, 3, L"ER-");
				//else if (mbi.Protect & PAGE_EXECUTE_READWRITE)
				//	m_ListCtr.SetItemText(count, 3, L"ERW");
				//else if (mbi.Protect & PAGE_READONLY)
				//	m_ListCtr.SetItemText(count, 3, L"-R-");
				//else if (mbi.Protect & PAGE_READWRITE)
				//	m_ListCtr.SetItemText(count, 3, L"-RW");
				//else if (mbi.Protect & PAGE_WRITECOPY)
				//	m_ListCtr.SetItemText(count, 3, L"WCOPY");
				//else if (mbi.Protect & PAGE_EXECUTE_WRITECOPY)
				//	m_ListCtr.SetItemText(count, 3, L"EWCOPY");

				// ����ڴ��Ĵ�С.
				// printf(" ��С:0x%X\n", mbi.RegionSize);
				str.Format(L"0x%X", mbi.RegionSize);
				// m_ListCtr.SetItemText(count, 4, str);
				// ��������һ���ڴ��
				dwBlockAddress += mbi.RegionSize;

				// �ۼ��ڴ��Ĵ�С
				dwSize += mbi.RegionSize;
			}
		}

		statue.size = dwSize;
		// this->vmlist.push_back(statue);
		// ������һ�������ڴ�.
		dwAddress += dwSize;
		++count;
	}
}
const bool UProcess::uf_GetProcessInfo(const DWORD dwPID, LPVOID pData)
{
	GetProceThread(dwPID);
	GetProcessModule(dwPID);
	return TRUE;
}

// EnumProcess
DWORD EnumProcess(LPVOID pData)
{
	TCHAR ProcessPath[MAX_PATH] = { 0, };
	// ��ʼ����Ч�ľ��ֵ
	HANDLE hprocess = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W p_32 = { 0 };
	DWORD procesnumber = 0;

	PUProcessEnum processbuf = (PUProcessEnum)pData;
	if (!processbuf)
		return procesnumber;

	// 1.�������̿���
	hprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hprocess)
	{
		p_32.dwSize = sizeof(PROCESSENTRY32W);
		// ���㵱ǰѭ������
		int count = 0;
		// ��ʼ��������
		if (!Process32First(hprocess, &p_32))
		{
			CloseHandle(hprocess);
			return procesnumber;
		}
		std::string pri = "";
		do
		{
			TCHAR bufs[MAX_PATH] = {};
			// ����ID
			processbuf[procesnumber].pid = p_32.th32ProcessID;
			processbuf[procesnumber].th32ParentProcessID = p_32.th32ParentProcessID;
			processbuf[procesnumber].threadcout = p_32.cntThreads;

			// �������ȼ�
			pri.clear();
			if (p_32.pcPriClassBase == 31)
				pri = "ʵʱ(real-time)";
			else if (p_32.pcPriClassBase >= 15)
				pri = "��(High)";
			else if (p_32.pcPriClassBase >= 11)
				pri = "���ڱ�׼(above normal)";
			else if (p_32.pcPriClassBase >= 8)
				pri = "��׼(normal)";
			else if (p_32.pcPriClassBase >= 5)
				pri = "���ڱ�׼(below Normal)";
			else if (p_32.pcPriClassBase >= 0)
				pri = "���(idle)";

			ProcessPath[0] = '\x00';
			if (GetProcessPath(p_32.th32ProcessID, ProcessPath))
				lstrcpyW(processbuf[procesnumber].fullprocesspath, ProcessPath);

			strcpy_s(processbuf[procesnumber].priclassbase, pri.c_str());
			lstrcpyW(processbuf[procesnumber].szExeFile, p_32.szExeFile);


			procesnumber++;

		} while (Process32Next(hprocess, &p_32));
	}
	else
		return procesnumber;

	if (hprocess)
		CloseHandle(hprocess);

	return procesnumber;
}
const bool UProcess::uf_EnumProcess(LPVOID pData)
{
	if (!pData)
		return false;

	PUProcessNode procesNode = (PUProcessNode)pData;
	if (!procesNode)
		return false;

	procesNode->processcount = EnumProcess(procesNode->sysprocess);

	return true;
}