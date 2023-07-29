#include <Windows.h>
#include "CodeTool.h"
#include "devctrl.h"
#include "workqueue.h"
#include "EventHandler.h"
#include "NetApi.h"

#include <iostream>
using namespace std;

static DevctrlIoct	devobj;
static EventHandler packtebuff;

bool SplitFilePath(const char* szFullPath, char* szPath, char* szFileName, char* szFileExt)
{
	char* p = nullptr, * q = nullptr, * r = nullptr;
	size_t	len = 0;

	if (NULL == szFullPath)
	{
		return false;
	}
	p = (char*)szFullPath;
	len = strlen(szFullPath);
	if (szPath)
	{
		szPath[0] = 0;
	}
	if (szFileName)
	{
		szFileName[0] = 0;
	}
	if (szFileExt)
	{
		szFileExt[0] = 0;
	}
	q = p + len;
	while (q > p)
	{
		if (*q == '\\' || *q == '/')
		{
			break;
		}
		q--;
	}
	if (q <= p)
	{
		return false;
	}
	if (szPath)
	{
		memcpy(szPath, p, q - p + 1);
		szPath[q - p + 1] = 0;
	}
	q++;
	p = q;
	r = NULL;
	while (*q)
	{
		if (*q == '.')
		{
			r = q;
		}
		q++;
	}
	if (NULL == r)
	{
		if (szFileName)
		{
			memcpy(szFileName, p, q - p + 1);
		}
	}
	else
	{
		if (szFileName)
		{
			memcpy(szFileName, p, r - p);
			szFileName[r - p] = 0;
		}
		if (szFileExt)
		{
			memcpy(szFileExt, r + 1, q - r + 1);
		}
	}

	return true;
}

int FindInMultiSz(LPTSTR szMultiSz, int nMultiSzLen, LPTSTR szMatch)
{
	size_t	i, j;
	size_t	len = lstrlenW(szMatch);
	TCHAR	FirstChar = *szMatch;
	bool	bFound;
	LPTSTR	pTry;

	if (NULL == szMultiSz || NULL == szMatch || nMultiSzLen <= 0)
	{
		return -1;
	}
	for (i = 0; i < nMultiSzLen - len; i++)
	{
		if (*szMultiSz++ == FirstChar)
		{
			bFound = true;
			pTry = szMultiSz;
			for (j = 1; j <= len; j++)
			{
				if (*pTry++ != szMatch[j])
				{
					bFound = false;
					break;
				}
			}
			if (bFound)
			{
				return (int)i;
			}
		}
	}

	return -1;
}

int CreateDriver(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath)
{
	SC_HANDLE		schManager;
	SC_HANDLE		schService;
	SERVICE_STATUS	svcStatus;
	bool			bStopped = false;
	int				i;

	if (NULL == cszDriverName || NULL == cszDriverFullPath)
	{
		return -1;
	}
	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		return -1;
	}
	schService = OpenService(schManager, cszDriverName, SERVICE_ALL_ACCESS);
	if (NULL != schService)
	{
		if (ControlService(schService, SERVICE_CONTROL_INTERROGATE, &svcStatus))
		{
			if (svcStatus.dwCurrentState != SERVICE_STOPPED)
			{
				if (0 == ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus))
				{
					CloseServiceHandle(schService);
					CloseServiceHandle(schManager);
					return -1;
				}
				for (i = 0; i < 10; i++)
				{
					if (ControlService(schService, SERVICE_CONTROL_INTERROGATE, &svcStatus) == 0 || svcStatus.dwCurrentState == SERVICE_STOPPED)
					{
						bStopped = true;
						break;
					}
					Sleep(LG_SLEEP_TIME);
				}
				if (!bStopped)
				{
					CloseServiceHandle(schService);
					CloseServiceHandle(schManager);
					return -1;
				}
			}
		}
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return 0;
	}
	schService = CreateService(schManager, cszDriverName, cszDriverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, cszDriverFullPath, NULL, NULL, NULL, NULL, NULL);
	if (NULL == schService)
	{
		CloseServiceHandle(schManager);
		return -1;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return 0;
}

int StartDriver(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath)
{
	SC_HANDLE		schManager;
	SC_HANDLE		schService;
	SERVICE_STATUS	svcStatus;
	bool			bStarted = false;
	int				i;

	if (NULL == cszDriverName)
	{
		return -1;
	}
	if (CreateDriver(cszDriverName, cszDriverFullPath) < 0)
	{
		return -1;
	}
	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		return -1;
	}
	schService = OpenService(schManager, cszDriverName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schManager);
		return -1;
	}
	if (ControlService(schService, SERVICE_CONTROL_INTERROGATE, &svcStatus))
	{
		if (svcStatus.dwCurrentState == SERVICE_RUNNING)
		{
			CloseServiceHandle(schService);
			CloseServiceHandle(schManager);
			return 0;
		}
	}
	else if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return -1;
	}
	if (0 == StartService(schService, 0, NULL))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return -1;
	}
	for (i = 0; i < 10; i++)
	{
		if (ControlService(schService, SERVICE_CONTROL_INTERROGATE, &svcStatus) && svcStatus.dwCurrentState == SERVICE_RUNNING)
		{
			bStarted = true;
			break;
		}
		Sleep(LG_SLEEP_TIME);
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return bStarted ? 1 : -1;
}

int StopDriver(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath)
{
	SC_HANDLE		schManager;
	SC_HANDLE		schService;
	SERVICE_STATUS	svcStatus;
	bool			bStopped = false;
	int				i;

	schManager = OpenSCManager(NULL, 0, 0);
	if (NULL == schManager)
	{
		return -1;
	}
	schService = OpenService(schManager, cszDriverName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schManager);
		return -1;
	}
	if (ControlService(schService, SERVICE_CONTROL_INTERROGATE, &svcStatus))
	{
		if (svcStatus.dwCurrentState != SERVICE_STOPPED)
		{
			if (0 == ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus))
			{
				CloseServiceHandle(schService);
				CloseServiceHandle(schManager);
				return -1;
			}
			for (i = 0; i < 10; i++)
			{
				if (ControlService(schService, SERVICE_CONTROL_INTERROGATE, &svcStatus) == 0 || svcStatus.dwCurrentState == SERVICE_STOPPED)
				{
					bStopped = true;
					break;
				}
				Sleep(LG_SLEEP_TIME);
			}
			if (!bStopped)
			{
				CloseServiceHandle(schService);
				CloseServiceHandle(schManager);
				return -1;
			}
		}
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return 0;
}

DWORD GetServicesStatus(void)
{
	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;

	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwOldCheckPoint = 0;
	DWORD dwStartTickCount = 0;
	DWORD dwWaitTime = 0;
	DWORD dwBytesNeeded = 0;

	schSCManager = OpenSCManager(
		NULL,                                // local computer
		NULL,                                // ServicesActive database
		SC_MANAGER_ALL_ACCESS);              // full access rights

	if (NULL == schSCManager)
	{
		return -1;

	}

	schService = OpenService(
		schSCManager,                      // SCM database
		g_DriverServerNameW.c_str(),	   // name of service
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);     // full access

	if (schService == NULL)
	{
		CloseServiceHandle(schSCManager);
		return -1;
	}

	if (!QueryServiceStatusEx(
		schService,                         // handle to service
		SC_STATUS_PROCESS_INFO,             // information level
		(LPBYTE)&ssStatus,                 // address of structure
		sizeof(SERVICE_STATUS_PROCESS),     // size of structure
		&dwBytesNeeded))                  // size needed if buffer is too small
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}
	return ssStatus.dwCurrentState;
}

int NetDriverInstall()
{
	wstring PathAll = L"";
	wstring DriverPath = L"";
	wstring pszCmd = (L"sc start " + g_DriverServerNameW).c_str();
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	TCHAR szFilePath[MAX_PATH + 1] = { 0 };
	GetModuleFileName(NULL, szFilePath, MAX_PATH);
	DriverPath = szFilePath;
	const size_t num = DriverPath.find_last_of(L"\\");
	PathAll = DriverPath.substr(0, num);
	PathAll += (L"\\" + g_DriverServerNameW + L".sys").c_str();

	// 先拷贝到C盘
	const std::wstring wStrPath = (L"C:\\Windows\\System32\\drivers\\" + g_DriverServerNameW + L".sys").c_str();
	CopyFile(PathAll.data(), wStrPath.c_str(), FALSE);
	if (StartDriver(g_DriverServerNameW.c_str(), wStrPath.c_str()) == TRUE)
	{
		OutputDebugString(L"Start Driver success.");
		return 1;
	}
	else
	{
		OutputDebugString(L"Start Driver failuer.");
		return -1;
	}
}

//int main(void)
int NetInit(void) {
	int status = 0; DWORD nSeriverstatus = -1;
	const std::wstring pszCmd = (L"sc start " + g_DriverServerNameW).c_str();
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	OutputDebugString(L"Install Driver");

	nSeriverstatus = GetServicesStatus();
	switch (nSeriverstatus)
	{
	// 正在运行
	case SERVICE_CONTINUE_PENDING:
	case SERVICE_RUNNING:
	case SERVICE_START_PENDING:
	{
		OutputDebugString(L"Driver Running");
		break;
	}
	break;
	// 已安装 - 未运行
	case SERVICE_STOPPED:
	case SERVICE_STOP_PENDING:
	{
		GetStartupInfo(&si);
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;
		// 启动命令行
		PROCESS_INFORMATION pi;
		if (CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		Sleep(3000);
		nSeriverstatus = GetServicesStatus();
		if (SERVICE_RUNNING == nSeriverstatus)
		{
			OutputDebugString(L"sc Driver Running");
			break;
		}
		else
		{
			OutputDebugString(L"sc Driver Install Failuer");
			return -1;
		}
	}
	break;
	default:
	{
		OutputDebugStringW(L"nf_driverInstall");
		if (!NetDriverInstall())
		{
			return -1;
		}
	}
	break;
	}

	// Init devctrl
	status = devobj.devctrl_init();
	if (0 > status)
	{
		cout << "devctrl_init error: main.c" << endl;
		return -1;
	}

	do 
	{
		// Open driver
		status = devobj.devctrl_opendeviceSylink(g_DevSyLinkName);
		if (0 > status)
		{
			cout << "devctrl_opendeviceSylink error: main.c" << endl;
			break;
		}

		// Init share Mem
		status = devobj.devctrl_InitshareMem();
		if (0 > status)
		{
			cout << "devctrl_InitshareMem error: main.c" << endl;
			break;
		}

		// 必须在 devctrl_workthread 之前初始化 Work Queue
		nf_InitWorkQueue((PVOID64)&packtebuff);

		status = devobj.devctrl_workthread();
		if (0 > status)
		{
			cout << "devctrl_workthread error: main.c" << endl;
			break;
		}

		// Enable try Network packte Monitor
		status = devobj.devctrl_OnMonitor();
		if (0 > status)
		{
			cout << "devctrl_InitshareMem error: main.c" << endl;
			break;
		}
		
		status = 1;
	} while (false);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return status;
}

int NetSetRule(void) {
	
	return 1;
}

int NetMonitor(int code)
{
	DWORD dSize = 0;
	DWORD ioctcode = 0;

	const HANDLE hNetMonx = SingletNetMonx::instance()->GetDrvHandle();
	if (!hNetMonx)
		return -1;

	switch (code)
	{
	case 0:
		ioctcode = CTL_DEVCTRL_DISENTABLE_MONITOR;
		break;
	case 1:
		ioctcode = CTL_DEVCTRL_ENABLE_MONITOR;
		break;
	}

	OutputDebugString(L"devctrl_sendioct entablMonitor");
	const BOOL bStu = DeviceIoControl(
		hNetMonx,
		ioctcode,
		NULL,
		0,
		NULL,
		0,
		&dSize,
		NULL
	);
	if (!bStu)
	{
		OutputDebugString(L"devctrl_sendioct Error End");
		return -2;
	}
	return bStu;
}