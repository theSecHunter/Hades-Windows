#include <Windows.h>
#include "uautostart.h"
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#include <wchar.h>
#include <sysinfo.h>
#include <regex>

UAutoStart::UAutoStart()
{

}
UAutoStart::~UAutoStart()
{
}

// 默认不超过1000条注册表启动
const ULONG CheckRegisterRun(RegRun* pRegRun)
{
	if (!pRegRun)
		return 0;

	HKEY hKey;
	DWORD dwType = 0;
	DWORD dwBufferSize = MAXBYTE;
	DWORD dwKeySize = MAXBYTE;
	CHAR szValueName[MAXBYTE] = { 0 };
	CHAR szValueKey[MAXBYTE] = { 0 };
	int i = 0, j = 0;
	int index = 0;

	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
	{
		while (TRUE)
		{
			int rect = RegEnumValueA(hKey, i, szValueName, &dwBufferSize, NULL, &dwType, (LPBYTE)szValueKey, &dwKeySize);
			if (rect == ERROR_NO_MORE_ITEMS)
			{
				break;
			}

			RtlCopyMemory(pRegRun[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(pRegRun[index].szValueKey, szValueKey, MAXBYTE);
			if (1000 >= (++index))
				break;

			i++;
			j++;
			dwBufferSize = MAXBYTE;
			dwKeySize = MAXBYTE;
			ZeroMemory(szValueName, MAXBYTE);
			ZeroMemory(szValueKey, MAXBYTE);
		}
		RegCloseKey(hKey);
	}

	i = 0; j = 0; dwType = 0; hKey = 0;
	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce", &hKey) == ERROR_SUCCESS)
	{
		while (TRUE)
		{
			int rect = RegEnumValueA(hKey, i, szValueName, &dwBufferSize, NULL, &dwType, (LPBYTE)szValueKey, &dwKeySize);
			if (rect == ERROR_NO_MORE_ITEMS)
			{
				break;
			}

			RtlCopyMemory(pRegRun[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(pRegRun[index].szValueKey, szValueKey, MAXBYTE);
			if (1000 >= (++index))
				break;

			i++;
			j++;
			dwBufferSize = MAXBYTE;
			dwKeySize = MAXBYTE;
			ZeroMemory(szValueName, MAXBYTE);
			ZeroMemory(szValueKey, MAXBYTE);
		}
		RegCloseKey(hKey);
	}

	i = 0; j = 0; dwType = 0; hKey = 0;
	if (RegOpenKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
	{
		while (TRUE)
		{
			int rect = RegEnumValueA(hKey, i, szValueName, &dwBufferSize, NULL, &dwType, (LPBYTE)szValueKey, &dwKeySize);
			if (rect == ERROR_NO_MORE_ITEMS)
			{
				break;
			}

			RtlCopyMemory(pRegRun[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(pRegRun[index].szValueKey, szValueKey, MAXBYTE);
			if (1000 >= (++index))
				break;

			i++;
			j++;
			dwBufferSize = MAXBYTE;
			dwKeySize = MAXBYTE;
			ZeroMemory(szValueName, MAXBYTE);
			ZeroMemory(szValueKey, MAXBYTE);
		}
		RegCloseKey(hKey);
	}

	i = 0; j = 0; hKey = 0;
	dwType = REG_SZ | REG_EXPAND_SZ;
	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
	{
		while (TRUE)
		{
			int rect = RegEnumValueA(hKey, i, szValueName, &dwBufferSize, NULL, &dwType, (LPBYTE)szValueKey, &dwKeySize);
			if (rect == ERROR_NO_MORE_ITEMS)
			{
				break;
			}

			RtlCopyMemory(pRegRun[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(pRegRun[index].szValueKey, szValueKey, MAXBYTE);
			if (1000 >= (++index))
				break;

			i++;
			j++;
			dwBufferSize = MAXBYTE;
			dwKeySize = MAXBYTE;
			ZeroMemory(szValueName, MAXBYTE);
			ZeroMemory(szValueKey, MAXBYTE);
		}
		RegCloseKey(hKey);
	}

	return index;
}

// 解析Xml中某个命令包含的格式
void XmlCommandAn(const wchar_t* source, wchar_t* deststr)
{
	try
	{
		const std::wstring sCommand = source;
		// <Command>F:\\360zip\360zipUpdate.exe</Command>
		{
			const std::wregex pattern(L"<Command>(.*?)</Command>");
			std::wsmatch match;
			if (std::regex_search(sCommand, match, pattern) && match.size() > 1) {
				const std::wstring sPath = match[1];
				if (!sPath.empty()) {
					lstrcpyW(deststr, sPath.c_str());
				}
			}
		}
		// <Arguments>/detectupdate</Arguments>
		{
			const std::wregex pattern(L"<Arguments>(.*?)</Arguments>");
			std::wsmatch match;
			if (std::regex_search(sCommand, match, pattern) && match.size() > 1) {
				const std::wstring sPath = match[1];
				if (!sPath.empty()) {
					int nCommandSize = lstrlenW(deststr) + 0x1;
					deststr[nCommandSize] = '&';
					lstrcatW(&deststr[nCommandSize + 0x1], sPath.c_str());
				}
			}
		}
	}
	catch (...)
	{
	}
}
/*
	通过WMI只能枚举使用Win32_ScheduledJob类别或At.exe实用程序创建的计划任务。NetScheduleJobEnum(); Win8以上就不支持了(放弃)
	Ues: Task Scheduler 2.0
*/
const ULONG CheckTaskSchedulerRun(UTaskSchedulerRun* pTaskRun)
{
	if (!pTaskRun)
		return 0;
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
		return 0;

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		CoUninitialize();
		return 0;
	}

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		CoUninitialize();
		return 0;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return 0;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

	pService->Release();
	if (FAILED(hr))
	{
		CoUninitialize();
		return 0;
	}

	//  -------------------------------------------------------
	//  Get the registered tasks in the folder.
	IRegisteredTaskCollection* pTaskCollection = NULL;
	hr = pRootFolder->GetTasks(NULL, &pTaskCollection);

	pRootFolder->Release();
	if (FAILED(hr))
	{
		CoUninitialize();
		return 0;
	}

	LONG numTasks = 0;
	hr = pTaskCollection->get_Count(&numTasks);

	if (numTasks == 0)
	{
		pTaskCollection->Release();
		CoUninitialize();
		return 0;
	}

	TASK_STATE taskState;
	wchar_t TaskCommand[1024] = { 0, };

	DWORD iCouent = 0;
	for (LONG i = 0; i < numTasks; i++)
	{
		IRegisteredTask* pRegisteredTask = NULL;
		hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

		if (SUCCEEDED(hr) && pRegisteredTask)
		{
			BSTR taskName = NULL;
			hr = pRegisteredTask->get_Name(&taskName);
			if (SUCCEEDED(hr))
			{
				
				lstrcpyW(pTaskRun[i].szValueName, taskName);

				hr = pRegisteredTask->get_State(&taskState);
				if (SUCCEEDED(hr))
					pTaskRun[i].State = taskState;

				DATE* pLastTime = NULL;
				hr = pRegisteredTask->get_LastRunTime(pLastTime);
				if (SUCCEEDED(hr) && pLastTime)
					pTaskRun[i].LastTime = *pLastTime;

				hr = pRegisteredTask->get_NextRunTime(pLastTime);
				if (SUCCEEDED(hr) && pLastTime)
					pTaskRun[i].NextTime = *pLastTime;

				hr = pRegisteredTask->get_Xml(&taskName);
				if (SUCCEEDED(hr))
				{
					XmlCommandAn((wchar_t*)taskName, TaskCommand);
					lstrcpyW(pTaskRun[i].TaskCommand, TaskCommand);
				}

				SysFreeString(taskName);

				iCouent++;
			}
			pRegisteredTask->Release();
		}
	}

	pTaskCollection->Release();
	CoUninitialize();
	return iCouent;
}

const bool UAutoStart::uf_EnumAutoStartask(LPVOID pData, const DWORD dwSize)
{
	if (!pData || 0 >= dwSize)
		return false;

	PUAutoStartNode Autorun = (PUAutoStartNode)pData;
	if (!Autorun)
		return false;

	// 注册表
	Autorun->regnumber = CheckRegisterRun((RegRun*)Autorun->regrun);

	// 计划任务
	Autorun->taskrunnumber = CheckTaskSchedulerRun((UTaskSchedulerRun*)Autorun->taskschrun);

	return true;
}