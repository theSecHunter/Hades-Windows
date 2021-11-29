#include <Windows.h>
#include "uautostart.h"
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#include <wchar.h>

#include "sysinfo.h"

UAutoStart::UAutoStart()
{

}

UAutoStart::~UAutoStart()
{
}

// 默认不超过1000条注册表启动
ULONG CheckRegisterRun(RegRun* outbuf)
{
	HKEY hKey;
	DWORD dwType = 0;
	DWORD dwBufferSize = MAXBYTE;
	DWORD dwKeySize = MAXBYTE;
	CHAR szValueName[MAXBYTE] = { 0 };
	CHAR szValueKey[MAXBYTE] = { 0 };
	int i = 0, j = 0;
	int index = 0;

	if (!outbuf)
		return false;

	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
	{
		while (TRUE)
		{
			int rect = RegEnumValueA(hKey, i, szValueName, &dwBufferSize, NULL, &dwType, (LPBYTE)szValueKey, &dwKeySize);
			if (rect == ERROR_NO_MORE_ITEMS)
			{
				break;
			}

			RtlCopyMemory(outbuf[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(outbuf[index].szValueKey, szValueKey, MAXBYTE);
			index++;
			if (1000 >= index)
				return index;

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

			RtlCopyMemory(outbuf[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(outbuf[index].szValueKey, szValueKey, MAXBYTE);
			index++;
			if (1000 >= index)
				return index;

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

			RtlCopyMemory(outbuf[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(outbuf[index].szValueKey, szValueKey, MAXBYTE);
			index++;
			if (1000 >= index)
				return index;

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

			RtlCopyMemory(outbuf[index].szValueName, szValueName, MAXBYTE);
			RtlCopyMemory(outbuf[index].szValueKey, szValueKey, MAXBYTE);
			index++;
			if (1000 >= index)
				return index;

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
	DWORD index_head = 0;
	DWORD index_tail = 0;
	// 查找<Command
	for (int i = 0; i < 0x1024; i++)
	{
		// <Command>F:\\360zip\360zipUpdate.exe</Command>
		if ((source[i] == '<') && (source[i + 1] == 'C') && (source[i + 2] == 'o') && (source[i + 3] == 'm'))
		{
			// 获取执行操作其实位置
			index_head = i + 9;
		}

		if ((source[i] == '<') && (source[i + 1] == '/') && (source[i + 2] == 'C') && (source[i + 3] == 'o'))
		{
			index_tail = i;
			if ((index_tail - index_head) >= 3)
			{
				// 拷贝<Command> xxxxx </Command>
				wmemcpy(deststr, &source[index_head], (index_tail - index_head));
				break;
			}
		}
	}

	// 查找参数 <Arguments>/detectupdate</Arguments>
	for (int i = index_tail; i < 0x1024; i++)
	{
		// <Command>F:\\360zip\360zipUpdate.exe</Command>
		if ((source[i] == '<') && (source[i + 1] == 'A') && (source[i + 2] == 'r') && (source[i + 3] == 'g'))
		{
			// 获取执行操作其实位置
			index_head = i + 11;
		}

		if ((source[i] == '<') && (source[i + 1] == '/') && (source[i + 2] == 'A') && (source[i + 3] == 'r'))
		{
			index_tail = i;
			if ((index_tail - index_head) >= 1)
			{
				// 拼接 <Command> + <Arguments>
				int nCommandSize = lstrlenW(deststr);
				deststr[nCommandSize] = ' ';
				wmemcpy(&deststr[nCommandSize + 1], &source[index_head], (index_tail - index_head));
				break;
			}
		}
	}
}
/*
	通过WMI只能枚举使用Win32_ScheduledJob类别或At.exe实用程序创建的计划任务。NetScheduleJobEnum(); Win8以上就不支持了(放弃)
	Ues: Task Scheduler 2.0
*/
ULONG CheckTaskSchedulerRun(UTaskSchedulerRun* outbuf)
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
		return false;

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
		return false;
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
		return false;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return false;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

	pService->Release();
	if (FAILED(hr))
	{
		CoUninitialize();
		return false;
	}

	//  -------------------------------------------------------
	//  Get the registered tasks in the folder.
	IRegisteredTaskCollection* pTaskCollection = NULL;
	hr = pRootFolder->GetTasks(NULL, &pTaskCollection);

	pRootFolder->Release();
	if (FAILED(hr))
	{
		CoUninitialize();
		return false;
	}

	LONG numTasks = 0;
	hr = pTaskCollection->get_Count(&numTasks);

	if (numTasks == 0)
	{
		pTaskCollection->Release();
		CoUninitialize();
		return false;
	}

	TASK_STATE taskState;
	wchar_t TaskCommand[1024] = { 0 };

	for (LONG i = 0; i < numTasks; i++)
	{
		IRegisteredTask* pRegisteredTask = NULL;
		hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

		if (SUCCEEDED(hr))
		{
			BSTR taskName = NULL;
			hr = pRegisteredTask->get_Name(&taskName);
			if (SUCCEEDED(hr))
			{
				
				lstrcpyW(outbuf[i].szValueName, taskName);

				hr = pRegisteredTask->get_State(&taskState);
				if (SUCCEEDED(hr))
					outbuf[i].State = taskState;

				DATE* pLastTime = NULL;
				hr = pRegisteredTask->get_LastRunTime(pLastTime);
				if (SUCCEEDED(hr) && pLastTime)
					outbuf[i].LastTime = *pLastTime;

				hr = pRegisteredTask->get_NextRunTime(pLastTime);
				if (SUCCEEDED(hr) && pLastTime)
					outbuf[i].NextTime = *pLastTime;

				hr = pRegisteredTask->get_Xml(&taskName);
				if (SUCCEEDED(hr))
				{
					XmlCommandAn((wchar_t*)taskName, TaskCommand);
					lstrcpyW(outbuf[i].TaskCommand, TaskCommand);
				}

				SysFreeString(taskName);
			}
			pRegisteredTask->Release();
		}
	}

	pTaskCollection->Release();
	CoUninitialize();
	return numTasks;
}

bool UAutoStart::uf_EnumAutoStartask(LPVOID outBuf, const DWORD size)
{
	if (!outBuf || 0 >= size)
		return false;

	PUAutoStartNode Autorun = (PUAutoStartNode)outBuf;
	if (!Autorun)
		return false;

	// 注册表
	Autorun->regnumber = CheckRegisterRun((RegRun*)Autorun->regrun);

	// 计划任务
	Autorun->taskrunnumber = CheckTaskSchedulerRun((UTaskSchedulerRun*)Autorun->taskschrun);

	return true;
}