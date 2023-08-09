#include <Windows.h>
#include "CodeTool.h"
#include "workqueue.h"
#include "EventHandler.h"
#include "NetApi.h"
#include "singGlobal.h"

#include <iostream>
using namespace std;

// 初始化状态
static bool g_bInitStus = false;

//int main(void)
int NetNdrInitEx(void) {
	// Init devctrl
	int ntStus = SingletNetMonx::instance()->devctrl_init();
	if (0 > ntStus)
	{
		cout << "devctrl_init error: main.c" << endl;
		return -1;
	}

	do 
	{
		// Open driver
		ntStus = SingletNetMonx::instance()->devctrl_opendeviceSylink(g_DevSyLinkName);
		if (0 > ntStus)
		{
			cout << "devctrl_opendeviceSylink error: main.c" << endl;
			break;
		}

		// Init share Mem
		ntStus = SingletNetMonx::instance()->devctrl_InitshareMem();
		if (0 > ntStus)
		{
			cout << "devctrl_InitshareMem error: main.c" << endl;
			break;
		}

		static EventHandler cEventHandle;
		// 必须在 devctrl_workthread 之前初始化 Work Queue
		InitWorkQueue((PVOID64)&cEventHandle);

		ntStus = SingletNetMonx::instance()->devctrl_workthread();
		if (0 > ntStus)
		{
			cout << "devctrl_workthread error: main.c" << endl;
			break;
		}

		// Enable try Network packte Monitor
		ntStus = SingletNetMonx::instance()->devctrl_OnMonitor();
		if (0 > ntStus)
		{
			cout << "devctrl_InitshareMem error: main.c" << endl;
			break;
		}
		ntStus = 1;
		g_bInitStus = true;
	} while (false);
	return ntStus;
}

void NetNdrCloseEx(void)
{
	g_bInitStus = false;
	SingletNetMonx::instance()->devctrl_clean();
}

bool GetNetNdrStusEx(void)
{
	return g_bInitStus;
}

int NetNdrSetRuleEx(void) {
	
	return 1;
}

int NetNdrMonitorEx(int code)
{
	DWORD dSize = 0;
	DWORD ioctcode = 0;

	const HANDLE hNetMonx = SingletNetMonx::instance()->get_Driverhandler();
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