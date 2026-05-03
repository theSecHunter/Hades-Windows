#include <Windows.h>
#include "workqueue.h"
#include "EventHandler.h"
#include "NetApi.h"
#include "singGlobal.h"
#include "CodeTool.h"
#include <iostream>
using namespace std;

// 初始化状态
static bool g_bInitStus = false;

namespace
{
	void SplitRuleValues(const std::string& source, std::vector<std::string>& output)
	{
		size_t start = 0;
		while (start < source.size())
		{
			size_t end = source.find('|', start);
			if (end == std::string::npos)
				end = source.size();

			if (end > start)
				output.emplace_back(source.substr(start, end - start));

			if (end == source.size())
				break;
			start = end + 1;
		}
	}
}

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

		// devctrl_workthread 之前初始化 Work Queue
		static EventHandler cEventHandle;
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
	try
	{
		g_bInitStus = false;
		SingletNetMonx::instance()->devctrl_clean();
		NetNdrRuleClear();
	}
	catch (const std::exception&)
	{
	}
}

bool GetNetNdrStusEx(void)
{
	return g_bInitStus;
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

	OutputDebugString(L"[HadesNetMon] devctrl_sendioct entablMonitor");
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
		OutputDebugString(L"[HadesNetMon] devctrl_sendioct Error End");
		return -2;
	}
	return bStu;
}

void NetNdrSetDenyRule(const char* cRuleName, const char* cIpAddress, const char* cProtocol, const char* cPortArray, const char* cAction)
{
	DENY_RULE denyRule; 
	denyRule.clear();
	denyRule.strRuleName = cRuleName;
	denyRule.strIpAddress = cIpAddress;
	denyRule.strProtocol = cProtocol;
	denyRule.strPorts = cPortArray;
	SplitRuleValues(denyRule.strPorts, denyRule.vecPorts);
	denyRule.strAction = cAction;
	SingletonNetRule::instance()->SetDenyRule(denyRule);
}

void NetNdrSetRediRectRule(const char* cRuleName, const char* cRedirectIp, const int iRedrectPort, const char* cProtocol, const char* cProcessName)
{
	REDIRECT_RULE tRediRectRule;
	tRediRectRule.clear();
	tRediRectRule.strRuleName = cRuleName;
	tRediRectRule.strRedirectIp = cRedirectIp;
	tRediRectRule.strProtocol = cProtocol;
	tRediRectRule.iRedirectPort = iRedrectPort;
	tRediRectRule.strProcessName = cProcessName;
	SplitRuleValues(tRediRectRule.strProcessName, tRediRectRule.vecProcessName);
	SingletonNetRule::instance()->SetRediRectRule(tRediRectRule);
}

void NetNdrSetDnsRule(const char* cRuleName, const char* cProtocol, const char* cDnsName, const char* cAction)
{
	DNS_RULE tDnsRule;
	tDnsRule.clear();
	tDnsRule.strRuleName = cRuleName;
	tDnsRule.strProtocol = cProtocol;
	tDnsRule.strAction = cAction;
	tDnsRule.sDnsName = cDnsName;
	SingletonNetRule::instance()->SetDnsRule(tDnsRule);
}

void NetNdrRuleClear(void)
{
	SingletonNetRule::instance()->NetRuleClear();
}
