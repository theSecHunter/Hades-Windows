#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <queue>
#include <WinSock2.h>
#include <TlHelp32.h>
#pragma comment(lib, "ws2_32.lib")

#include "singGloal.h"
#include <usysinfo.h>

#include <DirectoryRuleAssist.h>

// Debug调试
static bool kerne_mon = false;		// kernel采集
static bool kerne_rootkit = false;	// rootkit接口
static bool user_mod = false;		// user接口
static bool etw_mon = false;		// user采集

static bool gpip_send = false;		// pip上报
static char g_chNameGuid[64] = { 0 };	// agentid

static HANDLE g_SvcExitEvent = nullptr;

bool IsProcessExist(LPCTSTR lpProcessName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	const HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	BOOL bResult = Process32First(hProcessSnap, &pe32);
	bool bExist = false;
	string strExeName;
	while (bResult)
	{
		if (lstrcmpi(pe32.szExeFile, lpProcessName) == 0)
		{
			bExist = true;
			break;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	if (hProcessSnap)
		CloseHandle(hProcessSnap);
	return bExist;
}

static DWORD WINAPI HadesAgentActiveCheckThread(LPVOID lpThreadParameter)
{
	// 判断HadesAgent是否存在
	for (;;)
	{
#ifdef _WIN64
		if (!IsProcessExist(L"HadesAgent64.exe"))
#else
		if (!IsProcessExist(L"HadesAgent.exe"))
#endif
		{
			if (g_SvcExitEvent)
				SetEvent(g_SvcExitEvent);
			break;
		}
		Sleep(5000);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	// 单进程模式
	const HANDLE hExit = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Global\\HadesSvc_EVNET_EXIT");
	if (hExit)
		return 0;

	// Check HadesAgent Process
#ifdef _WIN64
	if (!IsProcessExist(L"HadesAgent64.exe"))
#else
	if (!IsProcessExist(L"HadesAgent.exe"))
#endif
		return 0;
	CreateThread(NULL, NULL, HadesAgentActiveCheckThread, NULL, 0, 0);
	
	// HadesSvc Exit Event - HadesSvc
	g_SvcExitEvent = CreateEvent(NULL, FALSE, FALSE, L"Global\\HadesSvc_EVNET_EXIT");
	if (!g_SvcExitEvent)
		return 0;

	// Init PipConnect
	true == SingletonDataHandler::instance()->PipInitAnonymous() ? gpip_send = true : gpip_send = false;
	if (!gpip_send)
	{
		SingletonDataHandler::instance()->PipFreeAnonymous();
		return 0;
	}

	// Init Recv Etw/Kernel Data
	SingletonDataHandler::instance()->ThreadPool_Init();

	// Set Exit Event
	SingletonDataHandler::instance()->SetExitSvcEvent(g_SvcExitEvent);


	SingletonUMon::instance()->uMsg_Init();
	SingletonKerMon::instance()->kMsg_Init();

	// Debug Test
	if (true == gpip_send && (true == kerne_rootkit || true == kerne_mon))
	{
		SingletonKerMon::instance()->DriverInit(false);
		cout << "Rootkit上报接口测试:" << endl;
		SingletonDataHandler::instance()->DebugTaskInterface(100);
		SingletonDataHandler::instance()->DebugTaskInterface(101);
		//SingletonDataHandler::instance()->DebugTaskInterface(103);
		SingletonDataHandler::instance()->DebugTaskInterface(108);
		SingletonDataHandler::instance()->DebugTaskInterface(109);
		SingletonDataHandler::instance()->DebugTaskInterface(110);
		SingletonDataHandler::instance()->DebugTaskInterface(111);
		SingletonDataHandler::instance()->DebugTaskInterface(113);
		SingletonDataHandler::instance()->DebugTaskInterface(115);
	}
	if (true == gpip_send && true == user_mod)
	{
		cout << "User下发接口测试" << endl;
		SingletonDataHandler::instance()->DebugTaskInterface(200);
		SingletonDataHandler::instance()->DebugTaskInterface(202);
		SingletonDataHandler::instance()->DebugTaskInterface(203);
		SingletonDataHandler::instance()->DebugTaskInterface(207);
		SingletonDataHandler::instance()->DebugTaskInterface(208);
		//SingletonDataHandler::instance()->DebugTaskInterface(204);
		//SingletonDataHandler::instance()->DebugTaskInterface(UF_SYSFILE_ID);
		//SingletonDataHandler::instance()->DebugTaskInterface(UF_FILE_INFO);
		//SingletonDataHandler::instance()->DebugTaskInterface(UF_SYSINFO_ID);
		//SingletonDataHandler::instance()->DebugTaskInterface(UF_PROCESS_PID_TREE);
	}
	if (true == gpip_send && true == etw_mon) {
		SingletonUMon::instance()->uMsg_EtwInit();
	}

	// 等待AgentEvent Exit
	WaitForSingleObject(g_SvcExitEvent, INFINITE);
	if (g_SvcExitEvent) {
		CloseHandle(g_SvcExitEvent);
		g_SvcExitEvent = nullptr;
	}

	if (SingletonUMon::instance()->GetEtwMonStatus())
		SingletonUMon::instance()->uMsg_EtwClose();
	if (SingletonKerMon::instance()->GetKerBeSnipingStatus())
		SingletonKerMon::instance()->OffBeSnipingMonitor();
	if (SingletonKerMon::instance()->GetKerMonStatus())
		SingletonKerMon::instance()->OffMonitor();
	Sleep(1000);
	if (SingletonKerMon::instance()->GetKerInitStatus())
		SingletonKerMon::instance()->DriverFree();
	if (gpip_send) {
		SingletonDataHandler::instance()->PipFreeAnonymous();
	}

	SingletonUMon::instance()->uMsg_Free();
	SingletonKerMon::instance()->kMsg_Free();
	return 0;
}
