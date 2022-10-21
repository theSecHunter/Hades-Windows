#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <queue>
#include <WinSock2.h>
#include <TlHelp32.h>
#pragma comment(lib, "ws2_32.lib")

#include "DataHandler.h"
#include "umsginterface.h"
#include "kmsginterface.h"
#include "msgloop.h"
#include "HlprMiniCom.h"
#include <usysinfo.h>

#include <DirectoryRuleAssist.h>

static kMsgInterface	g_mainMsgKlib;
static uMsgInterface	g_mainMsgUlib;
static WinMsgLoop		g_MsgControl;
static HlprMiniPortIpc	g_miniport;
static USysBaseInfo		g_DynSysBaseinfo;
static DataHandler		g_DataHandler;

// Debug调试
static bool kerne_mon = false;		// kernel采集
static bool kerne_rootkit = false;	// rootkit接口
static bool user_mod = false;		// user接口
static bool etw_mon = true;			// user采集

static bool gpip_send = false;		// pip上报
static char g_chNameGuid[64] = { 0 };	// agentid

static HANDLE g_SvcExitEvent = nullptr;

bool IsProcessExist(LPCTSTR lpProcessName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
			{
				SetEvent(g_SvcExitEvent);
				CloseHandle(g_SvcExitEvent);
			}
			break;
		}
		Sleep(5000);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	// 允许单进程运行
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
	true == g_DataHandler.PipInitAnonymous() ? gpip_send = true : gpip_send = false;
	if (!gpip_send)
	{
		g_DataHandler.PipFreeAnonymous();
		return 0;
	}

	// Init Recv Etw/Kernel Data
	g_DataHandler.ThreadPool_Init();

	// Set Exit Event
	g_DataHandler.SetExitSvcEvent(g_SvcExitEvent);

	// Set HadesControl Lib ObjectPtr
	if (false == g_MsgControl.setUmsgLib(&g_mainMsgUlib) || false == g_MsgControl.setKmsgLib(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置HadesControl指针失败");
		return 0;
	}
	// Set DataHandler Lib ObjectPtr
	if (false == g_DataHandler.SetUMontiorLibPtr(&g_mainMsgUlib) || false == g_DataHandler.SetKMontiorLibPtr(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置DataHandler指针失败");
		return 0;
	}
	
	g_mainMsgUlib.uMsg_Init();
	g_mainMsgKlib.kMsg_Init();

	// Debug Test
	if (true == gpip_send && (true == kerne_rootkit || true == kerne_mon))
	{
		g_mainMsgKlib.DriverInit(false);
		cout << "Rootkit上报接口测试:" << endl;
		g_DataHandler.DebugTaskInterface(100);
		g_DataHandler.DebugTaskInterface(101);
		//g_DataHandler.DebugTaskInterface(103);
		g_DataHandler.DebugTaskInterface(108);
		g_DataHandler.DebugTaskInterface(109);
		g_DataHandler.DebugTaskInterface(110);
		g_DataHandler.DebugTaskInterface(111);
		g_DataHandler.DebugTaskInterface(113);
		g_DataHandler.DebugTaskInterface(115);
	}
	if (true == gpip_send && true == user_mod)
	{
		cout << "User下发接口测试" << endl;
		g_DataHandler.DebugTaskInterface(200);
		g_DataHandler.DebugTaskInterface(202);
		g_DataHandler.DebugTaskInterface(203);
		g_DataHandler.DebugTaskInterface(207);
		g_DataHandler.DebugTaskInterface(208);
		//g_DataHandler.DebugTaskInterface(204);
		//g_DataHandler.DebugTaskInterface(UF_SYSFILE_ID);
		//// 数据未清理
		//g_DataHandler.DebugTaskInterface(UF_FILE_INFO);
		//// 上线后已上报
		//g_DataHandler.DebugTaskInterface(UF_SYSINFO_ID);
		//// 数据未清理
		//g_DataHandler.DebugTaskInterface(UF_PROCESS_PID_TREE);

	}
	if (true == gpip_send && true == etw_mon) {
		g_mainMsgUlib.uMsg_EtwInit();
	}

	// 等待AgentEvent Exit 否则不退出
	WaitForSingleObject(g_SvcExitEvent, INFINITE);
	CloseHandle(g_SvcExitEvent);
	g_SvcExitEvent = nullptr;
	
	if (g_mainMsgUlib.GetEtwMonStatus())
		g_mainMsgUlib.uMsg_EtwClose();
	if (g_mainMsgKlib.GetKerBeSnipingStatus())
		g_mainMsgKlib.OffBeSnipingMonitor();
	if (g_mainMsgKlib.GetKerMonStatus())
		g_mainMsgKlib.OffMonitor();
	Sleep(1000);
	if (g_mainMsgKlib.GetKerInitStatus())
		g_mainMsgKlib.DriverFree();
	if (gpip_send)
		g_DataHandler.PipFree();

	g_mainMsgUlib.uMsg_Free();
	g_mainMsgKlib.kMsg_Free();
	return 0;
}
