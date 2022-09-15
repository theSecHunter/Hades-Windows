#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <queue>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

#include "DataHandler.h"
#include "umsginterface.h"
#include "kmsginterface.h"
#include "msgloop.h"
#include "HlprMiniCom.h"
#include <usysinfo.h>

//#ifdef _WIN64
//	#ifdef _DEBUG
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib_d64.lib")
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d64.lib")
//	#else
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib64.lib")
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib64.lib")
//	#endif
//#else
//	#ifdef _DEBUG
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib_d.lib")
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d.lib")
//	#else
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib.lib")
//		#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib.lib")
//	#endif
//#endif

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
static bool etw_mon = false;		// user采集

static bool gpip_send = false;		// pip上报
static char g_chNameGuid[64] = { 0 };	// agentid

static HANDLE g_SvcExitEvent = nullptr;

int main(int argc, char* argv[])
{
	//Sleep(5000);
	// HadesSvc Exit Event - HadesSvc退出标识
	g_SvcExitEvent = CreateEvent(NULL, FALSE, FALSE, L"Global\\HadesSvc_EVNET_EXIT");
	// Init PipConnect
	true == g_DataHandler.PipInitAnonymous() ? gpip_send = true : gpip_send = false;
	if (!gpip_send || !g_SvcExitEvent)
		return 0;
	if(false == gpip_send)
	{
		g_DataHandler.PipFree();
		CloseHandle(g_SvcExitEvent);
		return 0;
	}
	else
	{
		// 通知界面Contrl连接Pip Success
		HANDLE HadesControlEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Global\\HadesContrl_Event");
		if (HadesControlEvent)
		{
			SetEvent(HadesControlEvent);
			CloseHandle(HadesControlEvent);
		}
	}

	// 设置退出Event
	g_DataHandler.SetExitSvcEvent(g_SvcExitEvent);

	// Test Pip
	//std::shared_ptr<uint8_t> data{ new uint8_t[MAX_PATH] };
	//DWORD dwRead = sizeof("hello server");
	//::memcpy(data.get(), "hello server", dwRead);
	//for (;;)
	//{
	//	g_DataHandler.PipWriteAnonymous(data, dwRead);
	//	Sleep(2000);
	//}

	// 初始化接收对象
	g_DataHandler.ThreadPool_Init();

	// Set HadesControl Lib ObjectPtr
	if (false == g_MsgControl.setUmsgLib(&g_mainMsgUlib) || false == g_MsgControl.setKmsgLib(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置MsgViewController指针失败");
		return 0;
	}
	// Set DataHandler Lib ObjectPtr
	if (false == g_DataHandler.SetUMontiorLibPtr(&g_mainMsgUlib) || false == g_DataHandler.SetKMontiorLibPtr(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置GrpcLib指针失败");
		return 0;
	}
	
	g_mainMsgUlib.uMsg_Init();
	g_mainMsgKlib.kMsg_Init();

	// Debug接口测试
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
	if (g_mainMsgKlib.GetKerMonStatus())
		g_mainMsgKlib.OffMonitor();
	if (g_mainMsgKlib.GetKerInitStatus())
		g_mainMsgKlib.DriverFree();
	if (gpip_send)
		g_DataHandler.PipFree();

	g_mainMsgUlib.uMsg_Free();
	g_mainMsgKlib.kMsg_Free();
	return 0;
}
