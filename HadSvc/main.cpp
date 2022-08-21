#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <queue>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

//#include "sysinfo.h"
#include "grpc.h"
#include "umsginterface.h"
#include "kmsginterface.h"
#include "msgloop.h"
#include "HlprMiniCom.h"
#include <usysinfo.h>

#ifdef _WIN64
	#ifdef _DEBUG
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib_d64.lib")
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d64.lib")
	#else
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib64.lib")
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib64.lib")
	#endif
#else
	#ifdef _DEBUG
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib_d.lib")
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d.lib")
	#else
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib.lib")
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib.lib")
	#endif
#endif

static kMsgInterface	g_mainMsgKlib;
static uMsgInterface	g_mainMsgUlib;
static WinMsgLoop		g_MsgControl;
static HlprMiniPortIpc	g_miniport;
static HANDLE			g_hPipe = nullptr;
static USysBaseInfo		g_DynSysBaseinfo;

// Debug调试 标志控制
static bool kerne_mon = false;		// kernel采集
static bool kerne_rootkit = false;	// rootkit接口
static bool user_mod = false;		// user接口
static bool etw_mon = false;		// user采集
static bool grpc_send = false;		// grpc上报
static char g_chNameGuid[64] = { 0 };	// agentid

static HANDLE g_SvcExitEvent = nullptr;

static DWORD pthread_grpread(LPVOID lpThreadParameter)
{
	Grpc* greeter = (Grpc*)lpThreadParameter;
	greeter->Grpc_ReadC2Thread(NULL);
	return 1;
}
// 检测HadesContrl是否活跃
static DWORD WINAPI HadesContrlActiveCheckNotify(LPVOID lpThreadParameter)
{
	for (;;)
	{//检测Event或者窗口
		HWND wxHand = FindWindowEx(NULL, NULL, L"HadesMainWindow", NULL);
		if (wxHand)
		{
			Sleep(1000);
		}
		else
		{
			if (g_SvcExitEvent)
			{
				SetEvent(g_SvcExitEvent);
				Sleep(100);
				CloseHandle(wxHand);
				break;
			}
		}
	}
	return 0;
}
// 检测Grpc_Server是否活跃
static DWORD WINAPI HadesServerActiveCheckNotify(LPVOID lpThreadParameter)
{
	Grpc* grpcobj = (Grpc*)lpThreadParameter;
	if (!grpcobj)
	{
		if (g_SvcExitEvent)
		{
			SetEvent(g_SvcExitEvent);
		}
		return 0;
	}

	static ::grpc::RawData rawData;
	static ::grpc::Record* pkg = rawData.add_data();
	static ::grpc::Item* item = rawData.add_item();
	pkg->set_datatype(1);
	pkg->set_timestamp(GetCurrentTime());
	auto MapMessage = item->mutable_fields();
	for (;;)
	{
		try
		{
			(*MapMessage)["cpu"] = std::to_string(g_DynSysBaseinfo.GetSysDynSysMem());
			(*MapMessage)["memory"] = std::to_string(g_DynSysBaseinfo.GetSysDynCpuUtiliza());
			if (false == grpcobj->Grpc_Transfer(rawData))
			{
				if (g_SvcExitEvent)
				{
					SetEvent(g_SvcExitEvent);
					Sleep(100);
					break;
				}
			}
		}
		catch (const std::exception&)
		{
		}
		Sleep(2000); // 2s发送一次心跳检测
	}
	return 0;
}
// PipClient
static DWORD WINAPI PipConnectNotifyMsg(LPVOID lpThreadParameter)
{
	WaitNamedPipe(L"\\\\.\\Pipe\\hadesctlport", NMPWAIT_WAIT_FOREVER);
	g_hPipe = CreateFile(L"\\\\.\\Pipe\\hadesctlport", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_hPipe)
	{
		char Databuffer[1024] = { 0 };
		DWORD dwRead = 0;
		DWORD dwAvail = 0;
		do
		{
			// PeekNamePipe用来预览一个管道中的数据，用来判断管道中是否为空
			if (!PeekNamedPipe(g_hPipe, NULL, NULL, &dwRead, &dwAvail, NULL) || dwAvail <= 0)
			{
				break;
			}
			if (ReadFile(g_hPipe, Databuffer, 1024, &dwRead, NULL))
			{
				if (dwRead != 0)
				{

				}
			}
		} while (TRUE);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	// Create HadesSvc Event - HadesContrl检测该Event判断HadesSvc是否活跃
	HANDLE HadesSvcEvent = CreateEvent(NULL, FALSE, FALSE, L"Global\\HadesSvc_EVENT");
	// HadesSvc Exit Event - HadesContrl退出设置该Event，HadesSvc也退出
	g_SvcExitEvent = CreateEvent(NULL, FALSE, FALSE, L"Global\\HadesSvc_EVNET_EXIT");
	// Open HadesContrl Event - 如果连接GRPC成功，设置该事件，HadesContrl更新连接状态
	HANDLE HadesSvcConnectStatus_Event = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Global\\HadesContrl_Event");
	if (!HadesSvcConnectStatus_Event || !g_SvcExitEvent || !HadesSvcEvent)
		return 0;

	// 127.0.0.1 121.4.171.129
	std::string ip_port = "127.0.0.1:8888";
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-ip") == 0)
		{
			if ((i + 1) >= argc)
			{
				exit(1);
			}
			std::string RstmpStrIp = argv[i + 1];
			if (RstmpStrIp.size())
				ip_port = RstmpStrIp;
			else
				ip_port = "localhost";
			i++;
		}
		else if (strcmp(argv[i], "-p") == 0)
		{
			if ((i + 1) >= argc)
			{
				exit(1);
			}
			std::string RstmpStrPort = argv[i + 1];
			if (RstmpStrPort.size())
			{
				ip_port += ":";
				ip_port += RstmpStrPort;
			}
			else
				ip_port += ":8888";
			i++;
		}
		else
		{
			exit(0);
		}
	}

	// 
	// @ Grpc Active Online Send to  Server Msg
	// SSL
	auto rootcert = get_file_contents(rootcrt_path);
	auto clientkey = get_file_contents(clientkey_path);
	auto clientcert = get_file_contents(clientcrt_path);
	grpc::SslCredentialsOptions ssl_opts;
	ssl_opts.pem_root_certs = rootcert;
	ssl_opts.pem_cert_chain = clientcert;
	ssl_opts.pem_private_key = clientkey;
	std::shared_ptr<grpc::ChannelCredentials> channel_creds = grpc::SslCredentials(ssl_opts);
	
	// Grpc_SSL模式未测
	// grpc::InsecureChannelCredentials()
	static Grpc greeter(
		grpc::CreateChannel(ip_port.c_str(), grpc::InsecureChannelCredentials()));
	grpc::RawData rawData;
	
	// agent_info
	DWORD ComUserLen = MAX_PATH;
	CHAR ComUserName[MAX_PATH] = { 0, };
	GetComputerNameA(ComUserName, &ComUserLen);
	GUID LinkGuid = { 0 };
	if (S_OK == ::CoCreateGuid(&LinkGuid))
	{
		char buf[64] = { 0 };
		::sprintf_s(buf, sizeof(buf), "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
			LinkGuid.Data1, LinkGuid.Data2, LinkGuid.Data3,
			LinkGuid.Data4[0], LinkGuid.Data4[1],
			LinkGuid.Data4[2], LinkGuid.Data4[3],
			LinkGuid.Data4[4], LinkGuid.Data4[5],
			LinkGuid.Data4[6], LinkGuid.Data4[7]);
		::strcpy_s(g_chNameGuid, ARRAYSIZE(g_chNameGuid), buf);
	}
	rawData.set_hostname(ComUserName);
	rawData.set_version("v2.1");
	rawData.set_agentid(g_chNameGuid);
	if (false == greeter.Grpc_Transfer(rawData))
		grpc_send = false;
	else
		grpc_send = true;

	// 通知界面Contrl已经连接Grpc
	if ( (true == grpc_send) && (0 < (int)HadesSvcConnectStatus_Event) )
	{
		SetEvent(HadesSvcConnectStatus_Event);
		CloseHandle(HadesSvcConnectStatus_Event);
	}
	else
	{
		CloseHandle(HadesSvcEvent);
		CloseHandle(HadesSvcConnectStatus_Event);
		CloseHandle(g_SvcExitEvent);
		return 0;
	}

	SYSTEMTIME time;
	GetLocalTime(&time);
	char dateTimeStr[200] = { 0 };
	sprintf(dateTimeStr, "%d-%02d-%02d %02d:%02d:%02d\t", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
	OSVERSIONINFOEX osver;
	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	//获取版本信息
	if (!GetVersionEx((LPOSVERSIONINFO)&osver))
	{
		cout << "Error:" << GetLastError() << endl;
	}
	rawData.Clear();
	rawData.set_hostname(ComUserName);
	rawData.set_version("v2.1");
	rawData.set_agentid(g_chNameGuid);
	rawData.add_intranetipv4("localhost");
	rawData.add_extranetipv4("localhost");
	rawData.add_intranetipv6("localhost");
	rawData.add_extranetipv6("localhost");
	::grpc::Record* pkg_re = rawData.add_data();
	pkg_re->set_datatype(0);
	pkg_re->set_timestamp(GetCurrentTime());
	greeter.Grpc_Transfer(rawData);
	
	// start grpc Read thread (Wait server Data) handler C2_Msg loop
	DWORD threadid = 0;
	HANDLE grocRead = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pthread_grpread, &greeter, 0, &threadid);
	// init grpc Heartbeat detection 
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HadesServerActiveCheckNotify, &greeter, 0, &threadid);
	// start grpc write thread
	greeter.ThreadPool_Init();

	// 设置Lib对象指针
	if (false == g_MsgControl.setUmsgLib(&g_mainMsgUlib) || false == g_MsgControl.setKmsgLib(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置MsgViewController指针失败");
		return 0;
	}
	if (false == greeter.SetUMontiorLibPtr(&g_mainMsgUlib) || false == greeter.SetKMontiorLibPtr(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置GrpcLib指针失败");
		return 0;
	}
	
	g_mainMsgUlib.uMsg_Init();
	g_mainMsgKlib.kMsg_Init();

	// Debug接口测试
	if (true == grpc_send && (true == kerne_rootkit || true == kerne_mon))
	{
		g_mainMsgKlib.DriverInit(false);

		cout << "Rootkit上报接口测试:" << endl;

		grpc::Command cmd;
		cmd.set_agentctrl(100);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(101);
		greeter.Grpc_ReadDispatchHandle(cmd);

		//cmd.Clear(); -- 有硬编码不同系统会有问题Dpc
		//cmd.set_agentctrl(103);
		//greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(108);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(109);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(110);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(111);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(113);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(115);
		greeter.Grpc_ReadDispatchHandle(cmd);
	}
	if (true == grpc_send && true == user_mod)
	{
		cout << "User下发接口测试" << endl;
		grpc::Command cmd;
		cmd.set_agentctrl(200);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(202);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(203);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(204);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(207);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(208);
		greeter.Grpc_ReadDispatchHandle(cmd);

		//cmd.Clear();
		//cmd.set_agentctrl(UF_SYSFILE_ID);
		//greeter.Grpc_ReadDispatchHandle(cmd);
		// 数据未清理
		//cmd.Clear();
		//cmd.set_agentctrl(UF_FILE_INFO);
		//greeter.Grpc_ReadDispatchHandle(cmd);
		// 上线后已上报
		//cmd.Clear();
		//cmd.set_agentctrl(UF_SYSINFO_ID);
		//greeter.Grpc_ReadDispatchHandle(cmd);
		// 数据未清理
		//cmd.Clear();
		//cmd.set_agentctrl(UF_PROCESS_PID_TREE);
		//greeter.Grpc_ReadDispatchHandle(cmd);

	}
	if (true == grpc_send && true == etw_mon) {
		g_mainMsgUlib.uMsg_EtwInit();
	}

	// 判断主界面是否已经退出
	CreateThread(NULL, 0, HadesContrlActiveCheckNotify, NULL, 0, &threadid);
	// 更改PipConnect --> Socket_Connect同步
	//CreateThread(NULL, 0, PipConnectNotifyMsg, NULL, 0, &threadid);
	
	// 等待主界面退出激活事件,否则一直不退出
	WaitForSingleObject(g_SvcExitEvent, INFINITE);
	CloseHandle(g_SvcExitEvent);
	g_SvcExitEvent = nullptr;

	if (grocRead)
	{
		TerminateThread(grocRead, 0);
		CloseHandle(grocRead);
	}	
	if (g_hPipe)
		CloseHandle(g_hPipe);
	if (g_mainMsgUlib.GetEtwMonStatus())
		g_mainMsgUlib.uMsg_EtwClose();
	if (g_mainMsgKlib.GetKerMonStatus())
		g_mainMsgKlib.OffMonitor();
	if (g_mainMsgKlib.GetKerInitStatus())
		g_mainMsgKlib.DriverFree();

	g_mainMsgUlib.uMsg_Free();
	g_mainMsgKlib.kMsg_Free();
	CloseHandle(HadesSvcEvent);
	return 0;
}
