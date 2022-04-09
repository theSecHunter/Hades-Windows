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

#ifdef _WIN64
	#ifdef _DEBUG
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmondrv\\lib\\SysMonDrvlib_d64.lib")
	#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib64.lib")
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

// 标志控制 - 后续config里面配置
static bool kerne_mon = false;		// kernel采集
static bool kerne_rootkit = false;	// rootkit接口
static bool user_mod = true;		// user接口
static bool etw_mon = true;			// user采集
static bool grpc_send = false;		// grpc上报

bool gethostip(RawData* ip_liststr)
{
	WSAData data;
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
		return false;

	char host[255] = { 0, };
	do {

		if (gethostname(host, sizeof(host)) == SOCKET_ERROR)
			break;

		auto p = gethostbyname(host);
		if (p == 0)
			break;
		else
		{
			for (int i = 0; p->h_addr_list[i] != 0; i++)
			{
				struct in_addr in;
				memcpy(&in, p->h_addr_list[i], sizeof(struct in_addr));
				ip_liststr->set_intranetipv4(i, inet_ntoa(in));
			}
		}
	
	} while (false);

	WSACleanup();

	return true;
}
bool SysNodeOnlineData(RawData* sysinfobuffer)
{
	sysinfobuffer->mutable_pkg();
	return true;
}
DWORD pthread_grpread(LPVOID lpThreadParameter)
{
	Grpc* greeter = (Grpc*)lpThreadParameter;
	greeter->Grpc_ReadC2Thread(NULL);
	return 1;
}
int main(int argc, char* argv[])
{
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
	
	// Grpc_SSL模式目前不支持 - 认证还有问题
	// grpc::InsecureChannelCredentials() localhost
	static Grpc greeter(
		grpc::CreateChannel("localhost:8888", grpc::InsecureChannelCredentials()));	
	proto::RawData rawData;

	// agent_info
	DWORD ComUserLen = MAX_PATH;
	CHAR ComUserName[MAX_PATH] = { 0, };
	GetComputerNameA(ComUserName, &ComUserLen);
	char chNameGuid[64] = { 0 };
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
		::strcpy_s(chNameGuid, ARRAYSIZE(chNameGuid), buf);
	}
	rawData.set_hostname(ComUserName);
	rawData.set_version("v2.0");
	rawData.set_agentid(chNameGuid); // guid = agentid
	rawData.set_timestamp(GetCurrentTime());
	if (false == greeter.Grpc_Transfer(rawData))
		grpc_send = false;
	else
		grpc_send = true;

	// current_sysinfo
	// 后续系统详细封装为公共类
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
	rawData.set_version("v2.0");
	rawData.set_agentid(chNameGuid);
	rawData.set_timestamp(GetCurrentTime());
	::proto::Record* pkg_re = rawData.add_pkg();
	auto MapMessage = pkg_re->mutable_message();
	(*MapMessage)["platform"] =  "windows";
	(*MapMessage)["agent_id"] = chNameGuid;
	(*MapMessage)["timestamp"] = dateTimeStr;
	(*MapMessage)["hostname"] = ComUserName;
	(*MapMessage)["version"] = to_string(osver.dwMajorVersion).c_str();
	(*MapMessage)["in_ipv4_list"] = "localhost";
	(*MapMessage)["in_ipv6_list"] = "localhost";
	(*MapMessage)["data_type"] = "1";
	(*MapMessage)["cpu"] = "1";
	(*MapMessage)["io"] = "1";
	(*MapMessage)["memory"] = "1";
	(*MapMessage)["slab"] = "1";
	if (false == greeter.Grpc_Transfer(rawData))
		grpc_send = false;
	else
		grpc_send = true;

	// start grpc Read thread (Wait server Data) handler C2_Msg loop
	DWORD threadid = 0;
	HANDLE grocRead = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pthread_grpread, &greeter, 0, &threadid);
	
	// init grpc Heartbeat detection 
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)心跳检测, &greeter, 0, &threadid);
	
	// start grpc write thread
	greeter.ThreadPool_Init();

	kMsgInterface g_mainMsgKlib;
	uMsgInterface g_mainMsgUlib;
	if (false == greeter.SetUMontiorLibPtr(&g_mainMsgUlib) || false == greeter.SetKMontiorLibPtr(&g_mainMsgKlib))
	{
		OutputDebugString(L"设置GrpcLib指针失败");
		return 0;
	}
	
	g_mainMsgUlib.uMsg_Init();
	g_mainMsgKlib.kMsg_Init();

	if (true == grpc_send && (true == kerne_rootkit || true == kerne_mon))
	{
		g_mainMsgKlib.DriverInit();

		cout << "Rootkit上报接口测试:" << endl;

		Command cmd;
		cmd.set_agentctrl(100);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(101);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(103);
		greeter.Grpc_ReadDispatchHandle(cmd);

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
		Command cmd;
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

	//MSG msg;
	//while (GetMessage(&msg, NULL, NULL, NULL))
	//{
	//	TranslateMessage(&msg);
	//	DispatchMessageW(&msg);
	//}
	getchar();
	if (grocRead)
	{
		TerminateThread(grocRead, 0);
		CloseHandle(grocRead);
	}	
	if (etw_mon)
		g_mainMsgUlib.uMsg_EtwClose();
	if (user_mod)
		g_mainMsgUlib.uMsg_Free();
	else if (kerne_mon)
	{
		g_mainMsgKlib.DriverFree();
		g_mainMsgKlib.kMsg_Free();
	}

	return 0;
}
