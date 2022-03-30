/*
	* mcfilter :  该程序负责r3的规则逻辑处理
*/
#include "HlprMiniCom.h"
#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fltuser.h>
#include "grpc.h"
#include "uetw.h"

#include <stdlib.h>

using namespace std;

const char devSyLinkName[] = "\\??\\KernelDark";
const int max_size = MAX_PATH * 3;

// 标志控制 - 后续config里面配置
static bool kerne_mon = true;	// grpc_send = true - rootkit接口开启
static bool user_mod = true;	// grpc_send = true - user接口开启
static bool etw_mon = true;
static bool grpc_send = false;

typedef struct _PE_CONTROL{
	string name;
	unsigned int type;
	unsigned int Permissions;
}PE_CONTROL, *PPE_CONTROL;

typedef struct _RULE_NODE {
	// rule public
	unsigned int module;
	string processname;

	// mode 1
	unsigned int redirectflag;
	string redirectdirectory;
	string filewhitelist;


	// mode 2
	vector<PE_CONTROL> pecontrol;

	// mode 3
	// ......

}RULE_NODE,*PRULE_NODE;

vector<RULE_NODE> g_ruleNode;

void helpPrintf() 
{
	string helpinfo = "支持功能规则如下\n";
	helpinfo += "1. 进程文件读写访问重定向\n";
	helpinfo += "2. 进程文件读写访问访问控制\n";
}
void charTowchar(const char* chr, wchar_t* wchar, int size)
{
	MultiByteToWideChar(CP_ACP, 0, chr,
		strlen(chr) + 1, wchar, size / sizeof(wchar[0]));
}

static UEtw g_testetw;

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
}
bool SysNodeOnlineData(RawData* sysinfobuffer)
{
	
	sysinfobuffer->mutable_pkg();
	return true;
}
typedef struct _SYSTEMONLIENNODE
{
	wchar_t platform[260];
	int id;
	__int64 id64;
}SYSTEMONLIENNODE, * PSYSTEMONLIENNODE;

DWORD pthread_grpread(LPVOID lpThreadParameter)
{
	Grpc* greeter = (Grpc*)lpThreadParameter;
	greeter->Grpc_ReadC2Thread(NULL);
	return 1;
}

// user id
enum USystemCollId1
{
	UF_PROCESS_ENUM = 200,
	UF_PROCESS_PID_TREE,
	UF_SYSAUTO_START,
	UF_SYSNET_INFO,
	UF_SYSSESSION_INFO,
	UF_SYSINFO_ID,
	UF_SYSLOG_ID,
	UF_SYSUSER_ID,
	UF_SYSSERVICE_SOFTWARE_ID,
	UF_SYSFILE_ID,
	UF_FILE_INFO,
	UF_ROOTKIT_ID
};

//////////////////////////////////////////////
// Example
int main(int argc, char* argv[])
{
	// Etw Start
	cout << "etw test start" << endl;
	g_testetw.uf_init();
	getchar();
	g_testetw.uf_close();
	cout << "etw test End" << endl;
	system("pause");
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
	// grpc::InsecureChannelCredentials()
	static Grpc greeter(
		grpc::CreateChannel("localhost:8888", grpc::InsecureChannelCredentials()));

	printf("greeteraddr %p\n", &greeter);
	
	proto::RawData rawData;
	DWORD ComUserLen = MAX_PATH;
	CHAR ComUserName[MAX_PATH] = { 0, };
	GetComputerNameA(ComUserName, &ComUserLen);
	// Send Agent
	rawData.set_hostname(ComUserName);
	rawData.set_version("0.1");
	rawData.set_agentid("123");
	rawData.set_timestamp(GetCurrentTime());
	if (false == greeter.Grpc_Transfer(rawData))
		grpc_send = false;
	else
		grpc_send = true;

	// Send System Onliy Buffer 
	rawData.Clear();
	rawData.set_hostname(ComUserName);
	rawData.set_version("0.1");
	rawData.set_agentid("123");
	rawData.set_timestamp(GetCurrentTime());
	::proto::Record* pkg_re = rawData.add_pkg();
	auto MapMessage = pkg_re->mutable_message();
	(*MapMessage)["platform"] =  "windows";
	(*MapMessage)["agent_id"] = "123";
	(*MapMessage)["timestamp"] = "1111";
	(*MapMessage)["hostname"] = ComUserName;
	(*MapMessage)["version"] = "0.1";
	(*MapMessage)["in_ipv4_list"] = "localhost";
	(*MapMessage)["in_ipv6_list"] = "localhost";
	(*MapMessage)["data_type"] = "1";
	if (false == greeter.Grpc_Transfer(rawData))
		grpc_send = false;
	else
		grpc_send = true;

	// start grpc read thread (Wait server Data)
	DWORD threadid = 0;
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pthread_grpread, &greeter, 0, &threadid);
	// start grpc write thread
	greeter.ThreadPool_Init();

	int status = 0;

	/*
	// kernel mod
	if (true == kerne_mon)
	{
		// Init devctrl
		status = devobj.devctrl_init();
		if (0 > status)
		{
			cout << "devctrl_init error: main.c --> lines: 342" << endl;
			return -1;
		}

		do
		{
			// Open driver
			status = devobj.devctrl_opendeviceSylink(devSyLinkName);
			if (0 > status)
			{
				cout << "devctrl_opendeviceSylink error: main.c --> lines: 352" << endl;
				break;
			}

			// Init share Mem
			status = devobj.devctrl_InitshareMem();
			if (0 > status)
			{
				cout << "devctrl_InitshareMem error: main.c --> lines: 360" << endl;
				break;
			}

			// ReadFile I/O Thread
			status = devobj.devctrl_workthread((LPVOID)&greeter);
			if (0 > status)
			{
				cout << "devctrl_workthread error: main.c --> lines: 367" << endl;
				break;
			}

			// Off/Enable try Network packte Monitor
			status = devobj.devctrl_OnMonitor();
			if (0 > status)
			{
				cout << "devctrl_InitshareMem error: main.c --> lines: 375" << endl;
				break;
			}

			// Enable Event --> 内核提取出来数据以后处理类
			devobj.nf_setEventHandler((PVOID)&eventobj);

			status = 1;

		} while (false);

		if (!status)
		{
			OutputDebugString(L"Init Driver Failuer");
			return -1;
		}

		if (true == grpc_send)
		{
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

	}
	*/

	// user mod
	if (true == grpc_send && true == user_mod)
	{
		cout << "User下发接口测试" << endl;
		Command cmd;
		cmd.set_agentctrl(UF_PROCESS_ENUM);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_PROCESS_PID_TREE);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSAUTO_START);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSNET_INFO);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSSESSION_INFO);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSINFO_ID);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSLOG_ID);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSUSER_ID);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSSERVICE_SOFTWARE_ID);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_SYSFILE_ID);
		greeter.Grpc_ReadDispatchHandle(cmd);

		cmd.Clear();
		cmd.set_agentctrl(UF_ROOTKIT_ID);
		greeter.Grpc_ReadDispatchHandle(cmd);
	}

	// etw mod
	if (true == etw_mon)
	{
		g_testetw.uf_init();
	}

	cout << "输入回车结束进程" << endl;
	getchar();
	//dev	obj.devctrl_free();
	g_testetw.uf_close();
	return 0;
}
