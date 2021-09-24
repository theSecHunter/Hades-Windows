// wfptools.dll测试用例
// 2021.9.6
#include <Windows.h>

typedef int (*Pnf_init)(void);
Pnf_init nf_init;

typedef int (*Pnf_getprocessinfo)(UINT32* Locaaddripv4, unsigned long localport, int protocol, PVOID64 getbuffer);
Pnf_getprocessinfo nf_getprocessinfo;

typedef int (*Pnf_monitor)(int code);
Pnf_monitor nf_monitor;

typedef struct _PROCESS_INFO
{
	WCHAR  processPath[260];
	UINT64 processId;
}PROCESS_INFO, * PPROCESS_INFO;

int main(void)
{
	DWORD status = 0;
	do
	{
		HMODULE wfpdll = LoadLibrary(L"wfptools.dll");
		if (!wfpdll)
			break;

		nf_init = (Pnf_init)GetProcAddress(wfpdll,"nf_init");
		if (!nf_init)
			break;

		nf_getprocessinfo = (Pnf_getprocessinfo)GetProcAddress(wfpdll, "nf_getprocessinfo");
		if (!nf_getprocessinfo)
			break;

		nf_monitor = (Pnf_monitor)GetProcAddress(wfpdll, "nf_monitor");
		if (!nf_monitor)
			break;

		// 1) 初始化： 函数封装驱动交互 - processinfo数据构建
		nf_init();

		system("pause");

		/*
			1.  ipv4 address - ipv6(数据有)
			2.  本地端口
			3.  协议 tcp - udp
			4.  指针
		*/
		PROCESS_INFO processinfo;
		RtlSecureZeroMemory(&processinfo, sizeof(PROCESS_INFO));
		UINT32 ipv4addr = 0x2199562432;
		unsigned long localport = 53;
		// 2) 获取进程信息
		status = nf_getprocessinfo(&ipv4addr, localport, IPPROTO_TCP, &processinfo);
		if (status == 1)
		{
			// Success
			processinfo.processId;
			processinfo.processPath;
		}

		// 需要支持ipv6地址查询

		// 3）暂停监控 - 并不是关闭驱动和DLL - 只是不在做数据抓捕
		status = nf_monitor(0);

		// 4) 启用监控 - 开启抓捕
		status = nf_monitor(1);

		// 5) DLL释放 - 堆上数据怕泄露

	} while (false);

	return 0;
}