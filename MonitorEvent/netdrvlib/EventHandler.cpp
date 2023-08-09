#include <WS2tcpip.h>
#include <sysinfo.h>
#include "NetApi.h"
#include "nfevents.h"
#include "EventHandler.h"
#include "tcpctx.h"
#include "establishedctx.h"
#include "datalinkctx.h"
#include "CodeTool.h"
#include <mutex>
#include <map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

typedef struct _PROCESS_INFO
{
	UINT64 processId;
	WCHAR  processPath[MAX_PATH * 2];
	void clear()
	{
		processId = 0;
		RtlSecureZeroMemory(processPath, sizeof(processPath));
	}
}PROCESS_INFO, * PPROCESS_INFO;

static std::mutex g_mutx;
static std::map<int, NF_CALLOUT_FLOWESTABLISHED_INFO> g_flowestablished_map;

static std::vector<int>			ids_destinationport;
static std::vector<ULONGLONG>	ids_destinationaddress;
static std::vector<ULONGLONG>	ids_destinationaddressport;

void EventHandler::EstablishedPacket(const char* buf, int len)
{
	NF_CALLOUT_FLOWESTABLISHED_INFO flowestablished_processinfo;
	RtlSecureZeroMemory(&flowestablished_processinfo, sizeof(NF_CALLOUT_FLOWESTABLISHED_INFO));
	RtlCopyMemory(&flowestablished_processinfo, buf, len);

	/*
		TCP - UDP 不同协议相同端口将覆盖，因为需求不需要保存所有的包
	*/
	DWORD keyLocalPort = flowestablished_processinfo.toLocalPort;
	switch (flowestablished_processinfo.protocol)
	{
	case IPPROTO_TCP:
		keyLocalPort += 1000000;
		break;
	case IPPROTO_UDP:
		keyLocalPort += 2000000;
		break;
	default:
	{
		OutputDebugString(L"Other Protocol Erro");
	}
	}
	g_mutx.lock();
	g_flowestablished_map[keyLocalPort] = flowestablished_processinfo;
	g_mutx.unlock();

	//// test api 测试是否可以从map获取数据
	//PROCESS_INFO processinfo = { 0, };
	//nf_getprocessinfo(&flowestablished_processinfo.ipv4LocalAddr, flowestablished_processinfo.toLocalPort, flowestablished_processinfo.protocol, &processinfo);
	//processinfo.processId;
	//processinfo.processPath;

	// test path
	std::wstring wsinfo;
	WCHAR info[MAX_PATH] = { 0, };
	// swprintf(str, 100, L"%ls%d is %d", L"The half of ", 80, 80 / 2);
	swprintf(info, MAX_PATH, L"Locate: 0x%d:%d -> remote: 0x%d:%d type: %d", \
		flowestablished_processinfo.ipv4LocalAddr, flowestablished_processinfo.toLocalPort, \
		flowestablished_processinfo.ipv4toRemoteAddr, flowestablished_processinfo.toRemotePort, \
		flowestablished_processinfo.protocol
	);
	wsinfo = flowestablished_processinfo.processPath;
	wsinfo += L"\r\n";
	wsinfo += info;
	OutputDebugString(wsinfo.data());
}

void EventHandler::DatalinkPacket(const char* buf, int len)
{
	NF_CALLOUT_MAC_INFO datalink_netinfo;
	RtlSecureZeroMemory(&datalink_netinfo, sizeof(NF_CALLOUT_MAC_INFO));
	RtlCopyMemory(&datalink_netinfo, buf, len);

	OutputDebugString(L"-------------------------------------");
	OutputDebugStringA((LPCSTR)datalink_netinfo.mac_info.pSourceAddress);
	OutputDebugStringA((LPCSTR)datalink_netinfo.mac_info.pDestinationAddress);
	OutputDebugString(L"-------------------------------------");
}

void EventHandler::TcpredirectPacket(const char* buf, int len)
{
	PNF_TCP_CONN_INFO pTcpConnectInfo = NULL;
	pTcpConnectInfo = (PNF_TCP_CONN_INFO)buf;
	if (!pTcpConnectInfo)
		return;

	/*
		1 - 单要素：目標 port 或者 ip
		2 - 双要素：目标ip:port
		3 - 重定向标志位 - 暂时不开启
	*/
	sockaddr_in* const pAddr = (sockaddr_in*)pTcpConnectInfo->remoteAddress;
	if (!pAddr)
		return;
	if ((pAddr->sin_family != AF_INET) && (pAddr->sin_family != AF_INET6))
	{
		return;
	}

	bool bIp6 = false; DWORD dwIp = 0; WORD wPort = 0; std::string strIpv6Addr = "";
	if (pAddr->sin_family == AF_INET6)
	{
		const sockaddr_in6* pAddr6 = (sockaddr_in6*)pAddr;
		if (!pAddr6)
			return;
		char sIp[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, &pAddr6->sin6_addr, sIp, INET6_ADDRSTRLEN);
		strIpv6Addr = sIp;
		dwIp = 1; wPort = ntohs(pAddr6->sin6_port); bIp6 = true;
	}
	else
	{
		dwIp = pAddr->sin_addr.S_un.S_addr;
		wPort = ntohs(pAddr->sin_port);
	}

	std::string sIp = "";
	if (bIp6) {
		sIp = strIpv6Addr.c_str();
	}
	else
	{
		sIp = inet_ntoa(*(IN_ADDR*)&dwIp);
	}
}

/*
	@ 参数1 ipv4 address
	@ 参数2 本地端口
	@ 参数3 协议
	@ 参数4 数据指针
*/
int NetNdrGetProcessInfoEx(unsigned int* Locaaddripv4, unsigned long localport, int protocol, void* pGetbuffer)
{
	// -1 参数错误
	if (!Locaaddripv4 && (localport <= 0) && !pGetbuffer && !protocol)
		return  -1;

	switch (protocol)
	{
	case IPPROTO_TCP:
		localport += 1000000;
		break;
	case IPPROTO_UDP:
		localport += 2000000;
		break;
	}

	try
	{
		auto mapiter = g_flowestablished_map.find(localport);
		// -3 find failuer not`t processinfo
		if (mapiter == g_flowestablished_map.end())
			return -2;
		PPROCESS_INFO processinf = NULL;
		processinf = (PPROCESS_INFO)pGetbuffer;
		if (processinf) {
			processinf->processId = mapiter->second.processId;
			WCHAR ntPath[MAX_PATH] = { 0 };
			CodeTool::DeviceDosPathToNtPath(mapiter->second.processPath, ntPath);
			RtlCopyMemory(processinf->processPath, ntPath, sizeof(ntPath));
			return 1;
		}
		return -3;
	}
	catch (const std::exception&)
	{
		// 异常
		return -4;
	}
}