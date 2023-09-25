#include <WS2tcpip.h>
#include <sysinfo.h>
#include "NetApi.h"
#include "nfevents.h"
#include "EventHandler.h"
#include "tcpctx.h"
#include "datalinkctx.h"
#include "establishedctx.h"
#include "singGlobal.h"
#include "CodeTool.h"
#include <mutex>
#include <map>
#include <vector>
#include <Psapi.h>
#include <ifdef.h>

#pragma comment(lib, "Ws2_32.lib")

// UDP Packet Option
#pragma pack(push, 1)
typedef struct _NF_UDP_PACKET_OPTIONS
{
	COMPARTMENT_ID		compartmentId;
	UINT64				endpointHandle;
	SCOPE_ID			remoteScopeId;
	IF_INDEX			interfaceIndex;
	IF_INDEX			subInterfaceIndex;
	ULONG				controlDataLength;
	UINT32				transportHeaderLength;
	unsigned char		localAddr[NF_MAX_ADDRESS_LENGTH];
} NF_UDP_PACKET_OPTIONS, * PNF_UDP_PACKET_OPTIONS;
#pragma pack(pop)

#ifdef _DEBUG
static bool bLog = true;
#else
static bool bLog = false;
#endif

void EventHandler::EstablishedPacket(const char* buf, int len)
{
	NF_CALLOUT_FLOWESTABLISHED_INFO flowestablished_processinfo;
	RtlSecureZeroMemory(&flowestablished_processinfo, sizeof(NF_CALLOUT_FLOWESTABLISHED_INFO));
	RtlCopyMemory(&flowestablished_processinfo, buf, len);

	if (bLog) {
		std::string strInfo = "";
		CHAR info[MAX_PATH] = { 0, };
		if (flowestablished_processinfo.addressFamily == AF_INET) {
			const std::string strLAddr = inet_ntoa(*(IN_ADDR*)&flowestablished_processinfo.ipv4LocalAddr);
			const std::string strRAddr = inet_ntoa(*(IN_ADDR*)&flowestablished_processinfo.ipv4toRemoteAddr);
			sprintf(info, "[HadesNetMon] Locate: 0x%s:%d -> remote: 0x%s:%d type: %d", \
				strLAddr.c_str(), flowestablished_processinfo.toLocalPort, \
				strRAddr.c_str(), flowestablished_processinfo.toRemotePort, \
				flowestablished_processinfo.protocol
			);
			strInfo = info;
			strInfo.append(" ProcessPath ").append(CodeTool::WStr2Str(flowestablished_processinfo.processPath));
			OutputDebugStringA(strInfo.c_str());
		}
	}
}

void EventHandler::DatalinkPacket(const char* buf, int len)
{
	NF_CALLOUT_MAC_INFO datalink_netinfo;
	RtlSecureZeroMemory(&datalink_netinfo, sizeof(NF_CALLOUT_MAC_INFO));
	RtlCopyMemory(&datalink_netinfo, buf, len);

	if (bLog) {
		std::string strInfo = "";
		CHAR info[MAX_PATH] = { 0, };
		if (datalink_netinfo.addressFamily == AF_INET) {
			const std::string strSrcAddr = (LPCSTR)datalink_netinfo.mac_info.pSourceAddress;
			const std::string strRAddr = (LPCSTR)datalink_netinfo.mac_info.pDestinationAddress;
			OutputDebugStringA(("[HadesNetMon] MacInfo Src " + strSrcAddr + " Dest" + strRAddr).c_str());
		}
	}
}

void EventHandler::TcpredirectPacket(const char* buf, int len)
{
	PNF_TCP_CONN_INFO pTcpConnectInfo = nullptr;
	pTcpConnectInfo = (PNF_TCP_CONN_INFO)buf;
	if (!pTcpConnectInfo)
		return;

	if ((pTcpConnectInfo->ip_family != AF_INET) && (pTcpConnectInfo->ip_family != AF_INET6))
		return;

	// [+] 下个版本会直接内核带上来ProcessName
	std::string strProcessName = "";
	const HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pTcpConnectInfo->processId);
	if (processHandle) {
		char cProcName[MAX_PATH] = { 0 };
		GetModuleBaseNameA(processHandle, NULL, cProcName, MAX_PATH);
		strProcessName = cProcName;
		CloseHandle(processHandle);
	}

	bool bIp6 = false;
	// Local
	sockaddr_in* const pLocalAddr = (sockaddr_in*)pTcpConnectInfo->localAddress;
	if (!pLocalAddr)
		return;
	DWORD dwLIp = 0; WORD wLPort = 0; std::string strLIpv6Addr = "";
	// Remote
	sockaddr_in* const pRemoteAddr = (sockaddr_in*)pTcpConnectInfo->remoteAddress;
	if (!pRemoteAddr)
		return;
	DWORD dwRIp = 0; WORD wRPort = 0; std::string strRIpv6Addr = "";

	if (pTcpConnectInfo->ip_family == AF_INET6) {
		do
		{
			// Local
			const sockaddr_in6* pAddr6 = (sockaddr_in6*)pLocalAddr;
			if (!pAddr6)
				break;
			char sIp[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &pAddr6->sin6_addr, sIp, INET6_ADDRSTRLEN);
			strLIpv6Addr = sIp;
			wLPort = ntohs(pAddr6->sin6_port);
		} while (false);

		do
		{
			// Remote
			const sockaddr_in6* pAddr6 = (sockaddr_in6*)pRemoteAddr;
			if (!pAddr6)
				break;
			char sIp[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &pAddr6->sin6_addr, sIp, INET6_ADDRSTRLEN);
			strRIpv6Addr = sIp;
			wRPort = ntohs(pAddr6->sin6_port);
		} while (false);
		bIp6 = true;
	}
	else
	{
		// Local
		dwLIp = pLocalAddr->sin_addr.S_un.S_addr;
		wLPort = ntohs(pLocalAddr->sin_port);

		// Remote
		dwRIp = pRemoteAddr->sin_addr.S_un.S_addr;
		wRPort = ntohs(pRemoteAddr->sin_port);
	}

	// Local
	std::string sLIp = "";
	if (bIp6) {
		sLIp = strLIpv6Addr.c_str();
	}
	else
	{
		sLIp = inet_ntoa(*(IN_ADDR*)&dwLIp);
	}

	// Remote
	std::string sRIp = "";
	if (bIp6) {
		sRIp = strRIpv6Addr.c_str();
	}
	else
	{
		sRIp = inet_ntoa(*(IN_ADDR*)&dwRIp);
	}

	// Log
	if(bLog)
	{
		const std::string strOutPut = ("[HadesNetMon] Tcp Connect Pid " + to_string(pTcpConnectInfo->processId) + " SrcIp " + sLIp + ":" + to_string(wLPort) + " DstIp " + sRIp + ":" + to_string(wRPort)).c_str();
		OutputDebugStringA(strOutPut.c_str());
	}

	try
	{
		// Rule yaml
		if (SingletonNetRule::instance()->FilterConnect(sRIp.c_str(), wRPort)) {
			if (bLog)
				OutputDebugStringA("[HadesNetMon] Tcp NF_BLOCK ");
			pTcpConnectInfo->filteringFlag = (unsigned long)NF_BLOCK;
			return;
		}

		std::string strRediRectIp = ""; int nRedirectPort = 0;
		if (!strProcessName.empty() && SingletonNetRule::instance()->RedirectTcpConnect(strProcessName, sRIp.c_str(), wRPort, strRediRectIp, nRedirectPort)) { 
			if (pTcpConnectInfo->ip_family == AF_INET)
			{
				sockaddr_in addr;
				RtlSecureZeroMemory(&addr, sizeof(addr));
				addr.sin_family = AF_INET;
				addr.sin_addr.S_un.S_addr = inet_addr(strRediRectIp.c_str());
				addr.sin_port = htons(nRedirectPort);
				memcpy(pTcpConnectInfo->remoteAddress, &addr, sizeof(addr));
			}
			else
			{
				sockaddr_in6 addr;
				RtlSecureZeroMemory(&addr, sizeof(addr));
				addr.sin6_family = AF_INET6;
				inet_pton(AF_INET6, strRediRectIp.c_str(), &addr.sin6_addr.u);
				addr.sin6_port = htons(nRedirectPort);
				memcpy(pTcpConnectInfo->remoteAddress, &addr, sizeof(addr));
			}
			pTcpConnectInfo->processId = GetCurrentProcessId();
			if (bLog)
				OutputDebugStringA(("[HadesNetMon] Tcp Redirect to PorxyServer: " + strRediRectIp + ":" + to_string(nRedirectPort)).c_str());
			return;
		}
	}
	catch (const std::exception&)
	{

	}
	return;
}

void EventHandler::UdpSend(const int id, const char* buf, int len)
{
	do
	{
		// Option
		PNF_UDP_PACKET_OPTIONS pOption = (PNF_UDP_PACKET_OPTIONS)buf;
		if (!pOption)
			break;
		
		// LocalAddr
		char* pLocalAddr = nullptr;
		pLocalAddr = (char*)pOption->localAddr;
		if (!pLocalAddr)
			break;

		// RemoteAdrr
		char* pRemoteAddr = nullptr;
		pRemoteAddr = (char*)(buf + sizeof(NF_UDP_PACKET_OPTIONS));
		if (!pRemoteAddr)
			break;

		// Data
		const int DataLens = len - sizeof(NF_DATA) - sizeof(NF_UDP_PACKET_OPTIONS) + NF_MAX_ADDRESS_LENGTH;
		char* pPacketData = nullptr;
		pPacketData = (char*)(buf + sizeof(NF_UDP_PACKET_OPTIONS) + NF_MAX_ADDRESS_LENGTH);
		if (!pPacketData)
			break;

		sockaddr_in const* pRAddr = (sockaddr_in*)pRemoteAddr;
		if (!pRAddr)
			break;
		if ((pRAddr->sin_family != AF_INET) && (pRAddr->sin_family != AF_INET6))
			break;

		WORD wPort = 0; DWORD dwIp = 0; bool bIp6 = false; std::string strIpv6Addr = "";
		if (pRAddr->sin_family == AF_INET6)
		{
			sockaddr_in6* const pAddr6 = (sockaddr_in6*)pRAddr;
			if (pAddr6) {
				char sIp[INET6_ADDRSTRLEN] = { 0 };
				inet_ntop(AF_INET6, &pAddr6->sin6_addr, sIp, INET6_ADDRSTRLEN);
				strIpv6Addr = sIp;
			}
			wPort = ntohs(pAddr6->sin6_port);
			bIp6 = true;
		}
		else
		{
			dwIp = pRAddr->sin_addr.S_un.S_addr;
			wPort = ntohs(pRAddr->sin_port);
		}
		std::string sIp = "";
		if (bIp6) {
			sIp = strIpv6Addr.c_str();
		}
		else
		{
			sIp = inet_ntoa(*(IN_ADDR*)&dwIp);
		}
		if (bLog) {
			std::string pOutPut = "[HadesNetMon] udp Send Id ";
			pOutPut.append(std::to_string(id));
			pOutPut.append(" RemoteAddr ").append(sIp).append(":").append(std::to_string(wPort));
			OutputDebugStringA(pOutPut.c_str());
		}
	} while (false);
}

void EventHandler::UdpRecv(const int id, const char* buf, int len)
{
	do
	{
		// Option
		PNF_UDP_PACKET_OPTIONS pOption = (PNF_UDP_PACKET_OPTIONS)buf;
		if (!pOption)
			break;

		// LocalAddr
		char* pLocalAddr = nullptr;
		pLocalAddr = (char*)pOption->localAddr;
		if (!pLocalAddr)
			break;

		// RemoteAdrr
		char* pRemoteAddr = nullptr;
		pRemoteAddr = (char*)(buf + sizeof(NF_UDP_PACKET_OPTIONS));
		if (!pRemoteAddr)
			break;

		// Data
		const int DataLens = len - sizeof(NF_DATA) - sizeof(NF_UDP_PACKET_OPTIONS) + NF_MAX_ADDRESS_LENGTH;
		char* pPacketData = nullptr;
		pPacketData = (char*)(buf + sizeof(NF_UDP_PACKET_OPTIONS) + NF_MAX_ADDRESS_LENGTH);
		if (!pPacketData)
			break;

		sockaddr_in const* pRAddr = (sockaddr_in*)pRemoteAddr;
		if (!pRAddr)
			break;
		if ((pRAddr->sin_family != AF_INET) && (pRAddr->sin_family != AF_INET6))
			break;

		WORD wPort = 0; DWORD dwIp = 0; bool bIp6 = false; std::string strIpv6Addr = "";
		if (pRAddr->sin_family == AF_INET6)
		{
			sockaddr_in6* const pAddr6 = (sockaddr_in6*)pRAddr;
			if (pAddr6) {
				char sIp[INET6_ADDRSTRLEN] = { 0 };
				inet_ntop(AF_INET6, &pAddr6->sin6_addr, sIp, INET6_ADDRSTRLEN);
				strIpv6Addr = sIp;
			}
			wPort = ntohs(pAddr6->sin6_port);
			bIp6 = true;
		}
		else
		{
			dwIp = pRAddr->sin_addr.S_un.S_addr;
			wPort = ntohs(pRAddr->sin_port);
		}
		std::string sIp = "";
		if (bIp6) {
			sIp = strIpv6Addr.c_str();
		}
		else
		{
			sIp = inet_ntoa(*(IN_ADDR*)&dwIp);
		}
		if (bLog) {
			std::string pOutPut = "[HadesNetMon] udp Recv id ";
			pOutPut.append(std::to_string(id));
			pOutPut.append(" RemoteAddr ").append(sIp).append(":").append(std::to_string(wPort));
			OutputDebugStringA(pOutPut.c_str());
		}
	} while (false);
}