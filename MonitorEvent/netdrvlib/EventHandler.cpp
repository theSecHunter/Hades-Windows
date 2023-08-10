#include <WS2tcpip.h>
#include <sysinfo.h>
#include "NetApi.h"
#include "nfevents.h"
#include "EventHandler.h"
#include "tcpctx.h"
#include "datalinkctx.h"
#include "establishedctx.h"
#include "CodeTool.h"
#include <mutex>
#include <map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

static bool bLog = false;

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
			dwLIp = 1; wLPort = ntohs(pAddr6->sin6_port);
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
			dwRIp = 1; wRPort = ntohs(pAddr6->sin6_port);
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

	// Rule yaml
	//pTcpConnectInfo->filteringFlag = NF_BLOCK;
}