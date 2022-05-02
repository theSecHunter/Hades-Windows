//#include <Windows.h>
//#include "HlprSocketTcp.h"
//#include <mstcpip.h>
//#pragma comment(lib, "WS2_32.lib")
//
//HlprSocketTcp::HlprSocketTcp()
//{
//}
//HlprSocketTcp::~HlprSocketTcp()
//{
//
//}
//
//// 初始化API
//void* GetExtensionFunction(SOCKET s, const GUID* which_fn)
//{
//	void* ptr = NULL;
//	DWORD bytes = 0;
//	WSAIoctl(s,
//		SIO_GET_EXTENSION_FUNCTION_POINTER,
//		(GUID*)which_fn, sizeof(*which_fn),
//		&ptr, sizeof(ptr),
//		&bytes,
//		NULL,
//		NULL);
//	return ptr;
//}
//bool HlprSocketTcp::InitExtensions()
//{
//	const GUID acceptex = WSAID_ACCEPTEX;
//	const GUID connectex = WSAID_CONNECTEX;
//	const GUID getacceptexsockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
//
//	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
//	if (s == INVALID_SOCKET)
//		return false;
//	// Get获取相关指针ptr
//	m_pAcceptEx = (LPFN_ACCEPTEX)GetExtensionFunction(s, &acceptex);
//	m_pConnectEx = (LPFN_CONNECTEX)GetExtensionFunction(s, &connectex);
//	m_pGetAcceptExSockaddrs = (LPFN_GETACCEPTEXSOCKADDRS)GetExtensionFunction(s, &getacceptexsockaddrs);
//	closesocket(s);
//	return m_pAcceptEx != NULL && m_pConnectEx != NULL && m_pGetAcceptExSockaddrs != NULL;
//}
//
//bool HlprSocketTcp::tcp_init(unsigned short port, bool bindToLocalhost, int threadCount)
//{
//	bool result = false;
//	if (!InitExtensions())
//		return false;
//	do {
//		if (false == m_IocpSvc.iocp_init(this, 0))
//			break;
//
//		sockaddr_in addr;
//		memset(&addr, 0, sizeof(addr));
//		addr.sin_family = AF_INET;
//		if (bindToLocalhost)
//			addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
//		addr.sin_port = m_port;
//		m_listenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
//		if (m_listenSocket == INVALID_SOCKET)
//			break;
//		if (bind(m_listenSocket, (SOCKADDR*)&addr, sizeof(addr)) != 0)
//			break;
//		if (listen(m_listenSocket, SOMAXCONN) != 0)
//			break;
//		m_IocpSvc.iocp_registersocket(m_listenSocket);
//
//		// 启动accept
//		//if (!startAccept(AF_INET))
//		//	break;
//
//		m_ipv4Available = true;
//		result = true;
//		break;
//	} while (1);
//
//	return result;
//
//}
//bool HlprSocketTcp::tcp_free()
//{
//}
//bool HlprSocketTcp::tcp_close()
//{
//}
//
///*
//	Icop Real Fcuntion
//*/
////bool startAccept(int ipFamily)
////{
////	SOCKET s = WSASocket(ipFamily, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
////	if (s == INVALID_SOCKET)
////	{
////		return false;
////	}
////
////	OV_DATA* pov = newOV_DATA();
////	DWORD dwBytes;
////
////	pov->type = OVT_ACCEPT;
////	pov->packetList.push_back(TCP_PACKET(NULL, 2 * (sizeof(sockaddr_in6) + 16)));
////
////	if (ipFamily == AF_INET)
////	{
////		m_acceptSocket = s;
////	}
////	else
////	{
////		m_acceptSocket_IPv6 = s;
////	}
////
////	if (!m_pAcceptEx((ipFamily == AF_INET) ? m_listenSocket : m_listenSocket_IPv6,
////		s,
////		pov->packetList[0].buffer.buf,
////		0,
////		sizeof(sockaddr_in6) + 16,
////		sizeof(sockaddr_in6) + 16,
////		&dwBytes,
////		&pov->ol))
////	{
////		if (WSAGetLastError() != ERROR_IO_PENDING)
////		{
////			closesocket(s);
////			deleteOV_DATA(pov);
////			return false;
////		}
////	}
////
////	// printf("[r3:] m_pAcceptEx Success\n");
////
////	return true;
////}
//bool startConnect(SOCKET socket, sockaddr* pAddr, int addrLen, ULONG64 id)
//{
//}
//bool startTcpSend(PROXY_DATA* pd, bool isInSocket, const char* buf, int len, ULONG64 id)
//{
//}
//bool startTcpReceive(PROXY_DATA* pd, bool isInSocket, ULONG64 id)
//{
//}
//bool startClose(SOCKET socket, ULONG64 id)
//{
//}
//
///*
//	IOCP Server
//*/
//void onAcceptComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
//{
//}
//void onConnectComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
//{
//}
//void onSendComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
//{
//}
//void onReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
//{
//}
//void onClose(SOCKET socket, OV_DATA* pov)
//{
//}
//
//void HlprSocketTcp::execute()
//{
//	OV_DATA* pov;
//
//	{
//		m_csEventList.lock();
//		if (m_eventList.empty())
//		{
//			m_csEventList.unlock();
//			return;
//		}
//		pov = CONTAINING_RECORD(m_eventList.front(), OV_DATA, entryEventList);
//		m_eventList.pop_front();
//		m_csEventList.unlock();
//	}
//
//	if (pov)
//	{
//		switch (pov->type)
//		{
//		case OVT_ACCEPT:
//			onAcceptComplete(pov->socket, pov->dwTransferred, pov, pov->error);
//			break;
//		case OVT_CONNECT:
//			onConnectComplete(pov->socket, pov->dwTransferred, pov, pov->error);
//			break;
//		case OVT_SEND:
//			onSendComplete(pov->socket, pov->dwTransferred, pov, pov->error);
//			break;
//		case OVT_RECEIVE:
//			onReceiveComplete(pov->socket, pov->dwTransferred, pov, pov->error);
//			break;
//		case OVT_CLOSE:
//			onClose(pov->socket, pov);
//			break;
//		}
//
//		deleteOV_DATA(pov);
//	}
//
//	{
//		m_csEventList.lock();
//		if (!m_eventList.empty())
//		{
//			//m_pool.jobAvailable();
//			m_csEventList.unlock();
//		}
//		m_csEventList.unlock();
//	}
//}
//void HlprSocketTcp::onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error)
//{
//	OV_DATA* pov = (OV_DATA*)pOverlapped;
//
//	pov->socket = socket;
//	pov->dwTransferred = dwTransferred;
//	pov->error = error;
//
//	{
//		m_csEventList.lock();
//		m_eventList.push_back(&pov->entryEventList);
//		m_csEventList.unlock();
//	}
//
//	// Event Hnadle
//	//m_pool.jobAvailable();
//}