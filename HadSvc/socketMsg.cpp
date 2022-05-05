/*
* 负责跨进程消息指令 - 代码线性阻塞等待server处理
*/
#include "socketMsg.h"
#include <sysinfo.h>

socketMsg::socketMsg()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);
}
socketMsg::~socketMsg()
{
	this->close();
	WSACleanup();
}

bool socketMsg::sendDlgMsg(const int msgid, char* info, const int lens)
{
	bool hr = false;
	if (!m_socket)
	{
		hr = connect();
		if (!m_socket || false == hr)
			return hr;
	}
	// sendbuf = msgid + structinfo + 1
	const int sendlens = sizeof(int) + lens + 1;
	char* sendbuf = new char[sendlens];
	if (!sendbuf)
		return false;
	RtlSecureZeroMemory(sendbuf, sendlens);
	// msgid
	*((int*)sendbuf) = msgid;
	// structinfo_buffer
	memcpy(sendbuf + sizeof(int), info, lens);
	switch (msgid)
	{
	case MIN_COMMAND::IPS_PROCESSSTART:hr = send(msgid, sendbuf, sendlens); break;
	}
	if (sendbuf)
	{
		delete[] sendbuf;
		sendbuf = nullptr;
	}
	return hr;
}
bool socketMsg::connect()
{
	try
	{
		m_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (!m_socket)
			return false;
		int recvTimeout = 11 * 1000;
		int sendTimeout = 2000;
		setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout, sizeof(int));
		setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout, sizeof(int));
		struct sockaddr_in serveraddr;
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		serveraddr.sin_port = htons(10246);
		if (SOCKET_ERROR == ::connect(m_socket, (sockaddr*)&serveraddr, sizeof(serveraddr)))
			return false;
		return true;
	}
	catch (...)
	{
		return false;
	}
}
bool socketMsg::send(const int msgid)
{
	try
	{
		if (!m_socket)
			return false;

		return ::send(m_socket, (char*)&msgid, sizeof(const int), false);
	}
	catch (...)
	{
		return false;
	}
}
bool socketMsg::send(const int msgid, char* buffer, const int buflen)
{
	try
	{
		if (!m_socket || nullptr == buffer || 0 >= buflen)
			return false;
		switch (msgid)
		{
		case _MINI_COMMAND::IPS_PROCESSSTART: break;
		}
		return ::send(m_socket, buffer, buflen, false);
	}
	catch (...)
	{
		return false;
	}
}
bool socketMsg::sendto()
{
	try
	{
		return true;
	}
	catch (...)
	{
		return false;
	}
}
const int socketMsg::recv()
{// recv无参数函数，server只会返回buffer dword大小数据
	char* recvbuf = nullptr;
	int hrstatus = 2;
	try
	{
		do {
			if (!m_socket)
				break;
			const int rebuflen = sizeof(DWORD);
			recvbuf = new char[rebuflen];
			if (!recvbuf)
				break;
			RtlSecureZeroMemory(recvbuf, rebuflen);
			// 优化：需要设置等待时常，最多10s,默认阻止
			bool hr = ::recv(m_socket, recvbuf, rebuflen, false);
			if (!hr)
				break;
			const int optionss = *(DWORD*)recvbuf;
			if (optionss > 3)
				hrstatus = 2;
			else
				hrstatus = *(DWORD*)recvbuf;
		} while (false);
		if (recvbuf)
			delete[] recvbuf;
		recvbuf = nullptr;
		return hrstatus;
	}
	catch (...)
	{
		if (recvbuf)
			delete[] recvbuf;
		recvbuf = nullptr;
		return hrstatus;
	}
}
bool socketMsg::recvto()
{
	try
	{
		return true;
	}
	catch (...)
	{
		return false;
	}
}
bool socketMsg::close()
{
	try
	{
		if (m_socket)
			closesocket(m_socket);
		m_socket = 0;
		return true;
	}
	catch (...)
	{
		return false;
	}
}