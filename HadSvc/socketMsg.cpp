/*
* 负责跨进程消息指令 - 代码线性阻塞等待server处理
*/
#include "socketMsg.h"
#include <sysinfo.h>

socketMsg::socketMsg()
{
}
socketMsg::~socketMsg()
{
	this->close();
}

bool socketMsg::sendDlgMsg(const int msgid)
{
	bool hr = false;
	// if not connect iocpserver, connect to iocpserver
	if (nullptr == m_socket)
	{
		hr = connect();
		if (nullptr == m_socket && false == hr)
			return false;
	}

	// send command 
	switch (msgid)
	{
	case MIN_COMMAND::IPS_PROCESSSTART:
	{
		if (false == send(msgid))
			return false;
	}
	break;
	default:return false;
	}

	return true;
}
bool socketMsg::connect()
{
	try
	{
		m_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (!m_socket)
			return false;
		int recvTimeout = 10 * 1000;
		int sendTimeout = 2000;
		setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout, sizeof(int));
		setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout, sizeof(int));
		struct sockaddr_in serveraddr;
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		serveraddr.sin_port = htons(10241);
		if (::connect(m_socket, (sockaddr*)&serveraddr, sizeof(serveraddr)))
			return true;
		return false;
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
		if (nullptr == m_socket)
			return false;
		return ::send(m_socket, NULL, 0, false);
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
		if (nullptr == m_socket || nullptr == buffer || 0 >= buflen)
			return false;
		switch (msgid)
		{
		case _MINI_COMMAND::IPS_PROCESSSTART:
		{
			// buffer
			return ::send(m_socket, buffer, buflen, false);
		}
		break;
		default:
			break;
		}
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
	int hrstatus = 0;
	try
	{
		do {
			if (nullptr == m_socket)
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
			if (*(DWORD*)recvbuf == 1)			// 阻止
				hrstatus = 1;
			else if (*(DWORD*)recvbuf == 2)		// 放行
				hrstatus = 2;
			else if (*(DWORD*)recvbuf == 3)		// 结束进程
				hrstatus = 3;
			else
				hrstatus = 0;					// 默认放行
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
		m_socket = nullptr;
		return true;
	}
	catch (...)
	{
		return false;
	}
}