#pragma once

#include <MSWSock.h>

class IOCPHandler
{
public:
	virtual void onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error) = 0;
};

class HlprIocpService
{
public:
	HlprIocpService();
	~HlprIocpService();

	bool iocp_init(IOCPHandler* pHandler, int numOfIoThreads = 0);
	bool iocp_work();
	bool iocp_free();
	bool iocp_recv();
	bool iocp_send();
	bool iocp_close();

private:

};

