#pragma once

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

	bool iocp_init(IOCPHandler* pHandler, int numOfIoThreads);
	bool iocp_free();
	bool iocp_registersocket(SOCKET s);
	bool postCompletion(SOCKET s, DWORD dwTransferred, LPOVERLAPPED pol);
	bool iocp_work();

private:
	HANDLE m_hIOCP;
	HANDLE m_stopEvent;
	IOCPHandler* m_pHandler;
};

