#include "HlprIocpService.h"

#include "MessageBoxDlg.h"

HlprIocpService::HlprIocpService()
{

}

HlprIocpService::~HlprIocpService()
{

}

bool HlprIocpService::iocp_recv()
{
}

bool HlprIocpService::iocp_send()
{

}

bool HlprIocpService::iocp_close()
{
}

bool HlprIocpService::iocp_work()
{
	// waiting client connect


	// dispatch socket handle

}

// ´´½¨IoCompletionPort
bool HlprIocpService::iocp_init(IOCPHandler* pHandler, int numOfIoThreads = 0)
{
	// Create
	HANDLE m_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
	if (INVALID_HANDLE_VALUE == m_hIOCP)
		return false;
	
	// listed


	// bind

	// Start socket_work
}

bool HlprIocpService::iocp_free()
{
}
