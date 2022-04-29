#include <Windows.h>
#include "HlprIocpService.h"
#include <process.h>
#include <vector>

std::vector<HANDLE> IoThreadHandleList;

HlprIocpService::HlprIocpService() : m_hIOCP(INVALID_HANDLE_VALUE), m_pHandler(NULL)
{
	m_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}
HlprIocpService::~HlprIocpService()
{
	if (m_stopEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_stopEvent);
		m_stopEvent = INVALID_HANDLE_VALUE;
	}
}

bool HlprIocpService::iocp_work()
{
	DWORD dwTransferred;
	ULONG_PTR cKey;
	OVERLAPPED* pOverlapped;

	for (;;)
	{
		if (GetQueuedCompletionStatus(m_hIOCP, &dwTransferred, &cKey, &pOverlapped, 500))
		{
			m_pHandler->onComplete((SOCKET)cKey, dwTransferred, pOverlapped, 0);
		}
		else
		{
			DWORD err = GetLastError();
			if (err != WAIT_TIMEOUT)
			{
				m_pHandler->onComplete((SOCKET)cKey, dwTransferred, pOverlapped, err);
			}
		}

		if (WaitForSingleObject(m_stopEvent, 0) == WAIT_OBJECT_0)
			break;
	}
	return true;
}
static unsigned int WINAPI _workerThread(void* pThis)
{
	((HlprIocpService*)pThis)->iocp_work();
	return 0;
}
// ´´½¨IoCompletionPort
bool HlprIocpService::iocp_init(IOCPHandler* pHandler, int numOfIoThreads)
{
	m_pHandler = pHandler;
	if (m_hIOCP != INVALID_HANDLE_VALUE)
		return false;
	// Create
	m_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
	if (INVALID_HANDLE_VALUE == m_hIOCP)
		return false;
	ResetEvent(m_stopEvent);
	// Start socket_work
	if (numOfIoThreads == 0) numOfIoThreads = 1;
	for (int i = 0; i < numOfIoThreads; i++)
	{
		HANDLE hThread = (HANDLE)_beginthreadex(0, 0, _workerThread, (LPVOID)this, 0, NULL);
		if (NULL != hThread)
			IoThreadHandleList.push_back(hThread);
	}
	if (IoThreadHandleList.size() == 0)
	{
		CloseHandle(m_hIOCP);
		return false;
	}

	return true;
}
bool HlprIocpService::iocp_free()
{
	SetEvent(m_stopEvent);
	unsigned workingThreadCount = IoThreadHandleList.size();
	std::vector<HANDLE>::iterator iter;
	while (workingThreadCount > 0)
	{
		workingThreadCount = 0;
		for (iter = IoThreadHandleList.begin(); iter != IoThreadHandleList.end(); iter++)
		{
			DWORD exitCode;
			if (GetExitCodeThread(*iter, &exitCode) && exitCode == STILL_ACTIVE)
				workingThreadCount++;
		}
	}
	for (iter = IoThreadHandleList.begin(); iter != IoThreadHandleList.end(); iter++)
	{
		CloseHandle(*iter);
	}
	IoThreadHandleList.clear();

	if (m_hIOCP != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hIOCP);
		m_hIOCP = INVALID_HANDLE_VALUE;
	}
	return true;
}
bool HlprIocpService::postCompletion(SOCKET s, DWORD dwTransferred, LPOVERLAPPED pol)
{
	return PostQueuedCompletionStatus(m_hIOCP, dwTransferred, (ULONG_PTR)s, pol) ? true : false;
}
bool HlprIocpService::iocp_registersocket(SOCKET s)
{
	if (!CreateIoCompletionPort((HANDLE)s, m_hIOCP, (ULONG_PTR)s, 1))
		return false;
	return true;
}
