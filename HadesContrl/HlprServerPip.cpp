#include "HlprServerPip.h"
#include <Windows.h>
#include <iostream>

using namespace std;

HANDLE m_PipHandle;

HlprServerPip::HlprServerPip()
{

}

HlprServerPip::~HlprServerPip()
{

}

int HlprServerPip::StartServerPip(
)
{
	m_PipHandle = CreateNamedPipeW(L"\\\\.\\Pipe\\hadesctlport", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 0, 0, 1000, NULL);
	if (m_PipHandle == INVALID_HANDLE_VALUE)
	{
		// Log
		cout << "[+]CreateNamedPipeW Error: %d\r\n" << GetLastError() << endl;
		return -1;
	}

	// Wait UI-Connect 
	BOOL nRet = ConnectNamedPipe(m_PipHandle, NULL);
	if (!nRet)
	{
		// Log
		cout << "[+]ConnectNamedPipe  Client Connect: %d\r\n" << GetLastError() << endl;
		return -1;
	}

	return 0;
}

int HlprServerPip::PipSendMsg(
	wchar_t* buf, 
	const int bufLen
)
{
	if (m_PipHandle)
	{
		DWORD wrtSize = 0;
		BOOL nRet = WriteFile(m_PipHandle, buf, bufLen, &wrtSize, NULL);
		if (!nRet)
			return -1;
		else
			return 0;
	}

	return 0;
}

void HlprServerPip::PipClose()
{
	if (m_PipHandle)
		CloseHandle(m_PipHandle);
	m_PipHandle = NULL;
}