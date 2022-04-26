#include "HlprMiniCom.h"
#include <fltuser.h>
#include <sysinfo.h>

typedef enum _MINI_COMMAND {
	SET_PROCESSNAME = 0,
	IPS_PROCESSSTART,
	IPS_REGISTERTAB,
	IPS_IMAGEDLL
}MIN_COMMAND;
typedef struct _COMAND_MESSAGE
{
	FILTER_MESSAGE_HEADER MsgHeader;
	OVERLAPPED Overlapped;
	BYTE MessageBuffer[MESSAGE_BUFFER_SIZE];
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;
typedef struct _COMMAND_REQUEST
{
	MIN_COMMAND Command;
	char data[1];
} COMMAND_REQUEST, * PCOMMAND_REQUEST;

HlprMiniPortIpc::HlprMiniPortIpc()
{
}
HlprMiniPortIpc::~HlprMiniPortIpc()
{
}

bool HlprMiniPortIpc::SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen) {
	if (FALSE == m_InitPortStatus)
		return false;
	
	DWORD bytesReturned = 0;
	DWORD hResult = 0;
	unsigned int total = sizeof(COMMAND_MESSAGE) + buflen + 1;
	auto InputBuffer = VirtualAlloc(NULL, total, MEM_RESERVE, PAGE_READWRITE);

	COMMAND_MESSAGE command_message;
	//command_message.Command = MIN_COMMAND::SET_PROCESSNAME;
	memcpy(InputBuffer, &command_message, sizeof(COMMAND_MESSAGE));
	memcpy((void*)((DWORD64)InputBuffer + sizeof(COMMAND_MESSAGE)), rulebuffer, buflen);

	if (m_hPort)
	{
		hResult = FilterSendMessage(m_hPort, InputBuffer, total, NULL, NULL, &bytesReturned);
		if (hResult != S_OK)
		{
			return hResult;
		}
	}

	return true;
}
void HlprMiniPortIpc::StartMiniPortWaitConnectWork()
{
	DWORD Status = 0;
	do {
		m_hPort = INVALID_HANDLE_VALUE;
		DWORD Status = FilterConnectCommunicationPort(
			L"\\HadesEventFltPort",
			0,
			NULL,
			0,
			NULL,
			&m_hPort);
		if (Status != S_OK)
			Sleep(2000);
		else
		{
			m_InitPortStatus = true;
			OutputDebugString(L"Connect sysmondriver miniPort Success");
			break;
		}
	} while (TRUE);
}
void HlprMiniPortIpc::MiniPortActiveCheck()
{

}

void HlprMiniPortIpc::GetMsgNotifyWork()
{
    PCOMMAND_MESSAGE message;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr;
	ULONG_PTR key;

	// Waiting Connect Driver MiniPort_Server
	do {
		if (m_InitPortStatus && m_hPort)
			break;
		else
			Sleep(2000);
	} while (1);

	// Check Port Status
	result = GetQueuedCompletionStatus(m_hPort, &outSize, &key, &pOvlp, INFINITE);
	if (!result) {
		hr = HRESULT_FROM_WIN32(GetLastError());
		return;
	}

#pragma warning(push)
#pragma warning(disable:4127)
	while (TRUE) {
#pragma warning(pop)
		hr = FilterGetMessage(
			m_hPort,
			(PFILTER_MESSAGE_HEADER)&message->MsgHeader,
			MESSAGE_BUFFER_SIZE,
			&message->Overlapped
		);

		if (result == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE))
		{
			break;
		}
		else if (result == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
		{
			break;
		}
		else if (result != HRESULT_FROM_WIN32(S_OK))
		{
			break;
		}

		PCOMMAND_REQUEST pRequest = (PCOMMAND_REQUEST)&message->MessageBuffer;
		switch (pRequest->Command)
		{
		case MIN_COMMAND::IPS_PROCESSSTART:
		{
			PROCESSINFO* processinfo = (PROCESSINFO*)pRequest->data;
			// 弹窗提示用户拦截进程
			//::SendMessage();
			
		}
		break;
		}

		// 回复FltSendMessage
		//hr = FilterReplyMessage(
		//	m_hPort,
		//	(PFILTER_REPLY_HEADER)&replyMessage,
		//	sizeof(replyMessage)
		//);
    }
}