#include "HlprMiniCom.h"
#include <fltuser.h>
#include <sysinfo.h>

static HANDLE g_hPort = nullptr;
static BOOL   g_InitPortStatus = FALSE;

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
typedef struct _REPLY_MESSAGE
{
	DWORD Option;
}REPLY_MESSAGE, * PREPLY_MESSAGE;

static DWORD WINAPI ThreadMiniPortConnectNotify(LPVOID pData)
{
	(reinterpret_cast<HlprMiniPortIpc*>(pData))->StartMiniPortWaitConnectWork();
	return 0;
}
static DWORD WINAPI ThreadMiniPortGetMsgNotify(LPVOID pData)
{
	(reinterpret_cast<HlprMiniPortIpc*>(pData))->GetMsgNotifyWork();
	return 0;
}

HlprMiniPortIpc::HlprMiniPortIpc()
{
	DWORD threadid = 0;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMiniPortConnectNotify, NULL, 0, &threadid);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMiniPortGetMsgNotify, NULL, 0, &threadid);
}
HlprMiniPortIpc::~HlprMiniPortIpc()
{
}

bool HlprMiniPortIpc::SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen) {
	if (FALSE == g_InitPortStatus)
		return false;
	
	DWORD bytesReturned = 0;
	DWORD hResult = 0;
	unsigned int total = sizeof(COMMAND_MESSAGE) + buflen + 1;
	auto InputBuffer = VirtualAlloc(NULL, total, MEM_RESERVE, PAGE_READWRITE);

	COMMAND_MESSAGE command_message;
	//command_message.Command = MIN_COMMAND::SET_PROCESSNAME;
	memcpy(InputBuffer, &command_message, sizeof(COMMAND_MESSAGE));
	memcpy((void*)((DWORD64)InputBuffer + sizeof(COMMAND_MESSAGE)), rulebuffer, buflen);

	if (g_hPort)
	{
		hResult = FilterSendMessage(g_hPort, InputBuffer, total, NULL, NULL, &bytesReturned);
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
		Status = FilterConnectCommunicationPort(
			L"\\HadesEventFltPort",
			0,
			NULL,
			0,
			NULL,
			&g_hPort);
		if (Status != S_OK)
			Sleep(2000);
		else
		{
			g_InitPortStatus = true;
			OutputDebugString(L"Connect sysmondriver miniPort Success");
			break;
		}
	} while (TRUE);
}
void HlprMiniPortIpc::GetMsgNotifyWork()
{
	REPLY_MESSAGE replyMessage;
    PCOMMAND_MESSAGE message;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr;
	ULONG_PTR key;

	// Waiting Connect Driver MiniPort_Server - Modify EventWaiting
	do {
		if (g_InitPortStatus && (nullptr != g_hPort) )
			break;
		else
			Sleep(2000);
	} while (1);

	// Check Port Status
	result = GetQueuedCompletionStatus(g_hPort, &outSize, &key, &pOvlp, INFINITE);
	if (!result) {
		hr = HRESULT_FROM_WIN32(GetLastError());
		return;
	}

#pragma warning(push)
#pragma warning(disable:4127)
	while (TRUE) {
#pragma warning(pop)
		hr = FilterGetMessage(
			g_hPort,
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
			OutputDebugString(processinfo->commandLine);
			// 允许
			replyMessage.Option = 1;
		}
		break;
		}

		// 回复FltSendMessage
		hr = FilterReplyMessage(
			g_hPort,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage)
		);
    }
}
void HlprMiniPortIpc::MiniPortActiveCheck()
{
}