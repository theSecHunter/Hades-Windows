#include "HlprMiniCom.h"
#include <fltuser.h>

bool nf_SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen) {

	HANDLE g_hPort = INVALID_HANDLE_VALUE;
	DWORD Status = FilterConnectCommunicationPort(
		L"\\MiniPort",
		0,
		NULL,
		0,
		NULL,
		&g_hPort);
	if (Status != S_OK)
	{
		return false;
	}

	DWORD bytesReturned = 0;
	DWORD hResult = 0;

	unsigned int total = sizeof(COMMAND_MESSAGE) + buflen + 1;
	auto InputBuffer = VirtualAlloc(NULL, total, MEM_RESERVE, PAGE_READWRITE);

	COMMAND_MESSAGE command_message;
	command_message.Command = MIN_COMMAND::SET_PROCESSNAME;
	command_message.processnamelen = processnamelen;

	memcpy(InputBuffer, &command_message, sizeof(COMMAND_MESSAGE));
	memcpy((void*)((DWORD64)InputBuffer + sizeof(COMMAND_MESSAGE)), rulebuffer, buflen);

	hResult = FilterSendMessage(g_hPort, InputBuffer, total, NULL, NULL, &bytesReturned);
	if (hResult != S_OK)
	{
		return hResult;
	}

	return true;
}