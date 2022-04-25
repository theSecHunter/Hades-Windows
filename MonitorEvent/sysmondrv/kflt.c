/*
* 为了解决Event上下文等待唤醒非同步，可以用FltSendMessage+FilterReplyMessage方案上线文同步
*/
#include "public.h"
#include <fltKernel.h>

#include "minifilter.h"

extern PFLT_FILTER g_FltServerPortEvnet;
static PFLT_PORT   g_FltServerPortEvnetPort = NULL;

static PFLT_FILTER g_FltClientPortEvnet = NULL;
static PFLT_PORT   g_FltClientPortEvnetPort = NULL;

NTSTATUS
CommunicateConnect(
	IN PFLT_PORT ClientPort,
	IN PVOID ServerPortCookie,
	IN PVOID ConnectionContext,
	IN ULONG SizeOfContext,
	OUT PVOID* ConnectionPortCookie
) {
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);
	PAGED_CODE();
	g_FltClientPortEvnet = ClientPort;
	return STATUS_SUCCESS;
}
VOID
CommunicateDisconnect(
	IN PVOID ConnectionCookie
) {
	UNREFERENCED_PARAMETER(ConnectionCookie);
	PAGED_CODE();
	FltCloseClientPort(g_FltClientPortEvnet, &g_FltClientPortEvnetPort);
	g_FltClientPortEvnetPort = NULL;
}

NTSTATUS kflt_initPort()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd;
	UNICODE_STRING EventPort;
	RtlInitUnicodeString(&EventPort, L"Global\\HadesEventFltPort");
	FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	InitializeObjectAttributes(&oa, &EventPort, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
	if (g_FltServerPortEvnet == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	DbgBreakPoint();
	status = FltCreateCommunicationPort(g_FltServerPortEvnet, &g_FltServerPortEvnetPort, &oa, NULL, CommunicateConnect, CommunicateDisconnect, NULL, 1);
	FltFreeSecurityDescriptor(sd);
	return status;
}

NTSTATUS kflt_SendMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength)
{
	return FltSendMessage(g_FltClientPortEvnet, g_FltClientPortEvnetPort, &SenderBuffer, SenderBufferLength, &ReplyBuffer, ReplyLength, NULL);
}
NTSTATUS kflt_SendToMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength)
{

}

void kflt_ClosePort()
{
	if (g_FltServerPortEvnet) {
		FltCloseCommunicationPort(g_FltServerPortEvnet);
		g_FltServerPortEvnet = NULL;
		// sleep 1s
	}
}
void kflt_freePort()
{
	kflt_ClosePort();
}

#include "kflt.h"