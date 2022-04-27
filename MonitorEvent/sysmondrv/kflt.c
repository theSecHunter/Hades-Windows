/*
* 为了解决Event上下文等待唤醒非同步，可以用FltSendMessage方案上下文同步
*/
#include "public.h"
#include <fltKernel.h>

#include "kflt.h"

extern PFLT_FILTER g_FltServerPortEvnet;
static PFLT_PORT   g_FltServerPortEvnetPort = NULL;
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
	g_FltClientPortEvnetPort = ClientPort;
	return STATUS_SUCCESS;
}
VOID
CommunicateDisconnect(
	IN PVOID ConnectionCookie
) {
	UNREFERENCED_PARAMETER(ConnectionCookie);
	PAGED_CODE();
	if (g_FltServerPortEvnet)
	{
		FltCloseClientPort(g_FltServerPortEvnet, &g_FltClientPortEvnetPort);
		g_FltClientPortEvnetPort = NULL;
	}
}

NTSTATUS Fsflt_initPort()
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd;
	UNICODE_STRING EventPortName;

	if (g_FltServerPortEvnet == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(status)) 
	{
		RtlSetDaclSecurityDescriptor(sd, TRUE, NULL, FALSE);
		RtlInitUnicodeString(&EventPortName, L"\\HadesEventFltPort");
		InitializeObjectAttributes(
			&oa,
			&EventPortName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			sd
		);
		status = FltCreateCommunicationPort(
			g_FltServerPortEvnet,
			&g_FltServerPortEvnetPort,
			&oa,
			NULL,
			CommunicateConnect,
			CommunicateDisconnect,
			NULL,
			1
		);

		FltFreeSecurityDescriptor(sd);
	}
	return status;
}

// Synchronize
NTSTATUS Fsflt_SendMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength)
{
	if (g_FltServerPortEvnet && g_FltClientPortEvnetPort)
		return FltSendMessage(g_FltServerPortEvnet, &g_FltClientPortEvnetPort, SenderBuffer, SenderBufferLength, ReplyBuffer, ReplyLength, NULL);
	return STATUS_UNSUCCESSFUL;
}
// Asynchronous
NTSTATUS Fsflt_SendToMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength)
{
}

void Fsflt_ClosePort()
{
	if (g_FltServerPortEvnet) {
		FltCloseCommunicationPort(g_FltServerPortEvnet);
		g_FltServerPortEvnet = NULL;
		// sleep 1s
	}
}
void Fsflt_freePort()
{
	Fsflt_ClosePort();
}