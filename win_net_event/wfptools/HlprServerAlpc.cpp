#include "ntbasic.h"
#include "HlprServerAlpc.h"
#include <queue>
#include <map>
#include <mutex>
#include "nfdriver.h"

using namespace std;
int waitDriverConnectAlpcHandle = 0;

// 负责保存进程pid, 防止注入多次
queue<NF_CALLOUT_FLOWESTABLISHED_INFO> flowestablished_list;
static mutex g_mutx;
// int(port): udp + 1000000 ||  tcp + 2000000
map<int, NF_CALLOUT_FLOWESTABLISHED_INFO> map_processinfo;
static mutex g_maptx;


// HlprServerPip pipsrvobj;

/*************************************************************************
	lnk lib extern
*************************************************************************/
extern "C"
{
	enum _NF_DATA_CODE
	{
		NF_DATALINK_PACKET = 1,
		NF_FLOWCTX_PACKET
	}NF_DATA_CODE;

	typedef struct _PORT_VIEW
	{
		ULONG Length;
		HANDLE SectionHandle;
		ULONG SectionOffset;
		SIZE_T ViewSize;
		PVOID ViewBase;
		PVOID ViewRemoteBase;
	} PORT_VIEW, *PPORT_VIEW;

	typedef struct _REMOTE_PORT_VIEW
	{
		ULONG Length;
		SIZE_T ViewSize;
		PVOID ViewBase;
	} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

	typedef struct _PORT_MESSAGE
	{
		union
		{
			struct
			{
				CSHORT DataLength;
				CSHORT TotalLength;
			} s1;
			ULONG Length;
		} u1;
		union
		{
			struct
			{
				CSHORT Type;
				CSHORT DataInfoOffset;
			} s2;
			ULONG ZeroInit;
		} u2;
		union
		{
			CLIENT_ID ClientId;
			QUAD DoNotUseThisField;
		};
		ULONG MessageId;
		union
		{
			SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
			ULONG CallbackId; // only valid for LPC_REQUEST messages
		};
	} PORT_MESSAGE, *PPORT_MESSAGE;

	typedef struct _ALPC_MESSAGE_ATTRIBUTES
	{
		ULONG AllocatedAttributes;
		ULONG ValidAttributes;
	} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

	// symbols
	typedef struct _ALPC_PORT_ATTRIBUTES
	{
		ULONG Flags;
		SECURITY_QUALITY_OF_SERVICE SecurityQos;
		SIZE_T MaxMessageLength;
		SIZE_T MemoryBandwidth;
		SIZE_T MaxPoolUsage;
		SIZE_T MaxSectionSize;
		SIZE_T MaxViewSize;
		SIZE_T MaxTotalSectionSize;
		ULONG DupObjectTypes;
	#ifdef _M_X64
		ULONG Reserved;
	#endif
	} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCreatePort(
			__out PHANDLE PortHandle,
			__in POBJECT_ATTRIBUTES ObjectAttributes,
			__in_opt PALPC_PORT_ATTRIBUTES PortAttributes
		);

	NTSYSAPI
		VOID
		NTAPI
		RtlInitUnicodeString(
			_Out_ PUNICODE_STRING DestinationString,
			_In_opt_z_ __drv_aliasesMem PCWSTR SourceString
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwCreateSection(
			_Out_ PHANDLE SectionHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PLARGE_INTEGER MaximumSize,
			_In_ ULONG SectionPageProtection,
			_In_ ULONG AllocationAttributes,
			_In_opt_ HANDLE FileHandle
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcConnectPort(
			__out PHANDLE PortHandle,
			__in PUNICODE_STRING PortName,
			__in POBJECT_ATTRIBUTES ObjectAttributes,
			__in_opt PALPC_PORT_ATTRIBUTES PortAttributes,
			__in ULONG Flags,
			__in_opt PSID RequiredServerSid,
			__inout PPORT_MESSAGE ConnectionMessage,
			__inout_opt PULONG BufferLength,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
			__in_opt PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcAcceptConnectPort(
			__out PHANDLE PortHandle,
			__in HANDLE ConnectionPortHandle,
			__in ULONG Flags,
			__in POBJECT_ATTRIBUTES ObjectAttributes,
			__in PALPC_PORT_ATTRIBUTES PortAttributes,
			__in_opt PVOID PortContext,
			__in PPORT_MESSAGE ConnectionRequest,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
			__in BOOLEAN AcceptConnection
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcSendWaitReceivePort(
			__in HANDLE PortHandle,
			__in ULONG Flags,
			__in_opt PPORT_MESSAGE SendMessage,
			__in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
			__inout_opt PPORT_MESSAGE ReceiveMessage,
			__inout_opt PULONG BufferLength,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
			__in_opt PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
	NTSTATUS
		NTAPI
		NtReplyWaitReceivePort(
			__in HANDLE PortHandle,
			__out_opt PVOID *PortContext,
			__in_opt PPORT_MESSAGE ReplyMessage,
			__out PPORT_MESSAGE ReceiveMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDisconnectPort(
			__in HANDLE PortHandle,
			__in ULONG Flags
		);
}

/*************************************************************************
	function handle Code
*************************************************************************/
enum CommandofCodeID
{
	ALPC_DRIVER_DLL_INJECTENABLE = 1,
	ALPC_DRIVER_DLL_INJECTDISABLE,

	ALPC_DRIVER_CONNECTSERVER = 10,
	ALPC_DRIVER_CONNECTSERVER_RECV,
	ALPC_DLL_CONNECTSERVER,
	ALPC_DLL_CONNECTSERVER_RECV,
	ALPC_UNCONNECTSERVER,

	ALPC_DLL_MONITOR_CVE = 30,
	ALPC_DLL_INJECT_SUCCESS,
	ALPC_DLL_INJECT_FAILUER,


	ALPC_DRIVER_MSG_TEST = 88,
	ALPC_IPPACK_HEADER = 89
};

// 事件句柄
HANDLE					Injecteventhandle;		// 驱动注入请求
HANDLE					Monitoreventhandle;		// DLL监控处理请求

LPVOID CreateMsgMem(
	PPORT_MESSAGE PortMessage,
	SIZE_T MessageSize,
	LPVOID Message
)
{
	LPVOID lpMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MessageSize + sizeof(PORT_MESSAGE));
	memmove(lpMem, PortMessage, sizeof(PORT_MESSAGE));
	memmove((BYTE*)lpMem + sizeof(PORT_MESSAGE), Message, MessageSize);
	return(lpMem);
}

/*
@private:
	负责处理客户端请求 - 双向消息处理
*/
void DispatchMsgHandle(
	const LPVOID lpMem,
	HANDLE* SendtoPort,
	const int msgid
)
{
	OutputDebugString(L"Entry CallBack Buffer");
	NF_CALLOUT_FLOWESTABLISHED_INFO flowestablished_info = { 0, };
	NF_CALLOUT_MAC_INFO datalink_info = { 0, };

	// Analysis universMsg
	NF_DATA* Msg = (NF_DATA*)((BYTE*)lpMem + sizeof(PORT_MESSAGE));

	if (!Msg && !SendtoPort)
		return;

	// Get DLL or Driver Msg 
	switch (Msg->code)
	{
	case NF_FLOWCTX_PACKET:
	{
		if (Msg->buffer && Msg->bufferSize)
		{
			memcpy(&flowestablished_info, Msg->buffer, Msg->bufferSize);
			g_mutx.lock();
			flowestablished_list.push(flowestablished_info);
			g_mutx.unlock();
			OutputDebugString(L"flowestablished_list push OK");
		}
	}
	break;
	case NF_DATALINK_PACKET:
	{
		if (Msg->buffer && Msg->bufferSize)
		{
			memcpy(&datalink_info, Msg->buffer, Msg->bufferSize);
			OutputDebugString(L"Mac Buffer");
		}
	}
	break;
	default:
		break;
	}
}

/*
@public:
	负责创建ALPC服务
	负责DispatchMsgHandle分发客户端请求
*/
void AlpcPortStart(
	wchar_t* PortName
)
{
	ALPC_PORT_ATTRIBUTES    serverPortAttr;
	ALPC_PORT_ATTRIBUTES    clientPortAttr;
	OBJECT_ATTRIBUTES       objPort;
	UNICODE_STRING          usPortName;
	PORT_MESSAGE            pmRequest;
	PORT_MESSAGE            pmReceive;
	NTSTATUS                ntRet;
	BOOLEAN                 bBreak;
	HANDLE                  hConnectedPort;
	HANDLE                  hPort;
	SIZE_T                  nLen;
	void*                   lpMem;
	BYTE                    bTemp;

	OutputDebugString(L"Entry Alpc Thread Callback");

	RtlInitUnicodeString(&usPortName, PortName);
	InitializeObjectAttributes(&objPort, &usPortName, 0, 0, 0);
	RtlSecureZeroMemory(&serverPortAttr, sizeof(serverPortAttr)); 
	serverPortAttr.MaxMessageLength = 0x500;
	ntRet = NtAlpcCreatePort(&hPort, &objPort, &serverPortAttr);
	if (!ntRet)
	{
		nLen = 0x500;
		ntRet = NtAlpcSendWaitReceivePort(hPort, 0, NULL, NULL, &pmReceive, (PULONG)&nLen, NULL, NULL);
		// Analysis universMsg
		UNIVERMSG* Msg = (UNIVERMSG*)((BYTE*)&pmReceive + sizeof(PORT_MESSAGE));
		if (!ntRet)
		{
			switch (Msg->ControlId)
			{
			case ALPC_DRIVER_CONNECTSERVER:
			{
				OutputDebugString(L"Driver connect alpc success\r\n");
				// 发送上线成功消息/发送事件句柄
				RtlSecureZeroMemory(&pmRequest, sizeof(pmRequest));
				pmRequest.MessageId = pmReceive.MessageId;
				UNIVERMSG universmg = { 0, };
				universmg.ControlId = ALPC_DRIVER_CONNECTSERVER_RECV;
				pmRequest.u1.s1.DataLength = sizeof(UNIVERMSG);
				pmRequest.u1.s1.TotalLength = pmRequest.u1.s1.DataLength + sizeof(PORT_MESSAGE);
				lpMem = CreateMsgMem(&pmRequest, sizeof(UNIVERMSG), &universmg);
			}
			break;
			default:
				break;
			}
			ntRet = NtAlpcAcceptConnectPort(&hConnectedPort,
				hPort,
				0,
				NULL,
				&serverPortAttr,
				NULL,
				(PPORT_MESSAGE)lpMem,
				NULL,
				TRUE);
			HeapFree(GetProcessHeap(), 0, lpMem);
			lpMem = NULL;
			if (ntRet != 0)
				return;
			
			waitDriverConnectAlpcHandle = 100;
			OutputDebugString(L"waitDriverConnectAlpcHandle = 100");

			bBreak = TRUE;
			while (bBreak)
			{
				//
				// 单线程：循环接收客户端消息
				// 多线程：区分客户端/资源共享等操作
				//
				NtAlpcSendWaitReceivePort(hPort, 0, NULL, NULL, (PPORT_MESSAGE)&pmReceive, (PULONG)&nLen, NULL, NULL);
				// Empty Msg
				if (0 >= pmReceive.u1.s1.DataLength)
					break;
				// Dispatch Msg
				DispatchMsgHandle(&pmReceive, &hConnectedPort, pmReceive.MessageId);
			}

			OutputDebugString(L"Alpc Thread End");
		}
	}
}

/*
@public:
	负责向客户端发送
*/
void AlpcSendtoClientMsg(
	HANDLE sendPort, 
	UNIVERMSG* univermsg, 
	const int msgid)
{
	PORT_MESSAGE    pmSend;
	ULONG nRet;
	RtlSecureZeroMemory(&pmSend, sizeof(pmSend));
	pmSend.MessageId = msgid;
	pmSend.u1.s1.DataLength = sizeof(UNIVERMSG);
	pmSend.u1.s1.TotalLength = pmSend.u1.s1.DataLength + sizeof(PORT_MESSAGE);

	int nlen = sizeof(UNIVERMSG) + sizeof(PORT_MESSAGE) + 1;
	PVOID lpMem; 
	lpMem = malloc(nlen);
	if (!lpMem)
		return;
	memcpy(lpMem, &pmSend, sizeof(PORT_MESSAGE));
	memcpy((void*)((BYTE*)lpMem + sizeof(PORT_MESSAGE)), univermsg, sizeof(UNIVERMSG));
	nRet = NtAlpcSendWaitReceivePort(sendPort, 0, (PPORT_MESSAGE)lpMem, NULL, NULL, NULL, NULL, NULL);
	free(lpMem);
	lpMem = NULL;
}


void list_thread(
	wchar_t* PortName)
{
	OutputDebugString(L"Entry Map Thread ~");
	DWORD localport = 0;
	for (;;)
	{
		while (!flowestablished_list.empty()) {
			localport = 0;
			auto iter = flowestablished_list.front();
			localport = iter.toLocalPort;
			if (iter.protocol == IPPROTO_TCP)
				localport += 2000000;
			else if(iter.protocol == IPPROTO_UDP)
				localport += 1000000;

			g_maptx.lock();
			map_processinfo[localport] = iter;
			g_maptx.unlock();

			OutputDebugString(L"Insert Map Success~");

			g_mutx.lock();
			flowestablished_list.pop();
			g_mutx.unlock();
		}

		Sleep(2000);
	}

}