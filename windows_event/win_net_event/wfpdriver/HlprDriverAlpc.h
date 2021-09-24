#ifndef _HLPRDRIVERALPC_H
#define _HLPRDRIVERALPC_H

/*************************************************************************
	ALPC Struct and Function
*************************************************************************/
typedef struct _PORT_VIEW
{
	ULONG Length;
	HANDLE SectionHandle;
	ULONG SectionOffset;
	SIZE_T ViewSize;
	PVOID ViewBase;
	PVOID ViewRemoteBase;
} PORT_VIEW, * PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
	ULONG Length;
	SIZE_T ViewSize;
	PVOID ViewBase;
} REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

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
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

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
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef NTSTATUS
(NTAPI*
	P_NtAlpcConnectPort)(
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


typedef NTSTATUS
(NTAPI*
	P_NtAlpcSendWaitReceivePort)(
		__in HANDLE PortHandle,
		__in ULONG Flags,
		__in_opt PPORT_MESSAGE SendMessage,
		__in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
		__inout_opt PPORT_MESSAGE ReceiveMessage,
		__inout_opt PULONG BufferLength,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
		__in_opt PLARGE_INTEGER Timeout
		);


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

// Exec struct
typedef struct _UNIVERMSG
{
	ULONG ControlId;		// Command function Id
	ULONG Event;			// Event
}UNIVERMSG, * PUNIVERMSG;

// 	DIRVER_INJECT_DLL
typedef struct _DIRVER_INJECT_DLL
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	PVOID ImageBase;
	ULONG Pids;
	wchar_t MsgData[10];
}DIRVER_INJECT_DLL, * PDIRVER_INJECT_DLL;

// ippackhander strucy
typedef struct _IPPACKHEAD
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	ULONG localaddr;
	long localport;
	ULONG remoteaddr;
	long remoteport;
	unsigned short protocol;
	int pid;
}IPPACKHEAD, * PIPPACKHEAD;

typedef struct _IPHEAD_LIST
{
	IPPACKHEAD ipheadbuf;
	LIST_ENTRY ListEntry;
}IPHEADLIST, * PIPHEADLIST;

// 	DIRVER_Data_Test
typedef struct _DIRVER_MSG_TEST
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	wchar_t MsgData[10];
}DIRVER_MSG_TEST, * PDIRVER_MSG_TEST;

// Api
NTSTATUS InitAlpcAddrs();
NTSTATUS AlpcDriverStart();
NTSTATUS AlpcSendflowEstablishedMsg(
	PVOID64 flowEstablishedPakcet, int	lens);
NTSTATUS AlpcSendDataLinkStructMsg(
	PVOID64 datalinkpacket, int	lens);
NTSTATUS TestSendMsg(
	DIRVER_MSG_TEST* Info
);


// gloable
extern LIST_ENTRY	g_IpHeadList;

#endif // !_HLPRDRIVERALPC_H

