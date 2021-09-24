#pragma once
#pragma comment(lib,"alpc.lib")
#pragma comment(lib,"ntdll.lib")

typedef USHORT ADDRESS_FAMILY;

#define FWP_BYTE_ARRAY6_SIZE 6

extern int waitDriverConnectAlpcHandle;

// Exec struct
typedef struct _UNIVERMSG
{
	ULONG ControlId;		// Command function Id
	ULONG Event;			// Event
}UNIVERMSG, *PUNIVERMSG;

// 	DIRVER_INJECT_DLL
typedef struct _DIRVER_INJECT_DLL
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	PVOID ImageBase;
	ULONG Pids;
	wchar_t MsgData[10];
}DIRVER_INJECT_DLL, *PDIRVER_INJECT_DLL;

// 	DIRVER_Data_Test
typedef struct _DIRVER_MSG_TEST
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	wchar_t MsgData[10];
}DIRVER_MSG_TEST, *PDIRVER_MSG_TEST;

typedef struct _IPPACKHADNER
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	ULONG pid;
	ULONG protocol;
	ULONG localaddr;
	ULONG localport;
	ULONG remoteaddr;
	ULONG remoteport;
	ULONG heartbeat;				// 心跳探测 
}IPPACKHANDER, *PIPPACKHANDER;

typedef struct _MONITORCVEINFO
{
	UNIVERMSG univermsg;
	wchar_t cvename[30];	// CVE Name
	int Pid;				// Process Pid
}MONITORCVEINFO, *PMONITORCVEINFO;

// extern vector<NF_CALLOUT_FLOWESTABLISHED_INFO> flowestablished_list;

void AlpcPortStart(wchar_t* PortName);

void list_thread(wchar_t* PortName);

void AlpcSendtoClientMsg(HANDLE sendPort, UNIVERMSG* univermsg, const int msgid);