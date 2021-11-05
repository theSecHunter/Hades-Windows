#ifndef _SYSNETWORK_H
#define _SYSNETWORK_H

typedef struct _MIB_UDPROW_OWNER_PID
{
	DWORD           dwLocalAddr;
	DWORD           dwLocalPort;
	DWORD           dwOwningPid;
} MIB_UDPROW_OWNER_PID, * PMIB_UDPROW_OWNER_PID;

typedef struct _MIB_TCPROW_OWNER_PID
{
	DWORD       dwState;
	DWORD       dwLocalAddr;
	DWORD       dwLocalPort;
	DWORD       dwRemoteAddr;
	DWORD       dwRemotePort;
	DWORD       dwOwningPid;
} MIB_TCPROW_OWNER_PID, * PMIB_TCPROW_OWNER_PID;

// Win7 or Xp?
//typedef struct _NSI_PARAM
//{
//	ULONG_PTR UnknownParam1;
//	SIZE_T UnknownParam2;
//	PVOID UnknownParam3;
//	SIZE_T UnknownParam4;
//	ULONG UnknownParam5;
//	ULONG UnknownParam6;
//	PVOID UnknownParam7;
//	SIZE_T UnknownParam8;
//	PVOID UnknownParam9;
//	SIZE_T UnknownParam10;
//	PVOID UnknownParam11;
//	SIZE_T UnknownParam12;
//	PVOID UnknownParam13;
//	SIZE_T UnknownParam14;
//	SIZE_T ConnCount;
//}NSI_PARAM, * PNSI_PARAM;

// Windows 10
typedef struct _NSI_PARAM
{
	ULONG_PTR UnknownParam1;
	ULONG_PTR UnknownParam2;
	ULONG_PTR UnknownParam3;
	ULONG_PTR UnknownParam4;
	ULONG_PTR UnknownParam5;
	ULONG_PTR UnknownParam6;
	ULONG_PTR UnknownParam7;
	ULONG_PTR UnknownParam8;
	ULONG_PTR UnknownParam9;
	ULONG_PTR UnknownParam10;
	ULONG_PTR UnknownParam11;
	ULONG_PTR UnknownParam12;
	ULONG_PTR UnknownParam13;
	ULONG_PTR ConnCount;
}NSI_PARAM, * PNSI_PARAM;

typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
{
	char bytesfill0[2];
	USHORT Port;
	ULONG dwIP;
	char bytesfill[20];
}INTERNAL_TCP_TABLE_SUBENTRY, * PINTERNAL_TCP_TABLE_SUBENTRY;

typedef struct _INTERNAL_TCP_TABLE_ENTRY
{
	INTERNAL_TCP_TABLE_SUBENTRY localEntry;
	INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;
}INTERNAL_TCP_TABLE_ENTRY, * PINTERNAL_TCP_TABLE_ENTRY;

typedef struct _NSI_STATUS_ENTRY
{
	ULONG  dwState;
	char bytesfill[8];
}NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;

typedef struct _NSI_PROCESSID_INFO
{
	ULONG dwUdpProId;
	ULONG UnknownParam2;
	ULONG UnknownParam3;
	ULONG dwTcpProId;
	ULONG UnknownParam5;
	ULONG UnknownParam6;
	ULONG UnknownParam7;
	ULONG UnknownParam8;
}NSI_PROCESSID_INFO, * PNSI_PROCESSID_INFO;

typedef struct _INTERNAL_UDP_TABLE_ENTRY
{
	char bytesfill0[2];
	USHORT Port;
	ULONG dwIP;
	char bytesfill[20];
}INTERNAL_UDP_TABLE_ENTRY, * PINTERNAL_UDP_TABLE_ENTRY;

typedef struct _SYSTPCINFO
{
	NSI_STATUS_ENTRY			socketStatus;
	NSI_PROCESSID_INFO			processinfo;
	INTERNAL_TCP_TABLE_ENTRY	TpcTable;
}SYSTPCINFO;

typedef struct _SYSUDPINFO
{
	NSI_PROCESSID_INFO			processinfo;
	INTERNAL_UDP_TABLE_ENTRY	UdpTable;
}SYSUDPINFO;

typedef struct _SYSNETWORKINFONODE
{
	DWORD			tcpcout;
	DWORD			udpcout;
	SYSTPCINFO		systcpinfo[65535];
	SYSUDPINFO		sysudpinfo[65535];
}SYSNETWORKINFONODE, * PSYSNETWORKINFONODE;

int nf_GetNetworkIpProcessInfo(PSYSNETWORKINFONODE pBuffer);

#endif // !_SYSNETWORK_H
