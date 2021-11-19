//
// 	WFPDRIVER 
// 	Copyright (C) 2021 Vitaly Sidorov
//	All rights reserved.
//
//  公共头
//

#ifndef _PUBLIC_H
#define _PUBLIC_H

#ifdef _NXPOOLS
#ifdef USE_NTDDI
#if (NTDDI_VERSION >= NTDDI_WIN8)
#define POOL_NX_OPTIN 1
#endif
#endif
#endif

#include <ntifs.h>
#include <ntstrsafe.h>

#undef ASSERT
#define ASSERT(x)

#define MEM_TAG		'3TLF'
#define MEM_TAG_TCP	'TTLF'
#define MEM_TAG_TCP_PACKET	'PTLF'
#define MEM_TAG_TCP_DATA	'DTLF'
#define MEM_TAG_TCP_DATA_COPY	'CTLF'
#define MEM_TAG_TCP_INJECT	'ITLF'
#define MEM_TAG_UDP	'UULF'
#define MEM_TAG_UDP_PACKET	'PULF'
#define MEM_TAG_UDP_DATA	'DULF'
#define MEM_TAG_UDP_DATA_COPY	'CULF'
#define MEM_TAG_UDP_INJECT	'IULF'
#define MEM_TAG_QUEUE	'QTLF'
#define MEM_TAG_IP_PACKET	'PILF'
#define MEM_TAG_IP_DATA_COPY 'DILF'
#define MEM_TAG_IP_INJECT	'IILF'
#define MEM_TAG_NETWORK	'SWSW'

#define MEM_TAG_DK	'UDDK'

#define malloc_np(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
#define free_np(p) ExFreePool(p);

#define sl_init(x) KeInitializeSpinLock(x)
#define sl_lock(x, lh) KeAcquireInStackQueuedSpinLock(x, lh)
#define sl_unlock(lh) KeReleaseInStackQueuedSpinLock(lh)

#define htonl(x) (((((ULONG)(x))&0xffL)<<24)           | \
	((((ULONG)(x))&0xff00L)<<8)        | \
	((((ULONG)(x))&0xff0000L)>>8)        | \
	((((ULONG)(x))&0xff000000L)>>24))

#define htons(_x_) ((((unsigned char*)&_x_)[0] << 8) & 0xFF00) | ((unsigned char*)&_x_)[1] 

#define DPREFIX "[DK]-"

#define DEFAULT_HASH_SIZE 3019

#define MAX_PROCESS_PATH_LEN 300
#define MAX_PROCESS_NAME_LEN 64

extern DWORD g_dwLogLevel;
// extern BOOLEAN g_monitorflag;

extern POBJECT_TYPE* IoDriverObjectType;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(
    IN PEPROCESS Process
);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN PVOID FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
    PEPROCESS Process
);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL
);

NTKERNELAPI UCHAR* PsGetProcessImageFileName(
    PEPROCESS Process
);

NTSTATUS
ObReferenceObjectByName(
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID* Object
);

enum _NF_DATA_CODE
{
	NF_PROCESS_INFO = 1,
    NF_THREAD_INFO,
    NF_IMAGEMODE_INFO,
    NF_REGISTERTAB_INFO,
    NF_FILE_INFO,
    NF_SESSION_INFO
}NF_DATA_CODE;



typedef UNALIGNED struct _NF_DATA
{
	int				code;
	int				id;
	unsigned long	bufferSize;
	char 			buffer[1];
} NF_DATA, * PNF_DATA;

typedef UNALIGNED struct _NF_READ_RESULT
{
	unsigned __int64 length;
} NF_READ_RESULT, * PNF_READ_RESULT;

typedef UNALIGNED struct _NF_BUFFERS
{
	unsigned __int64 inBuf;
	unsigned __int64 inBufLen;
	unsigned __int64 outBuf;
	unsigned __int64 outBufLen;
} NF_BUFFERS, * PNF_BUFFERS;

typedef struct _ETHERNET_HEADER_
{
    unsigned char    pDestinationAddress[6];
    unsigned char    pSourceAddress[6];
    unsigned short  type;
}ETHERNET_HEADER, *PETHERNET_HEADER;

typedef struct _IP_HEADER_V4_
{
    union
    {
        unsigned char  versionAndHeaderLength;
        struct
        {
            unsigned char  headerLength : 4;
            unsigned char  version : 4;
        };
    };
    union
    {
        unsigned char   typeOfService;
        unsigned char   differentiatedServicesCodePoint;
        struct
        {
            unsigned char  explicitCongestionNotification : 2;
            unsigned char  typeOfService6bit : 6;
        };
    };
    unsigned short  totalLength;
    unsigned short  identification;
    union
    {
        unsigned short  flagsAndFragmentOffset;
        struct
        {
            unsigned short  fragmentOffset : 13;
            unsigned short  flags : 3;
        };
    };
    unsigned char   timeToLive;
    unsigned char   protocol;
    unsigned short  checksum;
    unsigned char    pSourceAddress[sizeof(unsigned int)];
    unsigned char    pDestinationAddress[sizeof(unsigned int)];
}IP_HEADER_V4, * PIP_HEADER_V4;

struct iphdr
{
    unsigned char  HdrLength : 4;
    unsigned char  Version : 4;
    unsigned char  TOS;
    unsigned short Length;
    unsigned short Id;
    unsigned short FragOff0;
    unsigned char  TTL;
    unsigned char  Protocol;
    unsigned short Checksum;
    unsigned int SrcAddr;
    unsigned int DstAddr;
};

typedef struct _IP_HEADER_V6_
{
    union
    {
        unsigned char pVersionTrafficClassAndFlowLabel[4];
        struct
        {
            unsigned char r1 : 4;
            unsigned char value : 4;
            unsigned char r2;
            unsigned char r3;
            unsigned char r4;
        }version;
    };
    unsigned short payloadLength;
    unsigned char  nextHeader;
    unsigned char  hopLimit;
    unsigned char    pSourceAddress[16];
    unsigned char    pDestinationAddress[16];
} IP_HEADER_V6, * PIP_HEADER_V6;


typedef struct _TCP_HEADER_
{
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned int sequenceNumber;
    unsigned int acknowledgementNumber;
    union
    {
        unsigned char dataOffsetReservedAndNS;
        struct
        {
            unsigned char nonceSum : 1;
            unsigned char reserved : 3;
            unsigned char dataOffset : 4;
        }dORNS;
    };
    union
    {
        unsigned char controlBits;
        struct
        {
            unsigned char FIN : 1;
            unsigned char SYN : 1;
            unsigned char RST : 1;
            unsigned char PSH : 1;
            unsigned char ACK : 1;
            unsigned char URG : 1;
            unsigned char ECE : 1;
            unsigned char CWR : 1;
        };
    };
    unsigned short window;
    unsigned short checksum;
    unsigned short urgentPointer;
}TCP_HEADER, * PTCP_HEADER;

typedef struct _UDP_HEADER_
{
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned short length;
    unsigned short checksum;
}UDP_HEADER, * PUDP_HEADER;

typedef enum _OBJECT_INFORMATION_CLASSEx {
    ObjectBasicInformation1,
    ObjectNameInformation1,
    ObjectTypeInformation1,
    ObjectAllInformation1,
    ObjectDataInformation1
} OBJECT_INFORMATION_CLASSEx, * POBJECT_INFORMATION_CLASSEx;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG                   Attributes;
    ACCESS_MASK             DesiredAccess;
    ULONG                   HandleCount;
    ULONG                   ReferenceCount;
    ULONG                   PagedPoolUsage;
    ULONG                   NonPagedPoolUsage;
    ULONG                   Reserved[3];
    ULONG                   NameInformationLength;
    ULONG                   TypeInformationLength;
    ULONG                   SecurityDescriptorLength;
    LARGE_INTEGER           CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING          TypeName;
    ULONG                   TotalNumberOfHandles;
    ULONG                   TotalNumberOfObjects;
    WCHAR                   Unused1[8];
    ULONG                   HighWaterNumberOfHandles;
    ULONG                   HighWaterNumberOfObjects;
    WCHAR                   Unused2[8];
    ACCESS_MASK             InvalidAttributes;
    GENERIC_MAPPING         GenericMapping;
    ACCESS_MASK             ValidAttributes;
    BOOLEAN                 SecurityRequired;
    BOOLEAN                 MaintainHandleCount;
    USHORT                  MaintainTypeList;
    POOL_TYPE               PoolType;
    ULONG                   DefaultPagedPoolCharge;
    ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT	UniqueProcessId;
    USHORT	CreatorBackTraceIndex;
    UCHAR	ObjectTypeIndex;
    UCHAR	HandleAttributes;
    USHORT	HandleValue;
    PVOID	Object;
    ULONG	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG64 NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY        InLoadOrderLinks;
    LIST_ENTRY        InMemoryOrderLinks;
    LIST_ENTRY        InInitializationOrderLinks;
    PVOID                 DllBase;
    PVOID                 EntryPoint;
    ULONG                 SizeOfImage;
    UNICODE_STRING        FullDllName;
    UNICODE_STRING        BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32                InLoadOrderLinks;
    LIST_ENTRY32                InMemoryOrderLinks;
    LIST_ENTRY32                InInitializationOrderLinks;
    ULONG                       DllBase;
    ULONG                       EntryPoint;
    ULONG                       SizeOfImage;
    UNICODE_STRING32            FullDllName;
    UNICODE_STRING32            BaseDllName;
    ULONG                       Flags;
    USHORT                      LoadCount;
    USHORT                      TlsIndex;
    //下面的省略
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

#endif