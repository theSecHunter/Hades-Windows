#ifndef _REGISTER_H
#define _REGISTER_H

typedef struct _REGISTERINFO
{
	ULONG			processid;
	ULONG			threadid;
	ULONG			opeararg;
	PVOID			RootObject;
	PVOID           Object;
	ULONG			Type;
	ULONG			Attributes;
	ULONG			DesiredAccess;
	PULONG			Disposition;
	ULONG			GrantedAccess;
	ULONG           Options;
	ULONG           Wow64Flags;
	ULONG			KeyInformationClass;
	ULONG			Index;
	wchar_t			ProcessPath[260 * 2];
	wchar_t			CompleteName[260 * 2];
	char			SetData[260 * 2];
	ULONG			DataSize;
}REGISTERINFO, * PREGISTERINFO;

typedef struct _REGISTERBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}REGISTERBUFFER, * PREGISTERBUFFER;

typedef struct _REGISTERDATA
{
	KSPIN_LOCK register_lock;
	LIST_ENTRY register_pending;
}REGISTERDATA, * PREGISTERDATA;

NTSTATUS Register_Init(PDRIVER_OBJECT pDriverObject);
void Register_Free(void);
void Register_Clean(void);
void Register_SetMonitor(BOOLEAN code);
void Register_SetIpsMonitor(BOOLEAN code);
BOOLEAN Register_IsIpsProcessNameInList(const PWCHAR path);
NTSTATUS Register_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp);

REGISTERBUFFER* Register_PacketAllocate(int lens);
void Register_PacketFree(REGISTERBUFFER* packet);

REGISTERDATA* registerctx_get();

#endif // !_REGISTER_H
