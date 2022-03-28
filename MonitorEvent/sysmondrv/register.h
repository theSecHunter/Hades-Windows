#ifndef _REGISTER_H
#define _REGISTER_H

typedef struct _REGISTERINFO
{
	int processid;
	int threadid;
	int opeararg;
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

REGISTERBUFFER* Register_PacketAllocate(int lens);
void Register_PacketFree(REGISTERBUFFER* packet);

REGISTERDATA* registerctx_get();

#endif // !_REGISTER_H
