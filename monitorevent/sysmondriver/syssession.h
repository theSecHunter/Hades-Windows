#ifndef _SYSSESSION_H
#define _SYSSESSION_H

typedef struct _SESSIONINFO
{
	int             processid;
	int             threadid;
	unsigned long	evens;
	char            iosessioninfo[sizeof(IO_SESSION_STATE_INFORMATION)];
}SESSIONINFO, * PSESSIONINFO;

typedef struct _SESSIONBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}SESSIONBUFFER, * PSESSIONBUFFER;

typedef struct _SESSIONDATA
{
	KSPIN_LOCK session_lock;
	LIST_ENTRY session_pending;
}SESSIONDATA, * PSESSIONDATA;

NTSTATUS Session_Init(PDRIVER_OBJECT pDriverObject);
void Session_Free(void);
void Session_Clean(void);
void Session_SetMonitor(BOOLEAN code);

SESSIONBUFFER* Session_PacketAllocate(int lens);
void Session_PacketFree(SESSIONBUFFER* packet);

SESSIONDATA* sessionctx_get();

#endif // !_SYSSESSION_H

