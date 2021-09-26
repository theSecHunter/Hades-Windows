#ifndef _PROCESS_H
#define _PROCESS_H

typedef struct _PROCESSINFO
{
	int processid;
	int endprocess;
	wchar_t processpath[260 * 2];
	wchar_t commandLine[260 * 2];
	wchar_t queryprocesspath[260 * 2];
}PROCESSINFO, * PPROCESSINFO;

typedef struct _PROCESSBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}PROCESSBUFFER,*P_PROCESSBUFFER;

typedef struct _PROCESSDATA
{
	KSPIN_LOCK process_lock;
	LIST_ENTRY process_pending;
}PROCESSDATA,*PPROCESSDATA;

int Process_Init(void);
void Process_Free(void);
void Process_Clean(void);
void Process_SetMonitor(BOOLEAN code);

PROCESSBUFFER* Process_PacketAllocate(int lens);
void Process_PacketFree(PROCESSBUFFER* packet);

PROCESSDATA* processctx_get();

#endif // !MY_PROCESS_H

