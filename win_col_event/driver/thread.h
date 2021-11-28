#ifndef _THREAD_H
#define _THREAD_H

typedef struct _THREADINFO
{
	int processid;
	int threadid;
	int createid;
}THREADINFO, *PTHREADINFO;

typedef struct _THREADBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}THREADBUFFER, * PTHREADBUFFER;

typedef struct _THREADDATA
{
	KSPIN_LOCK thread_lock;
	LIST_ENTRY thread_pending;
}THREADDATA, * PTHREADDATA;

NTSTATUS Thread_Init();
void Thread_Clean();
void Thread_Free();
void Thread_SetMonitor(BOOLEAN code);

PTHREADBUFFER Thread_PacketAllocate(int lens);
void Thread_PacketFree(PTHREADBUFFER packet);

THREADDATA* threadctx_get();

#endif // !_THREAD_H
