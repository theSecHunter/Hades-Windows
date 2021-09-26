#include "public.h"
#include "thread.h"

#include "devctrl.h"

static  BOOLEAN					g_thr_monitorprocess = FALSE;
static  KSPIN_LOCK				g_thr_monitorlock = NULL;

static KSPIN_LOCK               g_threadlock = NULL;
NPAGED_LOOKASIDE_LIST			g_threadlist;

static THREADDATA				g_threadQueryhead;

THREADDATA* threadctx_get()
{
	return &g_threadQueryhead;
}

VOID Thread_Notify(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	)
{
	// Create: delete (FLASE)
	KLOCK_QUEUE_HANDLE lh;
	PTHREADBUFFER threadbuf = NULL;
	THREADINFO threadinfo;
	RtlSecureZeroMemory(&threadinfo, sizeof(THREADINFO));

	threadinfo.processid = ProcessId;
	threadinfo.threadid = ThreadId;
	threadinfo.createid = Create;

	// Insert Query Head
	threadbuf = (PTHREADBUFFER)Thread_PacketAllocate(sizeof(THREADINFO));
	if (!threadbuf)
		return;

	threadbuf->dataLength = sizeof(THREADINFO);
	if (threadbuf->dataBuffer)
		RtlCopyMemory(threadbuf->dataBuffer, &threadinfo, sizeof(THREADINFO));

	sl_lock(&g_threadQueryhead.thread_lock, &lh);
	InsertHeadList(&g_threadQueryhead.thread_pending, &threadbuf->pEntry);
	sl_unlock(&lh);

	devctrl_pushinfo(NF_THREAD_INFO);
}

void thread_init()
{
	sl_init(&g_thr_monitorlock);
	sl_init(&g_threadlock);
	ExInitializeNPagedLookasideList(
		&g_threadlist,
		NULL,
		NULL,
		0,
		sizeof(THREADBUFFER),
		'THMM',
		0
	);

	sl_init(&g_threadQueryhead.thread_lock);
	InitializeListHead(&g_threadQueryhead.thread_pending);

	// Set Calloutback
	PsSetCreateThreadNotifyRoutine(Thread_Notify);
}

void trhead_clean()
{

}

void thread_free()
{

}

PTHREADBUFFER Thread_PacketAllocate(int lens)
{
	PTHREADBUFFER threadbuf = NULL;
	threadbuf = (PTHREADBUFFER)ExAllocateFromNPagedLookasideList(&g_threadlist);
	if (!threadbuf)
		return NULL;
	RtlSecureZeroMemory(threadbuf, sizeof(THREADBUFFER));
	
	if (lens > 0)
	{
		threadbuf->dataBuffer = (char*)ExAllocatePoolWithTag(lens, sizeof(THREADINFO), 'THMM');
		if (!threadbuf->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_threadlist, threadbuf);
			return FALSE;
		}
	}

	return threadbuf;
}

void Thread_PacketFree(PTHREADBUFFER packet)
{
	if (packet->dataBuffer)
	{
		free_np(packet->dataBuffer);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_threadlist, packet);
}
