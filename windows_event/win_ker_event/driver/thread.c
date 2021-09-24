#include "public.h"
#include "thread.h"

static  BOOLEAN					g_thr_monitorprocess = FALSE;
static  KSPIN_LOCK				g_thr_monitorlock = NULL;

static KSPIN_LOCK               g_threadlock = NULL;
NPAGED_LOOKASIDE_LIST			g_threadlist;

static THREADDATA				g_threadQueryhead;

VOID Thread_Route(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	)
{

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
	PsSetCreateThreadNotifyRoutineEx(1, Thread_Route);
}


void trhead_clean()
{

}

void thread_free()
{

}