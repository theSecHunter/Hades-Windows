#include "public.h"
#include "thread.h"

#include "devctrl.h"
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

static  BOOLEAN					g_thr_monitor = FALSE;
static  KSPIN_LOCK				g_thr_monitorlock = NULL;

static  BOOLEAN					g_thr_ips_monitor = FALSE;
static  KSPIN_LOCK				g_thr_ips_monitorlock = NULL;

static KSPIN_LOCK               g_threadlock = NULL;
NPAGED_LOOKASIDE_LIST			g_threadlist;

static THREADDATA				g_threadQueryhead;

THREADDATA* threadctx_get()
{
	return &g_threadQueryhead;
}

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREAD_INFORMATION           Threads[0];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

BOOLEAN CheckIsRemoteThread(HANDLE ProcessId)
{
	PSYSTEM_PROCESS_INFORMATION pInfo = NULL, pMemAddr = NULL;
	ULONG						BufferLen = 0;
	NTSTATUS					status;
	BOOLEAN						bRet = FALSE;

	do
	{
		if (ZwQuerySystemInformation(SystemProcessInformation, pInfo, BufferLen, &BufferLen) == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (!BufferLen) 
				break;

			pInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(NonPagedPool, BufferLen);
			if (!pInfo) 
				break;
			pMemAddr = pInfo;

			status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, BufferLen, &BufferLen);
			if (!NT_SUCCESS(status)) break;

			do
			{
				if (pInfo->ProcessId == ProcessId)
				{
					//线程数如果等于1 是进程刚启动的主线程 不是"远程线程"
					bRet = (pInfo->NumberOfThreads > 1);
					break;
				}
				if (!pInfo->NextEntryOffset) 
					break;
			} while (pInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)pInfo + (SIZE_T)pInfo->NextEntryOffset));
			break;
		}
	} while (FALSE);

	if (pMemAddr) 
		ExFreePool(pMemAddr);
	return bRet;
}

VOID Process_NotifyThread(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	)
{
	if (!g_thr_monitor && !g_thr_ips_monitor)
		return;

	// Create: delete (FLASE)
	KLOCK_QUEUE_HANDLE lh;
	PTHREADBUFFER threadbuf = NULL;
	THREADINFO threadinfo;
	RtlSecureZeroMemory(&threadinfo, sizeof(THREADINFO));

	threadinfo.processid = ProcessId;
	threadinfo.threadid = ThreadId;
	threadinfo.createid = Create;

	// Alter Check CraeteRemoteThread
	const int CurrentId = PsGetCurrentProcessId();
	if (g_thr_ips_monitor && Create && (CurrentId != (HANDLE)4) && (ProcessId != (HANDLE)4) && (CurrentId != ProcessId) && CheckIsRemoteThread(ProcessId))
	{
		UCHAR* SrcPsName, DstPsName;
		PEPROCESS p = NULL;
		p = PsGetCurrentProcess();
		PsLookupProcessByProcessId(ProcessId, &p);
		if (p)
		{
			SrcPsName = PsGetProcessImageFileName(p);
			DstPsName = PsGetProcessImageFileName(p);
			ObDereferenceObject(p);
			DebugPrint("Find CraeteRemoteThread SrcPid: %08X %s DestPid: %08X %s\n", ProcessId, SrcPsName, CurrentId, DstPsName);
		}
		if (!g_thr_monitor)
			return;
	}

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

NTSTATUS Thread_Init()
{
	sl_init(&g_thr_monitorlock);
	sl_init(&g_thr_ips_monitorlock);

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

	// See: SAvailable starting with Windows 2000.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine
	PsSetCreateThreadNotifyRoutine(Process_NotifyThread);
	return STATUS_SUCCESS;
}

void Thread_Clean()
{
	KLOCK_QUEUE_HANDLE lh;
	THREADBUFFER* pData = NULL;
	int lock_status = 0;
	try
	{
		// Distable ProcessMon
		sl_lock(&g_threadQueryhead.thread_lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_threadQueryhead.thread_pending))
		{
			pData = RemoveHeadList(&g_threadQueryhead.thread_pending);
			sl_unlock(&lh);
			lock_status = 0;
			Thread_PacketFree(pData);
			pData = NULL;
			sl_lock(&g_threadQueryhead.thread_lock, &lh);
			lock_status = 1;
		}
		sl_unlock(&lh);
		lock_status = 0;
	}
	finally
	{
		if (1 == lock_status)
			sl_unlock(&lh);
	}

}

void Thread_Free()
{
	Thread_Clean();
	ExDeleteNPagedLookasideList(&g_threadlist);
	PsRemoveCreateThreadNotifyRoutine(Process_NotifyThread);
}

void Thread_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_thr_monitorlock, &lh);
	g_thr_monitor = code;
	sl_unlock(&lh);
}

void Thread_SetIpsMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_thr_ips_monitorlock, &lh);
	g_thr_ips_monitor = code;
	sl_unlock(&lh);
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
		threadbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, 'THMM');
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
