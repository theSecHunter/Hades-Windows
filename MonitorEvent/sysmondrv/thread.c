#include "public.h"
#include "thread.h"
#include "rThread.h"
#include "utiltools.h"
#include "devctrl.h"

static  BOOLEAN					g_thr_monitor = FALSE;
static  KSPIN_LOCK				g_thr_monitorlock = 0;

static  BOOLEAN					g_thr_ips_monitor = FALSE;
static  KSPIN_LOCK				g_thr_ips_monitorlock = 0;

NPAGED_LOOKASIDE_LIST			g_threadlist;
static KSPIN_LOCK               g_threadlock = 0;

static THREADDATA				g_threadQueryhead;

static WinVer					g_thrOsver = 0;

THREADDATA* threadctx_get()
{
	return &g_threadQueryhead;
}

void thr_pushversion(const ULONG dOsver)
{
	g_thrOsver = dOsver;
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

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

BOOLEAN CheckIsRemoteThread(const HANDLE ProcessId)
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

			pInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, BufferLen, 'THMM');
			if (!pInfo) 
				break;
			pMemAddr = pInfo;

			status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, BufferLen, &BufferLen);
			if (!NT_SUCCESS(status)) break;

			do
			{
				if (pInfo->ProcessId == ProcessId)
				{
					// 线程数如果等于1 是进程刚启动的主线程 不是"远程线程"
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

const ULONG GetThrStartAddressOffset()
{
	/*
		0x02C0 (3.10);
		0x0230 (3.50 to 5.0);
		0x0224 (5.1);
		0x022C (early 5.2); XP
		0x021C (late 5.2)
		0x03D8 (late 5.2);
		0x03C0 (v. late 5.2)
	*/
	ULONG uThrStartAddrOffset = 0;
	switch (g_thrOsver)
	{
	case WINVER_7:
	case WINVER_7_SP1:
	{
#ifndef _WIN32

#else

#endif
	}
	break;
	case WINVER_8:
	case WINVER_81:
	{
#ifndef _WIN32

#else

#endif
	}
	break;
	case WINVER_10:
	{
#ifndef _WIN32

#else

#endif
	}
	break;
	}
	return uThrStartAddrOffset;
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

	// Alter Check CraeteRemoteThread
	const HANDLE CurrentProcId = PsGetCurrentProcessId();
	if (g_thr_ips_monitor && Create && (CurrentProcId != (HANDLE)4) && (ProcessId != (HANDLE)4) && (CurrentProcId != ProcessId) && CheckIsRemoteThread(ProcessId))
	{
		// Find DestPid
		WCHAR path[260 * 2] = { 0 };
		BOOLEAN QueryPathStatus = FALSE;
		if (QueryProcessNamePath((DWORD)ProcessId, path, sizeof(path)))
			QueryPathStatus = TRUE;
		if (QueryPathStatus && rThrInject_IsIpsProcessNameInList(path))
		{
			UCHAR* SrcPsName = NULL, DstPsName = NULL;
			const PEPROCESS pSrc = PsGetCurrentProcess();
			PEPROCESS pDst = NULL;
			PsLookupProcessByProcessId(ProcessId, &pDst);
			if (pSrc && pDst)
			{
				SrcPsName = PsGetProcessImageFileName(pSrc);
				DstPsName = PsGetProcessImageFileName(pDst);
				ObDereferenceObject(pDst);
				//DebugPrint("Find CraeteRemoteThread SrcPid: %08X %s DestPid: %08X %s\n", CurrentProcId, SrcPsName, ProcessId, DstPsName);
			}
			DbgBreakPoint();
			// Kill pSrc Process
			HANDLE hThreadRef = NULL;
			PETHREAD pEth = NULL;
			PsLookupThreadByThreadId(ThreadId, &pEth);
			do 
			{
				if (!pEth)
					break;
				NTSTATUS rc = ObOpenObjectByPointer(pEth, OBJ_KERNEL_HANDLE, NULL, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &hThreadRef);
				if (!NT_SUCCESS(rc) || !hThreadRef)
					break;
				//InitGloableFunction_Process();
				//if (!ZwQueryInformationThread)
				//	break;
				//THREAD_BASIC_INFORMATION ThreadInfo; ULONG res;
				//rc = ZwQueryInformationThread(hThreadRef, ThreadBasicInformation, &ThreadInfo, sizeof(ThreadInfo), &res);
				//if (!NT_SUCCESS(rc))
				//	break;
				//PVOID pStartAddress; r3
				//rc = ZwQueryInformationThread(hThreadRef, ThreadQuerySetWin32StartAddress, &pStartAddress, sizeof(pStartAddress), &res);
				//if (!NT_SUCCESS(rc))
				//	break;
				// STATUS_INVALID_PARAMETER
				/*rc = ZwSetInformationThread(hThreadRef, ThreadQuerySetWin32StartAddress, NULL, 0);
				if (!NT_SUCCESS(rc))
					break;*/
			} while (FALSE);
			if (hThreadRef)
				ZwClose(hThreadRef);
			if (pEth)
				ObDereferenceObject(pEth);
		}
	}
	if (!g_thr_monitor)
		return;

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
	// Ips Rule Name
	rThrInject_IpsClean();

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
			pData = (THREADBUFFER*)RemoveHeadList(&g_threadQueryhead.thread_pending);
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
