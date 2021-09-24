#include "public.h"
#include "process.h"
#include "devctrl.h"

#include <ntddk.h>

static  BOOLEAN g_monitorprocess = FALSE;
static  KSPIN_LOCK g_monitorlock = NULL;

static KSPIN_LOCK               g_processlock = NULL;
static NPAGED_LOOKASIDE_LIST    g_processList;
static PROCESSDATA              g_processQueryhead;

typedef NTSTATUS(*PfnNtQueryInformationProcess) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
static PfnNtQueryInformationProcess ZwQueryInformationProcess;

static void Process_NotifyProcessEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

BOOLEAN Mem_GetLockResource(PERESOURCE* ppResource, BOOLEAN InitMsg);
BOOLEAN QueryProcessNamePath(__in DWORD pid, __out PWCHAR path, __in DWORD pathlen);

void InitGloableFunction_Process()
{
    UNICODE_STRING UtrZwQueryInformationProcessName =
        RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    ZwQueryInformationProcess =
        (PfnNtQueryInformationProcess)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
}

PROCESSDATA* processcxt_get()
{
    return &g_processQueryhead;
}

int Process_Init(void) {

    sl_init(&g_processlock);
    sl_init(&g_monitorlock);

    ExInitializeNPagedLookasideList(
        &g_processList,
        NULL,
        NULL,
        0,
        sizeof(PROCESSBUFFER),
        'PRMM',
        0
    );

    sl_init(&g_processQueryhead.process_lock);
    InitializeListHead(&g_processQueryhead.process_pending);

    InitGloableFunction_Process();
    if (!ZwQueryInformationProcess)
        return FALSE;

	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcessEx, FALSE);
	return 1;
}

void Process_Free(void)
{
    // Set Close Monitro

    Process_Clean();

    PsSetCreateProcessNotifyRoutineEx(Process_NotifyProcessEx, TRUE);
}

void Process_SetMonitor(BOOLEAN code)
{
    KSPIN_LOCK_QUEUE lh;

    sl_lock(&g_monitorlock, &lh);
    g_monitorprocess = code;
    sl_unlock(&lh);
}

BOOLEAN Mem_GetLockResource(
    PERESOURCE* ppResource, 
    BOOLEAN InitMsg)
{
    *ppResource = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(ERESOURCE), 'tk');
    if (*ppResource) {
        ExInitializeResourceLite(*ppResource);
        return TRUE;
    }
    else {
        return FALSE;
    }
}

VOID Process_NotifyProcessEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
    /*
        // 创建进程、销毁进程 ProcessInfo
    */
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Process);

    // 关闭监控
    if (FALSE == g_monitorprocess)
    {
        return;
    }

    PWCHAR pSub = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE lh;
    PROCESSINFO processinfo;
    RtlZeroMemory(&processinfo, sizeof(PROCESSINFO));

    // 父进程pid -- BUG
   
    
    // DbgBreakPoint();
    WCHAR path[260] = { 0 };
    if (QueryProcessNamePath((DWORD)ProcessId, path, sizeof(path))) {
        // _wcsupr(path);
        RtlCopyMemory(processinfo.queryprocesspath, path, sizeof(WCHAR) * 260);
    }

    PROCESSBUFFER* pinfo = (PROCESSBUFFER*)Process_PacketAllocate(sizeof(PROCESSINFO));
    if (!pinfo)
        return;

    if (NULL == CreateInfo)
    {
        processinfo.processid = ProcessId;
        processinfo.endprocess = 0;
        pinfo->dataLength = sizeof(PROCESSINFO);
        memcpy(pinfo->dataBuffer, &processinfo, sizeof(PROCESSINFO));
        sl_lock(&g_processQueryhead.process_lock, &lh);
        InsertHeadList(&g_processQueryhead.process_pending, &pinfo->pEntry);
        sl_unlock(&lh);
        return;
    }

    processinfo.processid = CreateInfo->ParentProcessId;

    // 父进程做的操作 --> 如果没有父进程 也可能是本身
    processinfo.endprocess = 1;
    if (CreateInfo->ImageFileName->Length < 260 * 2)
        RtlCopyMemory(processinfo.processpath, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
    if(CreateInfo->CommandLine->Length < 260*2)
        RtlCopyMemory(processinfo.commandLine, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);

    pinfo->dataLength = sizeof(PROCESSINFO);
    memcpy(pinfo->dataBuffer, &processinfo, sizeof(PROCESSINFO));

    sl_lock(&g_processQueryhead.process_lock, &lh);
    InsertHeadList(&g_processQueryhead.process_pending, &pinfo->pEntry);
    sl_unlock(&lh);

    // push_devctrl
    devctrl_pushprocessinfo(NF_PROCESS_INFO);

    return;
}

BOOLEAN QueryProcessNamePath(__in DWORD pid, __out PWCHAR path, __in DWORD pathlen)
{
    BOOLEAN bRet = FALSE;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES obj;
    HANDLE hProc = NULL;
    NTSTATUS status;

    InitializeObjectAttributes(&obj, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = NULL;
    status = ZwOpenProcess(&hProc, GENERIC_ALL, &obj, &cid);
    if (NT_SUCCESS(status))
    {
        DWORD dw;
        WCHAR ProcessPath[MAX_PROCESS_PATH_LEN + sizeof(UNICODE_STRING)] = { 0 };
        status = ZwQueryInformationProcess(hProc, ProcessImageFileName, ProcessPath, sizeof(ProcessPath), &dw);
        if (NT_SUCCESS(status))
        {
            PUNICODE_STRING dststring = (PUNICODE_STRING)ProcessPath;
            // 7/29 可能会遇到length为空，导致拷贝蓝屏 - 已修复
            if ((pathlen > (DWORD)dststring->Length + sizeof(WCHAR)) && dststring->Length)
            {
                RtlMoveMemory(path, dststring->Buffer, dststring->Length + sizeof(WCHAR));
                bRet = TRUE;
            }
        }
        ZwClose(hProc);
    }
    return bRet;
}

void Process_Clean(void)
{
    KLOCK_QUEUE_HANDLE lh;
    PROCESSBUFFER* pData = NULL;

    // Distable ProcessMon
    sl_lock(&g_processQueryhead.process_lock, &lh);

    while (!IsListEmpty(&g_processQueryhead.process_pending))
    {
        // BUG关机蓝屏
        pData = RemoveEntryList(&g_processQueryhead.process_pending);
        sl_unlock(&lh);
        Process_PacketFree(pData);
        pData = NULL;
        sl_lock(&g_processQueryhead.process_lock, &lh);
    }

    sl_unlock(&lh);
}

PROCESSBUFFER* Process_PacketAllocate(int lens)
{
    PROCESSBUFFER* processbuf = NULL;
    processbuf = (PROCESSBUFFER*)ExAllocateFromNPagedLookasideList(&g_processList);
    if (!processbuf)
        return NULL;

    memset(processbuf, 0, sizeof(PROCESSBUFFER));

    if (lens > 0)
    {
        processbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, 'PRMM');
        if (!processbuf->dataBuffer)
        {
            ExFreeToNPagedLookasideList(&g_processList, processbuf);
            return FALSE;
        }
    }
    return processbuf;
}

void Process_PacketFree(PROCESSBUFFER* packet)
{
    if (packet->dataBuffer)
    {
        free_np(packet->dataBuffer);
        packet->dataBuffer = NULL;
    }
    ExFreeToNPagedLookasideList(&g_processList, packet);
}