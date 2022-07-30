#include "public.h"
#include "process.h"
#include "devctrl.h"
#include "kflt.h"

#include <ntddk.h>

static  BOOLEAN     g_proc_monitorprocess = FALSE;
static  KSPIN_LOCK  g_proc_monitorlock = NULL;

static  PWCHAR	    g_proc_ipsList = NULL;

static KSPIN_LOCK               g_processlock = NULL;
static NPAGED_LOOKASIDE_LIST    g_processList;
static PROCESSDATA              g_processQueryhead;

//static KEVENT					g_testEvent;

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

PROCESSDATA* processctx_get()
{
    return &g_processQueryhead;
}
NTSTATUS Process_Init(void) {

    sl_init(&g_processlock);
    sl_init(&g_proc_monitorlock);

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

    // See: Available starting with Windows Vista with SP1 and Windows Server 2008.
    // Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcessEx, FALSE);
    return STATUS_SUCCESS;
}
void Process_Free(void)
{
    // Set Close Monitro
    Process_Clean();
    ExDeleteNPagedLookasideList(&g_processList);
    PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcessEx, TRUE);
}
void Process_SetMonitor(BOOLEAN code)
{
    KLOCK_QUEUE_HANDLE lh;

    sl_lock(&g_proc_monitorlock, &lh);
    g_proc_monitorprocess = code;
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
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Process);

    // 关闭监控
    if (FALSE == g_proc_monitorprocess)
    {
        return;
    }

    PWCHAR pSub = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE lh;
    PROCESSINFO processinfo;
    RtlZeroMemory(&processinfo, sizeof(PROCESSINFO));

    // 父进程pid -- BUG
    WCHAR path[260] = { 0 };
    BOOLEAN QueryPathStatus = FALSE;
    if (QueryProcessNamePath((DWORD)ProcessId, path, sizeof(path))) {
        // _wcsupr(path);
        RtlCopyMemory(processinfo.queryprocesspath, path, sizeof(WCHAR) * 260);
        QueryPathStatus = TRUE;
    }

    PROCESSBUFFER* pinfo = (PROCESSBUFFER*)Process_PacketAllocate(sizeof(PROCESSINFO));
    if (!pinfo)
        return;

    processinfo.pid = (DWORD)ProcessId;
    if (NULL == CreateInfo)
    {
        processinfo.endprocess = 0;
        pinfo->dataLength = sizeof(PROCESSINFO);
        memcpy(pinfo->dataBuffer, &processinfo, sizeof(PROCESSINFO));
        sl_lock(&g_processQueryhead.process_lock, &lh);
        InsertHeadList(&g_processQueryhead.process_pending, &pinfo->pEntry);
        sl_unlock(&lh);
        return;
    }
    else
        processinfo.endprocess = 1;
    if (CreateInfo->ImageFileName->Length < 260 * 2)
        RtlCopyMemory(processinfo.processpath, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
    if(CreateInfo->CommandLine->Length < 260*2)
        RtlCopyMemory(processinfo.commandLine, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
    processinfo.parentprocessid = CreateInfo->ParentProcessId;

    pinfo->dataLength = sizeof(PROCESSINFO);
    memcpy(pinfo->dataBuffer, &processinfo, sizeof(PROCESSINFO));
    if (QueryPathStatus && g_proc_ipsList && Process_IsIpsProcessNameInList(processinfo.queryprocesspath))
    {// Ips
        PHADES_NOTIFICATION  notification = NULL;
        do {
            int replaybuflen = sizeof(HADES_REPLY);
            int sendbuflen = sizeof(HADES_NOTIFICATION);
            notification = (char*)ExAllocatePoolWithTag(NonPagedPool, sendbuflen, 'IPSP');
            if (!notification)
                break;
            RtlZeroMemory(notification, sendbuflen);
            notification->CommandId = 1; // IPS_PROCESSSTART
            RtlCopyMemory(&notification->Contents, &processinfo, sizeof(PROCESSINFO));
            // 等待用户操作
            NTSTATUS nSendRet = Fsflt_SendMsg(notification, sendbuflen, notification, &replaybuflen);
            // 返回Error: 数据缓冲区不够,其实已经有数据
            const DWORD  ReSafeToOpen = ((PHADES_REPLY)notification)->SafeToOpen;
            // 禁止
            if ((1 == ReSafeToOpen) || (3 == ReSafeToOpen))
                CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
        } while (FALSE);
        if (notification)
        {
            ExFreePoolWithTag(notification, 'IPSP');
            notification = NULL;
        }
    }
    sl_lock(&g_processQueryhead.process_lock, &lh);
    InsertHeadList(&g_processQueryhead.process_pending, &pinfo->pEntry);
    sl_unlock(&lh);
    // push_devctrl
    devctrl_pushinfo(NF_PROCESS_INFO);
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
    int lock_status = 0;

    // Ips Rule Name
    if (g_proc_ipsList)
    {
        ExFreePool(g_proc_ipsList);
        g_proc_ipsList = NULL;
    }

    try
    {
        // Distable ProcessMon
        sl_lock(&g_processQueryhead.process_lock, &lh);
        lock_status = 1;
        // 4/24莫名的BUG清空了相关内存，process_pending数据，锁数据还在蓝屏
        while (!IsListEmpty(&g_processQueryhead.process_pending))
        {
            pData = (PROCESSBUFFER*)RemoveHeadList(&g_processQueryhead.process_pending);
            sl_unlock(&lh);
            lock_status = 0;
            Process_PacketFree(pData);
            pData = NULL;
            sl_lock(&g_processQueryhead.process_lock, &lh);
            lock_status = 1;
        }
        sl_unlock(&lh);
        lock_status = 0;
    }
    finally {
        if (1 == lock_status)
            sl_unlock(&lh);
    }

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


BOOLEAN Process_IsIpsProcessPidInList(HANDLE ProcessId)
{

}
BOOLEAN Process_IsIpsProcessNameInList(PWCHAR path)
{
    BOOLEAN bRet = FALSE;

    if (g_proc_ipsList)
    {
        PWCHAR pName = wcsrchr(path, L'\\');
        if (pName)
        {
            PWCHAR pGame = g_proc_ipsList;
            pName++;
            while (*pGame)
            {
                if (wcscmp(pGame, pName) == 0)
                {
                    bRet = TRUE;
                    break;
                }
                while (*pGame++);
            }
        }
    }
    return bRet;
}
BOOLEAN Process_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;

    do
    {
        PWCHAR p1, p2;
        ULONG i;
        if (NULL == inputBuffer || inputBufferLength < sizeof(WCHAR))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        p1 = (PWCHAR)inputBuffer;
        p2 = ExAllocatePoolWithTag(NonPagedPool, inputBufferLength, MEM_TAG_DK);
        if (NULL == p2)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlCopyMemory(p2, p1, inputBufferLength);
        inputBufferLength >>= 1;
        for (i = 0; i < inputBufferLength; i++)
        {
            if (p2[i] == L'|')
                p2[i] = 0;
        }
        p1 = g_proc_ipsList;
        g_proc_ipsList = p2;
        if (p1)
        {
            ExFreePool(p1);
        }
    } while (FALSE);

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
void Process_ClrProcessFilterOption()
{

}
ULONG Process_SetProcessFilterOption()
{

}
DWORD Process_GetProcessFilterOption(UINT64 ProcessId)
{
}
void Process_DelProcessFilterOption(UINT64 ProcessId)
{

}

