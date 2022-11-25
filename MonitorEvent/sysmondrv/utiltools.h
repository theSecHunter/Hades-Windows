#ifndef _UTIL_H
#define _UTIL_H
#include <ndis.h>
#define MAX_PATH 260

static void utiltools_sleep(const unsigned int ttw)
{
    if (PASSIVE_LEVEL == KeGetCurrentIrql())
    {
        NDIS_EVENT  _SleepEvent;
        NdisInitializeEvent(&_SleepEvent);
        NdisWaitEvent(&_SleepEvent, ttw);
    }
}

typedef NTSTATUS(*PfnNtQueryInformationProcess) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
static PfnNtQueryInformationProcess ZwQueryInformationProcess = NULL;

typedef  NTSTATUS(*PfnZwQueryInformationThread)(
    _In_      HANDLE          ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _In_      PVOID           ThreadInformation,
    _In_      ULONG           ThreadInformationLength,
    _Out_opt_ PULONG          ReturnLength
);
static PfnZwQueryInformationThread ZwQueryInformationThread = NULL;

static void InitGloableFunction_Process()
{
    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING UtrZwQueryInformationProcessName =
            RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
        ZwQueryInformationProcess =
            (PfnNtQueryInformationProcess)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
    }
    else if (ZwQueryInformationThread == NULL)
    {
        UNICODE_STRING UtrZwQueryInformationProcessName =
            RTL_CONSTANT_STRING(L"ZwQueryInformationThread");
        ZwQueryInformationThread =
            (PfnZwQueryInformationThread)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
    }
}

static BOOLEAN QueryProcessNamePath(__in DWORD pid, __out PWCHAR path, __in DWORD pathlen)
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
        InitGloableFunction_Process();
        DWORD dw;
        WCHAR ProcessPath[MAX_PROCESS_PATH_LEN + sizeof(UNICODE_STRING)] = { 0 };
        status = ZwQueryInformationProcess(hProc, ProcessImageFileName, ProcessPath, sizeof(ProcessPath), &dw);
        if (NT_SUCCESS(status))
        {
            PUNICODE_STRING dststring = (PUNICODE_STRING)ProcessPath;
            // 7/29 可能会遇到length为空，导致拷贝蓝屏 - 已修复
            if (dststring->Length && (pathlen > (DWORD)dststring->Length + sizeof(WCHAR)))
            {
                RtlMoveMemory(path, dststring->Buffer, dststring->Length + sizeof(WCHAR));
                bRet = TRUE;
            }
        }
        ZwClose(hProc);
    }
    return bRet;
}

#ifndef _WIN64
    static void ShudowMemoryPageProtect32()
    {
        __asm
        {
            pushad;
            pushfd;

            mov eax, cr0;
            and eax, ~0x10000;
            mov cr0, eax;

            popfd;
            popad;

        }
    }
    static void StartMemoryPageProtect32()
    {
        __asm
        {
            pushad;
            pushfd;

            mov eax, cr0;
            or eax, 0x10000;
            mov cr0, eax;

            popfd;
            popad;

        }
    }
#else
// 不推荐关闭 - 推荐MDL映射修改
    const KIRQL ShudowMemoryPageProtect64()
    {
        KIRQL  irql = KeRaiseIrqlToDpcLevel();
        UINT64  cr0 = __readcr0();
        cr0 &= 0xfffffffffffeffff;
        __writecr0(cr0);
        _disable();
        return  irql;
    }
    void StartMemoryPageProtect64(const KIRQL irql)
    {
        UINT64  cr0 = __readcr0();
        cr0 |= 0x10000;
        _enable();
        __writecr0(cr0);
        KeLowerIrql(irql);
    }
#endif

#endif // !_UTIL_H


