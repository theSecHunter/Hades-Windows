#include "public.h"
#include "devctrl.h"
#include "driver.h"
#include "process.h"
#include "thread.h"
#include "imagemod.h"
#include "register.h"
#include "syswmi.h"
#include "sysfile.h"
#include "syssession.h"
#include "minifilter.h"
#include "kflt.h"

#include <fltKernel.h>
#include <dontuse.h>

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG_PTR       OperationStatusCtx = 1;
ULONG           gTraceFlags = 0;
PFLT_PORT		gClientPort;
PFLT_FILTER		gFilterHandle = NULL;
WCHAR*          g_processname = NULL;
unsigned int	g_processnamelen = 0;
PFLT_PORT       gServerPort;
static BOOLEAN  g_unDriverLoadFlag = FALSE;
static BOOLEAN  g_Win10Version = FALSE;

typedef NTSTATUS(*PfnNtQueryInformationProcess) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
static PfnNtQueryInformationProcess ZwQueryInformationProcess;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/
EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

VOID driverUnload(
    _In_ struct _DRIVER_OBJECT* DriverObject
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, driverUnload)
#endif

VOID driverUnload(
    _In_ struct _DRIVER_OBJECT* DriverObject
)
{
    PAGED_CODE();

    if (g_processname) {
        ExFreePoolWithTag(g_processname, 'CM');
        g_processname = NULL;
    }

    Fsflt_freePort();
    //FsMini_Free();
    devctrl_free();
    devctrl_ioThreadFree();
    return STATUS_SUCCESS;
}


/*************************************************************************
	Driver Entry
*************************************************************************/
NTSTATUS
	DriverEntry(
		_In_ PDRIVER_OBJECT DriverObject,
		_In_ PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("driver!DriverEntry: Entered\n"));

    // Init MiniFilter
    status = FsMini_Init(DriverObject);
    if (!NT_SUCCESS(status))
        return status;
    status = Mini_StartFilter();
    if (!NT_SUCCESS(status))
        return status;
    status = Fsflt_initPort();
    if (!NT_SUCCESS(status))
    {
        FsMini_Clean();
        return status;
    }
    
    int i = 0;
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)devctrl_dispatch;
    }
    
    DriverObject->DriverUnload = driverUnload;
    
	// Init Event Handler
    status = devctrl_ioInit(DriverObject);
    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    // Get System Version
    OSVERSIONINFOW osver;
    RtlSecureZeroMemory(&osver, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);
    status = RtlGetVersion(&osver);
    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    // Os <= Win8 (FileObject 8.1也可能PG)
    if ((osver.dwMajorVersion == 6) && (osver.dwMinorVersion <= 1))
        g_Win10Version = TRUE;
    else if ((osver.dwMajorVersion < 6) && (osver.dwMajorVersion > 4))
        g_Win10Version = TRUE;
    else
        g_Win10Version = FALSE;

    devctrl_pushversion(g_Win10Version);

    do {
        g_processname = (char*)ExAllocatePoolWithTag(NonPagedPool, 260 * (260 * sizeof(WCHAR)), 'CM');
        if (!g_processname)
            return status;

        status = Process_Init();
        if (!NT_SUCCESS(status))
            return status;

        status = Thread_Init();
        if (!NT_SUCCESS(status))
            return status;

        status = Imagemod_Init();
        if (!NT_SUCCESS(status))
            return status;

        status = Register_Init(DriverObject);
        if (!NT_SUCCESS(status))
            return status;

        status = Wmi_Init();
        if (!NT_SUCCESS(status))
            return status;

        if (g_Win10Version)
        {
            status = File_Init(DriverObject);
            if (!NT_SUCCESS(status))
                return status;
        }

        status = Session_Init(DriverObject);
        if (!NT_SUCCESS(status))
            return status;

    } while (0);

	return status;
}