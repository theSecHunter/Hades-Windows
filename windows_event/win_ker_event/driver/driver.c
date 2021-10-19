#include "public.h"
#include "devctrl.h"
#include "driver.h"
#include "process.h"
#include "thread.h"
#include "imagemod.h"
#include "register.h"
#include "syswmi.h"
#include "sysfile.h"

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

    // RemoveLoadImageNotify();
    if (g_processname) {
        ExFreePoolWithTag(g_processname, 'CM');
        g_processname = NULL;
    }

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

    do {
        g_processname = (char*)ExAllocatePoolWithTag(NonPagedPool, 260 * (260 * sizeof(WCHAR)), 'CM');
        if (!g_processname)
            return;

        // Register Process Monitor
        status = Process_Init();
        if (!NT_SUCCESS(status))
            return status;

        // Register registry_tab Monito

        // Register Thread Monitot
        status = Thread_Init();
        if (!NT_SUCCESS(status))
            return status;

        // Register DLL Monitor
        status = Imagemod_Init();
        if (!NT_SUCCESS(status))
            return status;

        status = Register_Init(DriverObject);
        if (!NT_SUCCESS(status))
            return status;

        status = Wmi_Init();
        if (!NT_SUCCESS(status))
            return status;

        status = File_Init(DriverObject);
        if (!NT_SUCCESS(status))
            return status;

    } while (0);

	return status;
}