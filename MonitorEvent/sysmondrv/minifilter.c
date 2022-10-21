#include "public.h"
#include "minifilter.h"
#include <fltKernel.h>
#include "rDirectory.h"
#include "utiltools.h"
#include <tchar.h>

// extern count +1 kflt.c
PFLT_FILTER         g_FltServerPortEvnet = NULL;
static ULONG        g_fltregstatus = FALSE;

static  BOOLEAN		    g_fsflt_ips_monitorprocess = FALSE;
static  KSPIN_LOCK		g_fsflt_ips_monitorlock = 0;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags1 = 0;
#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags1,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

NTSTATUS
FsFilter1Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FsFilter1InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

NTSTATUS
FsFilter1InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
FsFilter1InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
FsFilter1InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FsFilter1Unload)
#pragma alloc_text(PAGE, FsFilter1InstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilter1InstanceSetup)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownComplete)
#endif

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsFilterAntsDrvPreExe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FsFilterAntsDrPostFileHide(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
      // file create
      { IRP_MJ_CREATE,
        0,
        FsFilter1PreOperation,
        NULL/*FsFilter1PostOperation*/},

      //// hide file
      //{ IRP_MJ_DIRECTORY_CONTROL,
      //  0,
      //  FsFilterAntsDrPostFileHide,
      //  NULL },

      //// disable exe execute
      //{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      //  0,
      //  FsFilterAntsDrvPreExe,
      //  NULL },

      //// delete rename
      //{ IRP_MJ_SET_INFORMATION,
      //  0,
      //  FsFilter1PreOperation,
      //  NULL },


#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_CLOSE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_READ,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_WRITE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_SET_EA,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      FsFilter1PreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_CLEANUP,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_PNP,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_MDL_READ,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    NULL,                               //  MiniFilterUnload

    FsFilter1InstanceSetup,                    //  InstanceSetup
    FsFilter1InstanceQueryTeardown,            //  InstanceQueryTeardown
    FsFilter1InstanceTeardownStart,            //  InstanceTeardownStart
    FsFilter1InstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

void FsFlt_SetDirectoryIpsMonitor(code)
{
    KLOCK_QUEUE_HANDLE lh;

    KeAcquireInStackQueuedSpinLock(&g_fsflt_ips_monitorlock, &lh);
    g_fsflt_ips_monitorprocess = code;
    KeReleaseInStackQueuedSpinLock(&lh);
}

NTSTATUS FsMini_Init(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS nStatus = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FltServerPortEvnet);
    if (NT_SUCCESS(nStatus))
    {
        g_fltregstatus = TRUE;
        // Init Rule
        rDirectory_IpsInit();
    }

    KeInitializeSpinLock(&g_fsflt_ips_monitorlock);

    return nStatus;
}

NTSTATUS FsMini_Clean()
{
    rDirectory_IpsClean();
    return STATUS_SUCCESS;
}

NTSTATUS FsMini_Free()
{
    FsMini_Clean();
    if ((TRUE == g_fltregstatus) && g_FltServerPortEvnet)
    {
        FltUnregisterFilter(g_FltServerPortEvnet);
        g_FltServerPortEvnet = NULL;
        g_fltregstatus = FALSE;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Mini_StartFilter()
{
    //
    //  Start filtering i/o
    //
    if ((g_FltServerPortEvnet == NULL) || !g_fltregstatus)
        return STATUS_UNSUCCESSFUL;

    NTSTATUS status = FltStartFiltering(g_FltServerPortEvnet);
    if (!NT_SUCCESS(status)) {

        FltUnregisterFilter(g_FltServerPortEvnet);
    }

    return status;
}

NTSTATUS
FsFilter1Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1!FsFilter1Unload: Entered\n"));

    if ((TRUE == g_fltregstatus) && g_FltServerPortEvnet)
        FltUnregisterFilter(g_FltServerPortEvnet);

    return STATUS_SUCCESS;
}

NTSTATUS
FsFilter1InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1!FsFilter1InstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
FsFilter1InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1!FsFilter1InstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}

VOID
FsFilter1InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1!FsFilter1InstanceTeardownStart: Entered\n"));
}

VOID
FsFilter1InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1!FsFilter1InstanceTeardownComplete: Entered\n"));
}


// Volum to Guid
//void GetFileGuid(_In_ PCFLT_RELATED_OBJECTS FltObjects)
//{
//    NTSTATUS status = STATUS_SUCCESS;
//    UNICODE_STRING VolumeGuidString, volumeGuidName;
//    ULONG bytesRequired = 0; GUID VolumeGuid;
//    //
//    // We use a while loop for cleanup
//    //
//    while (STATUS_SUCCESS == status) {
//
//        //
//        // First call is to get the correct size
//        // 
//        VolumeGuidString.Buffer = NULL;
//        VolumeGuidString.Length = 0;
//        VolumeGuidString.MaximumLength = 0;
//
//        (void)FltGetVolumeGuidName(FltObjects->Volume, &VolumeGuidString, &bytesRequired);
//
//        //
//        // Let's allocate space
//        //
//        VolumeGuidString.Buffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, bytesRequired, 'GUMM');
//        VolumeGuidString.Length = 0;
//        ASSERT(bytesRequired <= UNICODE_STRING_MAX_BYTES);
//        VolumeGuidString.MaximumLength = (USHORT)bytesRequired;
//
//        if (NULL == VolumeGuidString.Buffer) {
//            status = STATUS_INSUFFICIENT_RESOURCES;
//            break;
//        }
//
//        //
//        // Lets call it again
//        // 
//        status = FltGetVolumeGuidName(FltObjects->Volume, &VolumeGuidString, &bytesRequired);
//
//        if (!NT_SUCCESS(status)) {
//            break;
//        }
//
//        //
//        // The format is \??\Volume{GUID}
//        //
//        int index = 0;
//        for (index = 0; (L'{' != VolumeGuidString.Buffer[index] && index < (VolumeGuidString.Length / sizeof(WCHAR))); index++)
//            /* nothing */;
//
//        volumeGuidName.Buffer = &VolumeGuidString.Buffer[index];
//        volumeGuidName.Length = (USHORT)(VolumeGuidString.Length - sizeof(WCHAR) * index);
//        status = RtlGUIDFromString(&volumeGuidName, &VolumeGuid);
//
//        if (!NT_SUCCESS(status)) {
//            break;
//        }
//        //
//        // Success or failure, we're done
//        //
//        break;
//    }
//}
//_Success_(return) BOOLEAN GetVolumeGuid(_In_z_ TCHAR * OriginalFilePathName, __out GUID * Guid)
//{
//    TCHAR* filePathName;
//    ULONG filePathNameSize = UNICODE_STRING_MAX_BYTES;
//    TCHAR guidVolumeName[64]; // these names are fixed size and much smaller than this
//    USHORT index;
//    TCHAR* fileNamePart;
//
//
//    filePathName = (TCHAR*)ExAllocatePoolWithTag(PagedPool, filePathNameSize, 'GUMM');
//
//    if (NULL == filePathName) {
//        return FALSE;
//    }
//
//    filePathNameSize /= sizeof(TCHAR);
//
//    GetFullPathName(OriginalFilePathName, filePathNameSize, filePathName, &fileNamePart);
//
//    //
//    // We now have a path name, let's see if we can trim it until we find a valid path
//    //
//    index = (USHORT)_tcslen(filePathName);
//
//    if (0 == index) {
//
//        //
//        // This is a very strange case - why would we get a zero length path name?
//        //
//        _tprintf(TEXT("GetVolumeGuid: Original Name is %s, GetFullPathName returned a zero length.  filePathName 0x%p, fileNamePart 0x%p\n"),
//            OriginalFilePathName,
//            filePathName,
//            fileNamePart);
//
//        return FALSE;
//    }
//
//    //
//    // We need to point to the last character
//    //
//    index--;
//
//
//    //
//    // volume mount points require a trailing backslash
//    //
//    if (TEXT('\\') != filePathName[index]) {
//
//        if (index == UNICODE_STRING_MAX_CHARS) {
//            //
//            // We can't deal with this case - but it won't really happen (32K long path name?)
//            //
//            ExFreePoolWithTag(filePathName, 'GUMM');
//            return FALSE;
//        }
//
//        //
//        // Add the trailing backslash
//        //
//        filePathName[++index] = TEXT('\\');
//        filePathName[++index] = TEXT('\0');
//
//    }
//
//    while (!GetVolumeNameForVolumeMountPoint(filePathName, guidVolumeName, sizeof(guidVolumeName) / sizeof(TCHAR))) {
//
//        while (--index) {
//
//            if (filePathName[index] == TEXT('\\')) {
//                filePathName[index + 1] = TEXT('\0');
//                break;
//            }
//
//            //
//            // Otherwise we just keep seeking back in the string
//        }
//
//        if (0 == index) {
//            //
//            // We don't have any string left to check, this is an error condition
//            //
//            break;
//        }
//    }
//
//    //
//    // At this point we are done with the buffer
//    //
//    ExFreePoolWithTag(filePathName, 'GUMM');
//    filePathName = NULL;
//
//    //
//    // If the index is zero, we terminated the loop without finding the mount point
//    //
//    if (0 == index) {
//        return FALSE;
//    }
//
//    //
//    // Look for the trailing closing brace }
//    //
//    for (index = 0; index < sizeof(guidVolumeName) / sizeof(TCHAR); index++) {
//        if (L'}' == guidVolumeName[index]) break;
//    }
//
//    if (index >= sizeof(guidVolumeName) / sizeof(TCHAR)) {
//        return FALSE;
//    }
//
//    //
//    // Set it as null
//    //
//    guidVolumeName[index++] = L'\0';
//
//    //
//    // Look for the leading opening brace {
//    //
//    for (index = 0; index < sizeof(guidVolumeName) / sizeof(TCHAR); index++) {
//        if (L'{' == guidVolumeName[index]) break;
//    }
//
//    if (index >= sizeof(guidVolumeName) / sizeof(TCHAR)) {
//        return FALSE;
//    }
//
//    //
//    // Skip over the leading {
//    //
//    index++;
//
//    //rstatus = UuidFromString((RPC_WSTR)&guidVolumeName[index], (UUID*)Guid);
//    //if (RPC_S_OK != rstatus) {
//    //    return FALSE;
//    //}
//
//    return TRUE;
//}

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_fsflt_ips_monitorprocess)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    const KIRQL irql = KeGetCurrentIrql();
    if (irql == PASSIVE_LEVEL)
    {
        // 1. find Rule Mods directoryPath 
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(status))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        FltReleaseFileNameInformation(Data);
        DbgBreakPoint();
        // Format FileInfo
        // FltParseFileNameInformation(nameInfo);
        WCHAR swDirectPath[MAX_PATH] = { 0, };
        RtlCopyMemory(swDirectPath, nameInfo->Name.Buffer, nameInfo->Name.Length);
        if (!wcslen(swDirectPath))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        int iRuleMods = 0;
        const BOOLEAN bStatus = rDirectory_IsIpsDirectNameInList(swDirectPath, &iRuleMods);
        if (!iRuleMods || !bStatus)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        
        // 2. query processid to processpath
        WCHAR path[260 * 2] = { 0 };
        //const ULONG pid = FltGetRequestorProcessId(Data);
        const ULONG processid = (int)PsGetCurrentProcessId();
        if (!QueryProcessNamePath((DWORD)processid, path, sizeof(path)))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        
        do {
            // 3. find processpath to ruleName
            const BOOLEAN QueryIpsProcessStatus = rDirectory_IsIpsProcessNameInList(path, iRuleMods);
            const unsigned char IRP_MJ_CODE = Data->Iopb->MajorFunction;
            if (IRP_MJ_CODE == IRP_MJ_CREATE)
            {
                BOOLEAN bhitOpear = FALSE;
                // create file
                if (((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff) == FILE_CREATE ||
                    ((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff) == FILE_OPEN_IF ||
                    ((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff) == FILE_OVERWRITE_IF)
                {
                    bhitOpear = TRUE;
                }

                // move into folder
                if (Data->Iopb->OperationFlags == '\x05')
                    bhitOpear = TRUE;

                // 白名单模式: 进程不在白名单 - 不允许访问
                if (bhitOpear && (iRuleMods == 1) && !QueryIpsProcessStatus)
                    break;
                // 黑名单模式: 进程在黑名单 - 不允许访问
                else if (bhitOpear && (iRuleMods == 2) && QueryIpsProcessStatus)
                    break;
            }
            else if (IRP_MJ_CODE == IRP_MJ_SET_INFORMATION)
            {
                // delete file
                if (iRuleMods == 2 && Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
                    break;

                // rename file
                if (iRuleMods == 2 && Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
                    break;
            }
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        } while (FALSE);

        // ACTION BLOCK
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1!FsFilter1PostOperation: Entered\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FsFilterAntsDrPostFileHide(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    PWCHAR HideFileName = L"HideTest";

    DbgPrint("Entry function hide\n");
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PVOID Bufferptr = NULL;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (Data->Iopb->MinorFunction == IRP_MN_QUERY_DIRECTORY &&
        (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass == FileBothDirectoryInformation) &&
        Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length > 0 &&
        NT_SUCCESS(Data->IoStatus.Status))
    {
        if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
        {

            Bufferptr = MmGetSystemAddressForMdl(Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
                NormalPagePriority);
        }
        else
        {
            Bufferptr = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        }

        if (Bufferptr == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        PFILE_BOTH_DIR_INFORMATION Currentfileptr = (PFILE_BOTH_DIR_INFORMATION)Bufferptr;
        PFILE_BOTH_DIR_INFORMATION prefileptr = Currentfileptr;
        PFILE_BOTH_DIR_INFORMATION nextfileptr = 0;
        ULONG nextOffset = 0;
        if (Currentfileptr == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        int nModifyflag = 0;
        int removedAllEntries = 1;
        do {
            nextOffset = Currentfileptr->NextEntryOffset;

            nextfileptr = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)(Currentfileptr)+nextOffset);

            if ((prefileptr == Currentfileptr) &&
                (_wcsnicmp(Currentfileptr->FileName, HideFileName, wcslen(HideFileName)) == 0) &&
                (Currentfileptr->FileNameLength == 2)
                )
            {
                RtlCopyMemory(Currentfileptr->FileName, L".", 2);
                Currentfileptr->FileNameLength = 0;
                FltSetCallbackDataDirty(Data);
                return FLT_POSTOP_FINISHED_PROCESSING;
            }

            if (_wcsnicmp(Currentfileptr->FileName, HideFileName, wcslen(HideFileName)) == 0 &&
                (Currentfileptr->FileNameLength == 2)
                )
            {
                if (nextOffset == 0)
                    prefileptr->NextEntryOffset = 0;
                else
                    prefileptr->NextEntryOffset = (ULONG)((PCHAR)Currentfileptr - (PCHAR)prefileptr + nextOffset);
                nModifyflag = 1;
            }
            else
            {
                removedAllEntries = 0;
                prefileptr = Currentfileptr;
            }
            Currentfileptr = nextfileptr;

        } while (nextOffset != 0);

        if (nModifyflag)
        {
            if (removedAllEntries)
                Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
            else
                FltSetCallbackDataDirty(Data);
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
FsFilterAntsDrvPreExe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    DbgPrint("[MiniFilter]: Read\n");
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PAGED_CODE();
    __try {
        if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_EXECUTE)
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        /*
            DbPrint("access denied");
            Data->IoStatus.Status = STATUS_ACCESS_DENIED
            Data->Iostatus.information = 0;
            return FLT_PREOP_COMPLETE;
        */
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("NPPreRead EXCEPTION_EXECUTE_HANDLER\n");
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}