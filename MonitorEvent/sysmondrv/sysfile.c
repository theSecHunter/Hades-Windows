#include "public.h"
#include "sysfile.h"

#include "devctrl.h"

static  BOOLEAN					g_file_monitor = FALSE;
static  KSPIN_LOCK				g_file_monitorlock = 0;

static	NPAGED_LOOKASIDE_LIST	g_filelist;
static	KSPIN_LOCK              g_filelock = 0;

static	FILEDATA				g_filedata;

static  PVOID					g_handleobj = NULL;

OB_PREOP_CALLBACK_STATUS preNotifyCall(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (FALSE == g_file_monitor)
		return OB_PREOP_SUCCESS;

	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle
	if (!OperationInformation || (OperationInformation->ObjectType != *IoFileObjectType))
		return OB_PREOP_SUCCESS;

	UNICODE_STRING DosName;
	RtlInitUnicodeString(&DosName, L"");

	PFILE_OBJECT fileo = OperationInformation->Object;
	if (fileo->FileName.Buffer == NULL ||
		!MmIsAddressValid(fileo->FileName.Buffer) ||
		fileo->DeviceObject == NULL ||
		!MmIsAddressValid(fileo->DeviceObject))
		return OB_PREOP_SUCCESS;
	
	if (!_wcsicmp(fileo->FileName.Buffer, L"\\Endpoint") ||
		!_wcsicmp(fileo->FileName.Buffer, L"?") ||
		!_wcsicmp(fileo->FileName.Buffer, L"\\.\\.") ||
		!_wcsicmp(fileo->FileName.Buffer, L"\\"))
		return OB_PREOP_SUCCESS;

	FILEINFO fileinfo;
	RtlSecureZeroMemory(&fileinfo, sizeof(FILEINFO));
	fileinfo.processid = (int)PsGetCurrentProcessId();
	fileinfo.threadid = (int)PsGetCurrentThreadId();

	fileinfo.LockOperation = fileo->LockOperation;
	fileinfo.DeletePending = fileo->DeletePending;
	fileinfo.ReadAccess = fileo->ReadAccess;
	fileinfo.WriteAccess = fileo->WriteAccess;
	fileinfo.DeleteAccess = fileo->DeleteAccess;
	fileinfo.SharedRead = fileo->SharedRead;
	fileinfo.SharedWrite = fileo->SharedWrite;
	fileinfo.SharedDelete = fileo->SharedDelete;
	fileinfo.flag = fileo->Flags;

	if (0 >= fileo->FileName.Length)
		return OB_PREOP_SUCCESS;
	memcpy(fileinfo.FileName, fileo->FileName.Buffer, fileo->FileName.Length);

	// Obsolete for Microsoft Windows XP and later versions of Windows
	RtlVolumeDeviceToDosName(fileo->DeviceObject, &DosName);
	if(DosName.Length)
		memcpy(fileinfo.DosName, DosName.Buffer, DosName.Length);

	KLOCK_QUEUE_HANDLE lh;
	FILEBUFFER* filebuf = NULL;

	filebuf = (FILEBUFFER*)File_PacketAllocate(sizeof(FILEINFO));
	if (!filebuf)
		return OB_PREOP_SUCCESS;

	filebuf->dataLength = sizeof(FILEINFO);
	if (filebuf->dataBuffer)
	{
		memcpy(filebuf->dataBuffer, &fileinfo, sizeof(FILEINFO));
	}

	sl_lock(&g_filedata.file_lock, &lh);
	InsertHeadList(&g_filedata.file_pending, &filebuf->pEntry);
	sl_unlock(&lh);

	devctrl_pushinfo(NF_FILE_INFO);

	return OB_PREOP_SUCCESS;
}

NTSTATUS File_Init(PDRIVER_OBJECT pDriverObject)
{
	// ÉèÖÃDriverSectionLdr
	PLDR_DATA_TABLE_ENTRY64 ldr = NULL;
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObject->DriverSection;
	ldr->Flags |= 0x20;

	sl_init(&g_filelock);
	sl_init(&g_file_monitorlock);

	sl_init(&g_filedata.file_lock);
	InitializeListHead(&g_filedata.file_pending);

	VerifiExInitializeNPagedLookasideList(
		&g_filelist,
		NULL,
		NULL,
		0,
		sizeof(FILEBUFFER),
		'REMM',
		0
	);

	// Set type callout
	POBJECT_TYPE_TEMP  ObjectTypeTemp = (POBJECT_TYPE_TEMP)*IoFileObjectType;
	if (ObjectTypeTemp)
		ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"filemon");

	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = IoFileObjectType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preNotifyCall;
	obReg.OperationRegistration = &opReg;

	// See: Available starting with Windows Vista with Service Pack 1 (SP1) and Windows Server 2008.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
	NTSTATUS status = ObRegisterCallbacks(&obReg, &g_handleobj);
	return STATUS_SUCCESS;
}

void File_Free(void)
{
	File_Clean();
	ExDeleteNPagedLookasideList(&g_filelist);
	if (g_handleobj)
		ObUnRegisterCallbacks(g_handleobj);
}

void File_Clean(void)
{
	KLOCK_QUEUE_HANDLE lh;
	FILEBUFFER* pData = NULL;
	int lock_status = 0;

	try
	{
		sl_lock(&g_filedata.file_lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_filedata.file_pending))
		{
			pData = (FILEBUFFER*)RemoveHeadList(&g_filedata.file_pending);
			sl_unlock(&lh);
			lock_status = 0;
			File_PacketFree(pData);
			pData = NULL;
			sl_lock(&g_filedata.file_lock, &lh);
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

void File_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_file_monitorlock, &lh);
	g_file_monitor = code;
	sl_unlock(&lh);
}

FILEBUFFER* File_PacketAllocate(int lens)
{
	FILEBUFFER* filebuf = NULL;
	filebuf = (FILEBUFFER*)ExAllocateFromNPagedLookasideList(&g_filelist);
	if (!filebuf)
		return NULL;

	memset(filebuf, 0, sizeof(FILEBUFFER));

	if (lens > 0)
	{
		filebuf->dataBuffer = (char*)VerifiExAllocatePoolTag(lens, 'FLMM');
		if (!filebuf->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_filelist, filebuf);
			return FALSE;
		}
	}
	return filebuf;
}

void File_PacketFree(FILEBUFFER* packet)
{
	if (packet->dataBuffer)
	{
		free_np(packet->dataBuffer);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_filelist, packet);
}

FILEDATA* filectx_get()
{
	return &g_filedata;
}