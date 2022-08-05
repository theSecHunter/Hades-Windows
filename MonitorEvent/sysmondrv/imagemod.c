#include "public.h"
#include "imagemod.h"

#include "devctrl.h"

static  BOOLEAN g_imagemod_monitor = FALSE;
static  KSPIN_LOCK g_imagemod_monitorlock = NULL;
static  BOOLEAN g_imagemod_ips_monitor = FALSE;
static  KSPIN_LOCK g_imagemod_ips_monitorlock = NULL;

static KSPIN_LOCK               g_imagemodlock = NULL;
static NPAGED_LOOKASIDE_LIST    g_imagemodList;
static IMAGEMODDATA             g_imagemodQueryhead;

#define STACK_WALK_WEIGHT 20
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
NTKERNELAPI
	NTSTATUS
	NTAPI
	ZwQueryInformationProcess(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	);
typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;
typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;
typedef struct _PS_PROTECTION {
	union {
		UCHAR Level;
		struct {
			UCHAR Type : 3;
			UCHAR Audit : 1;                  // Reserved
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;

//bool CheckProcessProtect() {
//	PS_PROTECTION ProtectInfo = { 0 };
//	NTSTATUS ntStatus = ZwQueryInformationProcess(NtCurrentProcess(), ProcessProtectionInformation, &ProtectInfo, sizeof(ProtectInfo), 0ull);
//	bool Result1 = false;
//	bool Result2 = false;
//	if (NT_SUCCESS(ntStatus)) {
//		Result1 = ProtectInfo.Type == PsProtectedTypeNone && ProtectInfo.Signer == PsProtectedSignerNone;
//		PROCESS_EXTENDED_BASIC_INFORMATION ProcessExtenedInfo = { 0 };
//		ntStatus = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &ProcessExtenedInfo, sizeof(ProcessExtenedInfo), 0ull);
//		if (NT_SUCCESS(ntStatus)) {
//			Result2 = ProcessExtenedInfo.IsProtectedProcess == false && ProcessExtenedInfo.IsSecureProcess == false;
//		}
//	}
//	return Result2 && Result1;
//}
//
//bool CheckStackVAD(PVOID pAddress) {
//	bool bResult = false;
//	size_t iReturnlength;
//	MEMORY_BASIC_INFORMATION MemoryInfomation[sizeof(MEMORY_BASIC_INFORMATION)] = { 0 };
//	if (MemoryInfomation) {
//		NTSTATUS nt_status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)pAddress, MemoryBasicInformation, MemoryInfomation, sizeof(MEMORY_BASIC_INFORMATION), &iReturnlength);
//		if (NT_SUCCESS(nt_status)) {
//			bool is_map_memory = (MemoryInfomation->Type == MEM_PRIVATE || MemoryInfomation->Type == MEM_MAPPED) && MemoryInfomation->State == MEM_COMMIT;
//			bResult = is_map_memory &&
//				(MemoryInfomation->Protect == PAGE_EXECUTE || MemoryInfomation->Protect == PAGE_EXECUTE_READWRITE ||
//					MemoryInfomation->Protect == PAGE_EXECUTE_READ || MemoryInfomation->Protect == PAGE_EXECUTE_WRITECOPY);
//			if (bResult) {
//				DebugPrint("MemoryInfomation->Protect %08X MemoryInfomation->Type %08X \n", MemoryInfomation->Protect, MemoryInfomation->Type);
//			}
//		}
//	}
//	return bResult;
//}
//
//bool WalkStack(int pHeight)
//{
//	bool bResult = true;
//	PVOID dwStackWalkAddress[STACK_WALK_WEIGHT] = { 0 };
//	unsigned __int64  iWalkChainCount = RtlWalkFrameChain(dwStackWalkAddress, STACK_WALK_WEIGHT, 1);
//	int iWalkLimit = 0;
//	for (unsigned __int64 i = iWalkChainCount; i > 0; i--)
//	{
//		if (iWalkLimit > pHeight)
//			break;
//		iWalkLimit++;
//		if (CheckStackVAD((PVOID)dwStackWalkAddress[i])) {
//			DebugPrint("height: %d address %p \n", i, dwStackWalkAddress[i]);
//			bResult = false;
//			break;
//		}
//	}
//	return bResult;
//}

void Process_NotifyImage(
	const UNICODE_STRING* FullImageName,
	HANDLE ProcessId, 
	IMAGE_INFO* ImageInfo)
{
	if (!g_imagemod_monitor && !g_imagemod_ips_monitor)
		return;

	if (!ImageInfo)
		return;

	if (g_imagemod_ips_monitor && PsGetCurrentProcessId() != (HANDLE)4 && PsGetCurrentProcessId() != (HANDLE)0) {
		//if (WalkStack(10) == false) {

		//	DebugPrint("[!!!] CobaltStrike Shellcode Detected Process Name: %s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));
		//	//ZwTerminateProcess(NtCurrentProcess(), 0);
		//}
	}
	if (!g_imagemod_monitor)
		return;

	KLOCK_QUEUE_HANDLE lh;
	IMAGEMODINFO imagemodinfo;
	RtlSecureZeroMemory(&imagemodinfo,sizeof(IMAGEMODINFO));

	imagemodinfo.processid = (int)ProcessId;
	imagemodinfo.systemmodeimage = ImageInfo->SystemModeImage;
	imagemodinfo.imagebase = (__int64)ImageInfo->ImageBase;
	imagemodinfo.imagesize = (__int64)ImageInfo->ImageSize;
	memcpy(imagemodinfo.imagename, FullImageName->Buffer, FullImageName->Length);

	PIMAGEMODBUFFER pimagebuf = NULL;
	pimagebuf = Imagemod_PacketAllocate(sizeof(IMAGEMODINFO));
	if (!pimagebuf)
		return;


	pimagebuf->dataLength = sizeof(IMAGEMODINFO);
	memcpy(pimagebuf->dataBuffer, &imagemodinfo, sizeof(IMAGEMODINFO));

	sl_lock(&g_imagemodQueryhead.imagemod_lock, &lh);
	InsertHeadList(&g_imagemodQueryhead.imagemod_pending, &pimagebuf->pEntry);
	sl_unlock(&lh);

	devctrl_pushinfo(NF_IMAGEMODE_INFO);
}

NTSTATUS Imagemod_Init(void)
{
	sl_init(&g_imagemod_monitorlock);
	sl_init(&g_imagemod_ips_monitorlock);

	sl_init(&g_imagemodlock);
	ExInitializeNPagedLookasideList(
		&g_imagemodList,
		NULL,
		NULL,
		0,
		sizeof(IMAGEMODBUFFER),
		'IMMM',
		0
	);
	
	sl_init(&g_imagemodQueryhead.imagemod_lock);
	InitializeListHead(&g_imagemodQueryhead.imagemod_pending);

	// See: Available starting with Windows 2000.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine
	PsSetLoadImageNotifyRoutine(Process_NotifyImage);
	return STATUS_SUCCESS;
}

void Imagemod_Free(void)
{
	Imagemod_Clean();
	ExDeleteNPagedLookasideList(&g_imagemodList);
	PsRemoveLoadImageNotifyRoutine(Process_NotifyImage);
}

void Imagemod_Clean(void)
{
	KLOCK_QUEUE_HANDLE lh;
	IMAGEMODBUFFER* pData = NULL;
	int lock_status = 0;

	try {
		// Distable ProcessMon
		sl_lock(&g_imagemodQueryhead.imagemod_lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_imagemodQueryhead.imagemod_pending))
		{
			pData = RemoveHeadList(&g_imagemodQueryhead.imagemod_pending);
			sl_unlock(&lh);
			lock_status = 0;
			Imagemod_PacketFree(pData);
			pData = NULL;
			sl_lock(&g_imagemodQueryhead.imagemod_lock, &lh);
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

void Imagemod_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_imagemod_monitorlock, &lh);
	g_imagemod_monitor = code;
	sl_unlock(&lh);
}

void Imagemod_SetIpsMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_imagemod_ips_monitorlock, &lh);
	g_imagemod_ips_monitor = code;
	sl_unlock(&lh);
}

IMAGEMODBUFFER* Imagemod_PacketAllocate(int lens)
{
	IMAGEMODBUFFER* imagebuf = NULL;
	imagebuf = (IMAGEMODBUFFER*)ExAllocateFromNPagedLookasideList(&g_imagemodList);
	if (!imagebuf)
		return NULL;

	memset(imagebuf, 0, sizeof(IMAGEMODBUFFER));

	if (lens > 0)
	{
		imagebuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, 'IMMM');
		if (!imagebuf->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_imagemodList, imagebuf);
			return FALSE;
		}
	}
	return imagebuf;
}

void Imagemod_PacketFree(IMAGEMODBUFFER* packet)
{
	if (packet->dataBuffer)
	{
		free_np(packet->dataBuffer);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_imagemodList, packet);
}

IMAGEMODDATA* imagemodctx_get()
{
	return &g_imagemodQueryhead;
}
