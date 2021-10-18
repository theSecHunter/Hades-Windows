#include "public.h"
#include "imagemod.h"

#include "devctrl.h"

static  BOOLEAN g_imagemod_monitor = FALSE;
static  KSPIN_LOCK g_imagemod_monitorlock = NULL;

static KSPIN_LOCK               g_imagemodlock = NULL;
static NPAGED_LOOKASIDE_LIST    g_imagemodList;
static IMAGEMODDATA             g_imagemodQueryhead;

void Process_NotifyImage(
	const UNICODE_STRING* FullImageName,
	HANDLE ProcessId, 
	IMAGE_INFO* ImageInfo)
{
	if (!g_imagemod_monitor)
		return;

	if ((!ProcessId) || ImageInfo->SystemModeImage)
		return;

	KLOCK_QUEUE_HANDLE lh;
	IMAGEMODINFO imagemodinfo;
	RtlSecureZeroMemory(&imagemodinfo,sizeof(IMAGEMODINFO));

	// Get ImageName
	//if (FullImageName->Length > 19 * sizeof(WCHAR)) {

	//	WCHAR* path = FullImageName->Buffer
	//		+ FullImageName->Length / sizeof(WCHAR)
	//		- 19;

	//}

	imagemodinfo.processid = (int)ProcessId;
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

	PsSetLoadImageNotifyRoutine(Process_NotifyImage);

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

	// Distable ProcessMon
	sl_lock(&g_imagemodQueryhead.imagemod_lock, &lh);

	while (!IsListEmpty(&g_imagemodQueryhead.imagemod_pending))
	{
		pData = RemoveHeadList(&g_imagemodQueryhead.imagemod_pending);
		sl_unlock(&lh);
		Imagemod_PacketFree(pData);
		pData = NULL;
		sl_lock(&g_imagemodQueryhead.imagemod_lock, &lh);
	}

	sl_unlock(&lh);
}

void Imagemod_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_imagemod_monitorlock, &lh);
	g_imagemod_monitor = code;
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
