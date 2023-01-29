#include "public.h"
#include "syssession.h"

#include "devctrl.h"


static  BOOLEAN					g_ses_monitor = FALSE;
static  KSPIN_LOCK				g_ses_monitorlock = 0;

static  BOOLEAN					g_ses_ips_monitor = FALSE;
static  KSPIN_LOCK				g_ses_ips_monitorlock = 0;

static	NPAGED_LOOKASIDE_LIST	g_sessionlist;
static	KSPIN_LOCK              g_sessionlock = 0;

static	SESSIONDATA				g_sessiondata;

static PVOID					g_handleobj = NULL;

NTSTATUS
Pio_NotifySession(
	_In_ PVOID SessionObject,
	_In_ PVOID IoObject,
	_In_ ULONG Event,
	_In_ PVOID Context,
	_In_reads_bytes_opt_(PayloadLength) PVOID NotificationPayload,
	_In_ ULONG PayloadLength
)
{
	UNREFERENCED_PARAMETER(SessionObject);
	UNREFERENCED_PARAMETER(IoObject);
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(NotificationPayload);
	UNREFERENCED_PARAMETER(PayloadLength);

	do 
	{
		if (FALSE == g_ses_monitor && FALSE == g_ses_ips_monitor)
			break;


		if (g_ses_ips_monitor)
		{
		}
		if (!g_ses_monitor)
			return STATUS_SUCCESS;
			

		IO_SESSION_STATE_INFORMATION iosession_info;
		RtlSecureZeroMemory(&iosession_info, sizeof(IO_SESSION_STATE_INFORMATION));
		if (SessionObject)
			IoGetContainerInformation(IoSessionStateInformation, SessionObject, &iosession_info, sizeof(IO_SESSION_STATE_INFORMATION));
		else
			break;

		SESSIONINFO sessioninfo;
		RtlSecureZeroMemory(&sessioninfo, sizeof(SESSIONINFO));

		sessioninfo.processid = (int)PsGetCurrentProcessId();
		sessioninfo.threadid = (int)PsGetCurrentThreadId();
		sessioninfo.evens = Event;
		memcpy(sessioninfo.iosessioninfo, &iosession_info, sizeof(IO_SESSION_STATE_INFORMATION));

		SESSIONBUFFER* const pSeBuffer = (SESSIONBUFFER*)Session_PacketAllocate(sizeof(SESSIONINFO));
		if (!pSeBuffer)
			break;

		pSeBuffer->dataLength = sizeof(SESSIONINFO);
		if (pSeBuffer->dataBuffer)
			memcpy(pSeBuffer->dataBuffer, &sessioninfo, sizeof(SESSIONINFO));

		KLOCK_QUEUE_HANDLE lh;
		sl_lock(&g_sessiondata.session_lock, &lh);
		InsertHeadList(&g_sessiondata.session_pending, &pSeBuffer->pEntry);
		sl_unlock(&lh);

		devctrl_pushinfo(NF_SESSION_INFO);

	} while (FALSE);

	return STATUS_SUCCESS;
}

NTSTATUS Session_Init(PDRIVER_OBJECT pDriverObject)
{
	sl_init(&g_ses_monitorlock);
	sl_init(&g_ses_ips_monitorlock);

	sl_init(&g_sessiondata.session_lock);
	InitializeListHead(&g_sessiondata.session_pending);

	ExInitializeNPagedLookasideList(
		&g_sessionlist,
		NULL,
		NULL,
		0,
		sizeof(SESSIONBUFFER),
		'SEMM',
		0
	);

	IO_SESSION_STATE_NOTIFICATION IoSessionNotify;
	RtlSecureZeroMemory(&IoSessionNotify, sizeof(IO_SESSION_STATE_NOTIFICATION));

	IoSessionNotify.Size = sizeof(IO_SESSION_STATE_NOTIFICATION);
	IoSessionNotify.Flags = 0;
	IoSessionNotify.Context = NULL;
	IoSessionNotify.IoObject = pDriverObject;
	IoSessionNotify.EventMask = IO_SESSION_STATE_ALL_EVENTS;

	// See: Available in Windows 7 and later versions of the Windows operating system.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregistercontainernotification
	IoRegisterContainerNotification(
		IoSessionStateNotification,
		(PIO_CONTAINER_NOTIFICATION_FUNCTION)Pio_NotifySession,
		&IoSessionNotify,
		sizeof(IoSessionNotify),
		&g_handleobj
	);

	return STATUS_SUCCESS;
}

void Session_Free(void)
{
	Session_Clean();
	ExDeleteNPagedLookasideList(&g_sessionlist);
	if (g_handleobj)
	{
		IoUnregisterContainerNotification(g_handleobj);
		g_handleobj = NULL;
	}
}

void Session_Clean(void)
{
	KLOCK_QUEUE_HANDLE lh;
	SESSIONBUFFER* pData = NULL;
	int lock_status = 0;

	try
	{
		sl_lock(&g_sessiondata.session_lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_sessiondata.session_pending))
		{
			pData = (SESSIONBUFFER*)RemoveHeadList(&g_sessiondata.session_pending);
			sl_unlock(&lh);
			lock_status = 0;
			Session_PacketFree(pData);
			pData = NULL;
			sl_lock(&g_sessiondata.session_lock, &lh);
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

void Session_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_ses_monitorlock, &lh);
	g_ses_monitor = code;
	sl_unlock(&lh);
}

void Session_SetIpsMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_ses_ips_monitorlock, &lh);
	g_ses_ips_monitor = code;
	sl_unlock(&lh);
}

SESSIONBUFFER* Session_PacketAllocate(int lens)
{
	SESSIONBUFFER* seionbuf = NULL;
	seionbuf = (SESSIONBUFFER*)ExAllocateFromNPagedLookasideList(&g_sessionlist);
	if (!seionbuf)
		return NULL;

	memset(seionbuf, 0, sizeof(SESSIONBUFFER));

	if (lens > 0)
	{
		seionbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, 'SEMM');
		if (!seionbuf->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_sessionlist, seionbuf);
			return FALSE;
		}
	}
	return seionbuf;
}

void Session_PacketFree(SESSIONBUFFER* packet)
{
	if (packet->dataBuffer)
	{
		free_np(packet->dataBuffer);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_sessionlist, packet);
}

SESSIONDATA* sessionctx_get()
{
	return &g_sessiondata;
}