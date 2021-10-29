#include "public.h"
#include "syswmi.h"


#include "devctrl.h"

#include <wmistr.h>
#include <wmiguid.h>

static  BOOLEAN					g_wmi_monitor = FALSE;
static  KSPIN_LOCK				g_wmi_monitorlock = NULL;

static	KSPIN_LOCK              g_wmilock = NULL;
static	NPAGED_LOOKASIDE_LIST	g_wmilist;

static	WMIDATA					g_wmidata;

static  PVOID					g_smbioshandobj = NULL;
static  PVOID					g_prochandobj = NULL;

enum WMICODE
{

};

VOID Sys_NotifyWmi(
	PVOID Wnode,
	PVOID Context
)
{
	UNREFERENCED_PARAMETER(Context);
	if (FALSE == g_wmi_monitor)
		return;

	WNODE_EVENT_ITEM* wnode = NULL;
	if (Wnode)
		wnode = (WNODE_EVENT_ITEM*)Wnode;
	else
		return;

	wnode->WnodeHeader.Guid;
	wnode->WnodeHeader.Version;
}


NTSTATUS Wmi_Init()
{
	sl_init(&g_wmi_monitor);
	sl_init(&g_wmi_monitorlock);

	sl_init(&g_wmidata.wmi_lock);
	InitializeListHead(&g_wmidata.wmi_pending);

	ExInitializeNPagedLookasideList(
		&g_wmilist,
		NULL,
		NULL,
		0,
		sizeof(WMIBUFFER),
		'REMM',
		0
	);

	NTSTATUS status = STATUS_SUCCESS;

	/*
		WMI See Gui: https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page

	*/
	GUID smbios = SMBIOS_DATA_GUID;

	// See: Available in Windows XP and later versions
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmisetnotificationcallback
	status = IoWMIOpenBlock(&smbios, 0x0004/*WMIGUID_NOTIFICATION*/, &g_smbioshandobj);
	if (NT_SUCCESS(status))
	{
		// See: Available in Windows XP and later versions
		// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmisetnotificationcallback
		if (g_smbioshandobj)
			IoWMISetNotificationCallback(g_smbioshandobj, Sys_NotifyWmi, NULL);
	}

	// smbios = "Win32_Process";
	//status = IoWMIOpenBlock(&smbios, 0x0004/*WMIGUID_NOTIFICATION*/, &g_prochandobj);
	//if (NT_SUCCESS(status))
	//{
	//	if (g_prochandobj)
	//		IoWMISetNotificationCallback(g_prochandobj, Sys_NotifyWmi, NULL);
	//}


	return STATUS_SUCCESS;
}

void Wmi_Free(void)
{
	Wmi_Clean();
	ExDeleteNPagedLookasideList(&g_wmilist);
}

void Wmi_Clean(void)
{
	KLOCK_QUEUE_HANDLE lh;
	WMIBUFFER* pData = NULL;

	sl_lock(&g_wmidata.wmi_lock, &lh);

	while (!IsListEmpty(&g_wmidata.wmi_pending))
	{
		pData = (WMIBUFFER*)RemoveHeadList(&g_wmidata.wmi_pending);
		sl_unlock(&lh);
		Wmi_PacketFree(pData);
		pData = NULL;
		sl_lock(&g_wmidata.wmi_lock, &lh);
	}

	sl_unlock(&lh);
}

void Wmi_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_wmi_monitorlock, &lh);
	g_wmi_monitor = code;
	sl_unlock(&lh);
}

WMIBUFFER* Wmi_PacketAllocate(int lens)
{
	WMIBUFFER* wmibuf = NULL;
	wmibuf = (WMIBUFFER*)ExAllocateFromNPagedLookasideList(&g_wmilist);
	if (!wmibuf)
		return NULL;

	memset(wmibuf, 0, sizeof(WMIBUFFER));

	if (lens > 0)
	{
		wmibuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, 'WMMM');
		if (!wmibuf->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_wmilist, wmibuf);
			return FALSE;
		}
	}
	return wmibuf;
}

void Wmi_PacketFree(WMIBUFFER* packet)
{
	if (packet->dataBuffer)
	{
		free_np(packet->dataBuffer);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_wmilist, packet);
}

WMIDATA* wmictx_get()
{
	return &g_wmidata;
}