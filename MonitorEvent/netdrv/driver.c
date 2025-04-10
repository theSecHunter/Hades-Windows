#include "public.h"
#include "driver.h"
#include "devctrl.h"
#include "datalinkctx.h"
#include "establishedctx.h"
#include "tcpctx.h"
#include "udpctx.h"
#include "callouts.h"

#include <fwpmk.h>

#include <in6addr.h>
#include <ip2string.h>
#include <stdlib.h>

DRIVER_INITIALIZE DriverEntry;
static PDEVICE_OBJECT g_deviceControl;
static HANDLE g_bfeStateSubscribeHandle = NULL;

UNICODE_STRING u_devicename;
UNICODE_STRING u_devicesyslink;

VOID VerifiExInitializeNPagedLookasideList(
	_Out_ PNPAGED_LOOKASIDE_LIST Lookaside,
	_In_opt_ PALLOCATE_FUNCTION Allocate,
	_In_opt_ PFREE_FUNCTION Free,
	_In_ ULONG Flags,
	_In_ SIZE_T Size,
	_In_ ULONG Tag,
	_In_ USHORT Depth
)
{
	UNREFERENCED_PARAMETER(Flags);
#if (NTDDI_VERSION >= NTDDI_WIN8)
	 ExInitializeNPagedLookasideList(
		Lookaside,
		Allocate,
		Free,
		POOL_NX_ALLOCATION,
		Size,
		Tag,
		Depth
	);
#else
	 ExInitializeNPagedLookasideList(
		Lookaside,
		Allocate,
		Free,
		0,
		Size,
		Tag,
		Depth
	);
#endif
}

PVOID VerifiMmGetSystemAddressForMdlSafe(
	_Inout_ PMDL Mdl,
	_In_    ULONG Priority
)
{
#if (NTDDI_VERSION >= NTDDI_WIN8)
	return  MmGetSystemAddressForMdlSafe(Mdl, Priority | MdlMappingNoExecute);
#else
	return  MmGetSystemAddressForMdlSafe(Mdl, Priority);
#endif
}

NTSTATUS driver_init(
	IN  PDRIVER_OBJECT  driverObject,
	IN  PUNICODE_STRING registryPath)
{
	UNREFERENCED_PARAMETER(registryPath);
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&u_devicename, L"\\Device\\HadesNetMonx");
	RtlInitUnicodeString(&u_devicesyslink, L"\\DosDevices\\HadesNetMonx");

	status = IoCreateDevice(driverObject,
		0,
		&u_devicename,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_deviceControl);
	if (!NT_SUCCESS(status)){
		return status;
	}

	g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;

	status = IoCreateSymbolicLink(&u_devicesyslink, &u_devicename);
	if(!NT_SUCCESS(status)){
		return status;
	}

	g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;
	g_deviceControl->Flags |= DO_DIRECT_IO;

	return status;
}

VOID driver_unload(IN PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	if (g_bfeStateSubscribeHandle)
	{
		FwpmBfeStateUnsubscribeChanges(g_bfeStateSubscribeHandle);
		g_bfeStateSubscribeHandle = NULL;
	}
	
	driver_free();

#ifdef _WPPTRACE
	WPP_CLEANUP(driverObject);
#endif
}

VOID NTAPI bfeStateCallback(
	IN OUT void* context,
	IN FWPM_SERVICE_STATE  newState
)
{
	UNREFERENCED_PARAMETER(context);

	if (newState == FWPM_SERVICE_RUNNING)
	{
		NTSTATUS status = callout_init(g_deviceControl);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"bfeStateCallback callouts_init failed, status=%x\n", status));
		}
	}
}

NTSTATUS DriverEntry(
	IN  PDRIVER_OBJECT  driverObject,
	IN  PUNICODE_STRING registryPath
)
{
	NTSTATUS nStatus = STATUS_SUCCESS;

	int i = 0;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		driverObject->MajorFunction[i] = (PDRIVER_DISPATCH)devctrl_dispatch;
	}

	driverObject->DriverUnload = driver_unload;

	do 
	{
		// Init driver 
		nStatus = driver_init(driverObject, registryPath);
		if (!NT_SUCCESS(nStatus))
		{
			return nStatus;
		}

		// Init dectrl 
		nStatus = devctrl_init();
		if (!NT_SUCCESS(nStatus))
		{
			if (g_deviceControl)
			{
				IoDeleteDevice(g_deviceControl);
				IoDeleteSymbolicLink(&u_devicesyslink);
				g_deviceControl = NULL;
			}
			devctrl_free();
			return nStatus;
		}

		// Init MAK Packet
		//status = datalinkctx_init();
		//if (!NT_SUCCESS(status))
		//{
		//	break;
		//}

		nStatus = establishedctx_init();
		if (!NT_SUCCESS(nStatus))
		{
			break;
		}

		nStatus = tcp_init();
		if (!NT_SUCCESS(nStatus))
		{
			break;
		}

		nStatus = udp_init();
		if (!NT_SUCCESS(nStatus))
		{
			break;
		}

		// Init WFP Callout
		if (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING)
		{
			nStatus = callout_init(g_deviceControl);
			if (!NT_SUCCESS(nStatus))
			{
				break;
			}
		}
		else
		{
			nStatus = FwpmBfeStateSubscribeChanges(
				g_deviceControl,
				bfeStateCallback,
				NULL,
				&g_bfeStateSubscribeHandle);
			if (!NT_SUCCESS(nStatus))
			{
				KdPrint((DPREFIX"FwpmBfeStateSubscribeChanges\n"));
				break;
			}
		}
		return nStatus;
	} while (FALSE);
	
	// ʧ��
	driver_free();
	return nStatus;
}

VOID driver_free()
{
	if (g_deviceControl)
	{
		IoDeleteSymbolicLink(&u_devicesyslink);
		IoDeleteDevice(g_deviceControl);
		g_deviceControl = NULL;
	}
	devctrl_setShutdown();
	devctrl_setmonitor(0);
	callout_free();
	devctrl_free();
	//datalinkctx_free();
	tcp_free();
	udp_free();
	establishedctx_free();
};
