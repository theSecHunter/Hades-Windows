#include "public.h"
#include "devctrl.h"
#include "process.h"
#include "thread.h"
#include "imagemod.h"

#include <ntddk.h>

#define NF_TCP_PACKET_BUF_SIZE 8192
#define NF_UDP_PACKET_BUF_SIZE 2 * 65536

static UNICODE_STRING g_devicename;
static UNICODE_STRING g_devicesyslink;
static PDEVICE_OBJECT g_deviceControl;

typedef struct _SHARED_MEMORY
{
    PMDL					mdl;
    PVOID					userVa;
    PVOID					kernelVa;
    UINT64					bufferLength;
} SHARED_MEMORY, * PSHARED_MEMORY;

static LIST_ENTRY               g_IoQueryHead;
static KSPIN_LOCK               g_IoQueryLock;
static NPAGED_LOOKASIDE_LIST    g_IoQueryList;
static PVOID			        g_ioThreadObject = NULL;
static KEVENT					g_ioThreadEvent;
static LIST_ENTRY				g_pendedIoRequests;
static BOOLEAN					g_shutdown = FALSE;
static BOOLEAN					g_monitorflag = FALSE;

static SHARED_MEMORY g_inBuf;
static SHARED_MEMORY g_outBuf;

typedef struct _NF_QUEUE_ENTRY
{
    LIST_ENTRY		entry;		// Linkage
    int				code;		// IO code
} NF_QUEUE_ENTRY, * PNF_QUEUE_ENTRY;

void devctrl_freeSharedMemory(PSHARED_MEMORY pSharedMemory)
{
	if (pSharedMemory->mdl)
	{
		__try
		{
			if (pSharedMemory->userVa)
			{
				MmUnmapLockedPages(pSharedMemory->userVa, pSharedMemory->mdl);
			}
			if (pSharedMemory->kernelVa)
			{
				MmUnmapLockedPages(pSharedMemory->kernelVa, pSharedMemory->mdl);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		MmFreePagesFromMdl(pSharedMemory->mdl);
		IoFreeMdl(pSharedMemory->mdl);

		memset(pSharedMemory, 0, sizeof(SHARED_MEMORY));
	}
}

NTSTATUS devctrl_createSharedMemory(PSHARED_MEMORY pSharedMemory, UINT64 len)
{
	PMDL  mdl;
	PVOID userVa = NULL;
	PVOID kernelVa = NULL;
	PHYSICAL_ADDRESS lowAddress;
	PHYSICAL_ADDRESS highAddress;

	memset(pSharedMemory, 0, sizeof(SHARED_MEMORY));

	lowAddress.QuadPart = 0;
	highAddress.QuadPart = 0xFFFFFFFFFFFFFFFF;

	mdl = MmAllocatePagesForMdl(lowAddress, highAddress, lowAddress, (SIZE_T)len);
	if (!mdl)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		kernelVa = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
		if (!kernelVa)
		{
			MmFreePagesFromMdl(mdl);
			IoFreeMdl(mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		//
		// The preferred way to map the buffer into user space
		//
		userVa = MmMapLockedPagesSpecifyCache(mdl,          // MDL
			UserMode,     // Mode
			MmCached,     // Caching
			NULL,         // Address
			FALSE,        // Bugcheck?
			HighPagePriority); // Priority
		if (!userVa)
		{
			MmUnmapLockedPages(kernelVa, mdl);
			MmFreePagesFromMdl(mdl);
			IoFreeMdl(mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	//
	// If we get NULL back, the request didn't work.
	// I'm thinkin' that's better than a bug check anyday.
	//
	if (!userVa || !kernelVa)
	{
		if (userVa)
		{
			MmUnmapLockedPages(userVa, mdl);
		}
		if (kernelVa)
		{
			MmUnmapLockedPages(kernelVa, mdl);
		}
		MmFreePagesFromMdl(mdl);
		IoFreeMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Return the allocated pointers
	//
	pSharedMemory->mdl = mdl;
	pSharedMemory->userVa = userVa;
	pSharedMemory->kernelVa = kernelVa;
	pSharedMemory->bufferLength = MmGetMdlByteCount(mdl);

	return STATUS_SUCCESS;
}

NTSTATUS devctrl_openMem(PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PVOID ioBuffer = NULL;
	ioBuffer = irp->AssociatedIrp.SystemBuffer;
	if (!ioBuffer)
	{
		ioBuffer = irp->UserBuffer;
	}
	ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (ioBuffer && (outputBufferLength >= sizeof(NF_BUFFERS)))
	{
		NTSTATUS 	status;

		for (;;)
		{
			if (!g_inBuf.mdl)
			{
				status = devctrl_createSharedMemory(&g_inBuf, NF_UDP_PACKET_BUF_SIZE * 50);
				if (!NT_SUCCESS(status))
				{
					break;
				}
			}

			if (!g_outBuf.mdl)
			{
				status = devctrl_createSharedMemory(&g_outBuf, NF_UDP_PACKET_BUF_SIZE * 2);
				if (!NT_SUCCESS(status))
				{
					break;
				}
			}

			status = STATUS_SUCCESS;

			break;
		}

		if (!NT_SUCCESS(status))
		{
			devctrl_freeSharedMemory(&g_inBuf);
			devctrl_freeSharedMemory(&g_outBuf);
		}
		else
		{
			PNF_BUFFERS pBuffers = (PNF_BUFFERS)ioBuffer;

			pBuffers->inBuf = (UINT64)g_inBuf.userVa;
			pBuffers->inBufLen = g_inBuf.bufferLength;
			pBuffers->outBuf = (UINT64)g_outBuf.userVa;
			pBuffers->outBufLen = g_outBuf.bufferLength;

			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(NF_BUFFERS);
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_SUCCESS;
		}
	}

	irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS devctrl_create(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	KLOCK_QUEUE_HANDLE lh;
	NTSTATUS 	status = STATUS_SUCCESS;
	HANDLE		pid = PsGetCurrentProcessId();

	UNREFERENCED_PARAMETER(irpSp);

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

VOID devctrl_cancelRead(IN PDEVICE_OBJECT deviceObject, IN PIRP irp)
{
	KLOCK_QUEUE_HANDLE lh;

	UNREFERENCED_PARAMETER(deviceObject);

	IoReleaseCancelSpinLock(irp->CancelIrql);

	sl_lock(&g_IoQueryLock, &lh);

	RemoveEntryList(&irp->Tail.Overlay.ListEntry);

	sl_unlock(&lh);

	irp->IoStatus.Status = STATUS_CANCELLED;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

ULONG devctrl_processRequest(ULONG bufferSize)
{
	PNF_DATA pData = (PNF_DATA)g_outBuf.kernelVa;

	if (bufferSize < (sizeof(NF_DATA) + pData->bufferSize - 1))
	{
		return 0;
	}

	switch (pData->code)
	{
	default:
		break;
	}
	return 0;
}

NTSTATUS devctrl_read(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;

	for (;;)
	{
		if (irp->MdlAddress == NULL)
		{
			KdPrint((DPREFIX"devctrl_read: NULL MDL address\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL ||
			irpSp->Parameters.Read.Length < sizeof(NF_READ_RESULT))
		{
			KdPrint((DPREFIX"devctrl_read: Invalid request\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		sl_lock(&g_IoQueryLock, &lh);

		IoSetCancelRoutine(irp, devctrl_cancelRead);

		if (irp->Cancel &&
			IoSetCancelRoutine(irp, NULL))
		{
			status = STATUS_CANCELLED;
		}
		else
		{
			// pending请求
			IoMarkIrpPending(irp);
			InsertTailList(&g_pendedIoRequests, &irp->Tail.Overlay.ListEntry);
			status = STATUS_PENDING;
		}

		sl_unlock(&lh);

		// 激活处理事件
		KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);

		break;
	}

	if (status != STATUS_PENDING)
	{
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}

NTSTATUS devctrl_write(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PNF_READ_RESULT pRes;
	ULONG bufferLength = irpSp->Parameters.Write.Length;

	pRes = (PNF_READ_RESULT)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
	if (!pRes || bufferLength < sizeof(NF_READ_RESULT))
	{
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		KdPrint((DPREFIX"devctrl_write invalid irp\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irp->IoStatus.Information = devctrl_processRequest((ULONG)pRes->length);
	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_close(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	KLOCK_QUEUE_HANDLE lh;
	NTSTATUS 	status = STATUS_SUCCESS;
	HANDLE		pid = PsGetCurrentProcessId();

	UNREFERENCED_PARAMETER(irpSp);

	devctrl_setMonitor(FALSE);
	Process_Clean();
	Thread_Clean();
	Imagemod_Clean();
	devctrl_clean();

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

VOID devctrl_clean()
{
	PNF_QUEUE_ENTRY pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_IoQueryLock, &lh);
	while (!IsListEmpty(&g_IoQueryHead))
	{
		pQuery = RemoveHeadList(&g_IoQueryHead);
		sl_unlock(&lh);

		ExFreeToNPagedLookasideList(&g_IoQueryList, pQuery);
		pQuery = NULL;
		sl_lock(&g_IoQueryLock, &lh);
	}
	sl_unlock(&lh);

	devctrl_freeSharedMemory(&g_inBuf);
	devctrl_freeSharedMemory(&g_outBuf);
}

VOID devctrl_free()
{
	if (g_deviceControl)
	{
		IoDeleteDevice(g_deviceControl);
		g_deviceControl = NULL;
		IoDeleteSymbolicLink(&g_devicesyslink);
	}
	devctrl_setShutdown();
	devctrl_setMonitor(FALSE);
	Process_Free();
	Thread_Free();
	Imagemod_Free();
}

VOID devctrl_setShutdown()
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);
	g_shutdown = TRUE;
	sl_unlock(&lh);
}

BOOLEAN	devctrl_isShutdown()
{
	BOOLEAN		res;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);
	res = g_shutdown;
	sl_unlock(&lh);

	return res;
}

VOID devctrl_setMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);
	g_monitorflag = code;
	sl_unlock(&lh);

	// estable monitor
	Process_SetMonitor(code);
	Thread_SetMonitor(code);
	Imagemod_SetMonitor(code);
}

NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp;
	irpSp = IoGetCurrentIrpStackLocation(irp);
	ASSERT(irpSp);

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_CREATE:
		return devctrl_create(irp, irpSp);

	case IRP_MJ_READ:
	{
		return devctrl_read(irp, irpSp);
	}

	case IRP_MJ_WRITE:
		return devctrl_write(irp, irpSp);

	case IRP_MJ_CLOSE:
	{
		return devctrl_close(irp, irpSp);
	}

	case IRP_MJ_DEVICE_CONTROL:
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case CTL_DEVCTRL_OPEN_SHAREMEM:
			return devctrl_openMem(DeviceObject, irp, irpSp);

		case CTL_DEVCTRL_ENABLE_MONITOR:
			devctrl_setMonitor(TRUE);
			break;
		case CTL_DEVCTRL_DISENTABLE_MONITOR:
			devctrl_setMonitor(FALSE);
			break;
		}
		break;
	default:
		break;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(NF_BUFFERS);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS devctrl_ioInit(PDRIVER_OBJECT DriverObject) {
	NTSTATUS status = STATUS_SUCCESS;

	// Create Device
	RtlInitUnicodeString(&g_devicename, L"\\Device\\KernelDark");
	RtlInitUnicodeString(&g_devicesyslink, L"\\DosDevices\\KernelDark");
	status = IoCreateDevice(
		DriverObject,
		0,
		&g_devicename,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_deviceControl);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;

	status = IoCreateSymbolicLink(&g_devicesyslink, &g_devicename);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;
	g_deviceControl->Flags |= DO_DIRECT_IO;

	InitializeListHead(&g_pendedIoRequests);
	InitializeListHead(&g_IoQueryHead);
	KeInitializeSpinLock(&g_IoQueryLock);

	ExInitializeNPagedLookasideList(
		&g_IoQueryList,
		NULL,
		NULL,
		0,
		sizeof(NF_QUEUE_ENTRY),
		'IOMM',
		0
	);

	HANDLE threadHandle;
	KeInitializeEvent(
		&g_ioThreadEvent,
		SynchronizationEvent,
		FALSE
	);

	status = PsCreateSystemThread(
		&threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		devctrl_ioThread,
		NULL
	);

	// if success callback
	if (NT_SUCCESS(status))
	{
		KPRIORITY priority = HIGH_PRIORITY;

		ZwSetInformationThread(threadHandle, ThreadPriority, &priority, sizeof(priority));

		status = ObReferenceObjectByHandle(
			threadHandle,
			0,
			NULL,
			KernelMode,
			&g_ioThreadObject,
			NULL
		);
		ASSERT(NT_SUCCESS(status));
	}
	return status;
}

void devctrl_ioThreadFree() {

	devctrl_clean();
	ExDeleteNPagedLookasideList(&g_IoQueryList);

	// clsoe process callback
	if (g_ioThreadObject) {
		// 标记卸载驱动-跳出循环
		KeSetEvent(&g_ioThreadObject, IO_NO_INCREMENT, FALSE);

		KeWaitForSingleObject(
			g_ioThreadObject,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		ObDereferenceObject(g_ioThreadObject);
		g_ioThreadObject = NULL;
	}

	return STATUS_SUCCESS;
}


/*
* pop
*/
NTSTATUS devctrl_popprocessinfo(UINT64* pOffset)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;
	PROCESSBUFFER* processbuffer = NULL;
	PROCESSDATA* processdata = NULL;
	PNF_DATA	pData;
	UINT64		dataSize = 0;
	ULONG		pPacketlens = 0;

	processdata = processctx_get();
	if (!processdata)
		return STATUS_UNSUCCESSFUL;

	sl_lock(&processdata->process_lock, &lh);

	while (!IsListEmpty(&processdata->process_pending))
	{
		processbuffer = (PROCESSBUFFER*)RemoveHeadList(&processdata->process_pending);

		pPacketlens = processbuffer->dataLength;

		dataSize = sizeof(NF_DATA) - 1 + pPacketlens;

		if ((g_inBuf.bufferLength - *pOffset - 1) < dataSize)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);

		pData->code = NF_PROCESS_INFO;
		pData->id = 1;
		pData->bufferSize = processbuffer->dataLength;

		if (processbuffer->dataBuffer) {
			memcpy(pData->buffer, processbuffer->dataBuffer, processbuffer->dataLength);
		}

		*pOffset += dataSize;

	}

	sl_unlock(&lh);

	if (processbuffer)
	{
		if (NT_SUCCESS(status))
		{
			Process_PacketFree(processbuffer);
		}
		else
		{
			sl_lock(&processdata->process_lock, &lh);
			InsertHeadList(&processdata->process_pending, &processbuffer->pEntry);
			sl_unlock(&lh);
		}
	}

}

NTSTATUS devctrl_popthreadinfo(UINT64* pOffset)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;
	THREADBUFFER* threadbuffer = NULL;
	THREADDATA* threaddata = NULL;
	PNF_DATA	pData;
	UINT64		dataSize = 0;
	ULONG		pPacketlens = 0;

	threaddata = threadctx_get();
	if (!threaddata)
		return STATUS_UNSUCCESSFUL;

	sl_lock(&threaddata->thread_lock, &lh);

	while (!IsListEmpty(&threaddata->thread_pending))
	{
		threadbuffer = (THREADBUFFER*)RemoveHeadList(&threaddata->thread_pending);

		pPacketlens = threadbuffer->dataLength;

		dataSize = sizeof(NF_DATA) - 1 + pPacketlens;

		if ((g_inBuf.bufferLength - *pOffset - 1) < dataSize)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);

		pData->code = NF_THREAD_INFO;
		pData->id = 1;
		pData->bufferSize = threadbuffer->dataLength;

		if (threadbuffer->dataBuffer) {
			memcpy(pData->buffer, threadbuffer->dataBuffer, threadbuffer->dataLength);
		}

		*pOffset += dataSize;

	}

	sl_unlock(&lh);

	if (threadbuffer)
	{
		if (NT_SUCCESS(status))
		{
			Thread_PacketFree(threadbuffer);
		}
		else
		{
			sl_lock(&threaddata->thread_lock, &lh);
			InsertHeadList(&threaddata->thread_pending, &threadbuffer->pEntry);
			sl_unlock(&lh);
		}
	}
}

NTSTATUS devctrl_popimagemodinfo(UINT64* pOffset)
{

}


UINT64 devctrl_fillBuffer()
{
	PNF_QUEUE_ENTRY	pEntry;
	UINT64		offset = 0;
	NTSTATUS	status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);

	while (!IsListEmpty(&g_IoQueryHead))
	{
		pEntry = (PNF_QUEUE_ENTRY)RemoveHeadList(&g_IoQueryHead);

		sl_unlock(&lh);

		switch (pEntry->code)
		{
		case NF_PROCESS_INFO:
		{
			status = devctrl_popprocessinfo(&offset);
		}
		break;
		case NF_THREAD_INFO:
		{
			status = devctrl_popthreadinfo(&offset);
		}
		break;
		default:
			ASSERT(0);
			status = STATUS_SUCCESS;
		}

		sl_lock(&g_IoQueryLock, &lh);

		if (!NT_SUCCESS(status))
		{
			InsertHeadList(&g_IoQueryHead, &pEntry->entry);
			break;
		}

		ExFreeToNPagedLookasideList(&g_IoQueryList, pEntry);
	}

	sl_unlock(&lh);
	return offset;
}

void devctrl_serviceReads()
{
	PIRP                irp = NULL;
	PLIST_ENTRY         pIrpEntry;
	BOOLEAN             foundPendingIrp = FALSE;
	PNF_READ_RESULT		pResult;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);

	if (IsListEmpty(&g_pendedIoRequests) || IsListEmpty(&g_IoQueryHead))
	{
		sl_unlock(&lh);
		return;
	}

	pIrpEntry = g_pendedIoRequests.Flink;
	while (pIrpEntry != &g_pendedIoRequests)
	{
		irp = CONTAINING_RECORD(pIrpEntry, IRP, Tail.Overlay.ListEntry);

		if (IoSetCancelRoutine(irp, NULL))
		{
			// 移除
			RemoveEntryList(pIrpEntry);
			foundPendingIrp = TRUE;
			break;
		}
		else
		{
			KdPrint((DPREFIX"devctrl_serviceReads: skipping cancelled IRP\n"));
			pIrpEntry = pIrpEntry->Flink;
		}
	}

	sl_unlock(&lh);

	if (!foundPendingIrp)
	{
		return;
	}

	pResult = (PNF_READ_RESULT)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
	if (!pResult)
	{
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return;
	}

	pResult->length = devctrl_fillBuffer();

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(NF_READ_RESULT);
	IoCompleteRequest(irp, IO_NO_INCREMENT);

}

void devctrl_ioThread(void* StartContext)
{
	KLOCK_QUEUE_HANDLE lh;
	PLIST_ENTRY	pEntry;

	for (;;)
	{
		// handler io packter
		KeWaitForSingleObject(
			&g_ioThreadEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		// if shutdown
		if (devctrl_isShutdown())
		{
			break;
		}

		// dispathMsghandle
		devctrl_serviceReads();

	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}


/*
* push 
*/
void devctrl_pushinfo(int code)
{
	NTSTATUS status = STATUS_SUCCESS;
	PNF_QUEUE_ENTRY pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;

	switch (code)
	{
	case NF_PROCESS_INFO:
	case NF_THREAD_INFO:
	case NF_IMAGEMODE_INFO:
	{
		pQuery = (PNF_QUEUE_ENTRY)ExAllocateFromNPagedLookasideList(&g_IoQueryList);
		if (!pQuery)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		pQuery->code = code;
		sl_lock(&g_IoQueryLock, &lh);
		InsertHeadList(&g_IoQueryHead, &pQuery->entry);
		sl_unlock(&lh);
	}
	break;
	default:
		break;
	}
	// keSetEvent
	KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);
	return status;
}