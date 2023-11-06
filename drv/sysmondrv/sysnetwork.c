#include "public.h"
#include "sysnetwork.h"

#define IOCTL_NSI_GETALLPARAM 0x12001B

NTSTATUS GetObjectByName(
	HANDLE* pFileHandle,
	OUT PFILE_OBJECT* FileObject,
	IN WCHAR* DeviceName
)
{
	UNICODE_STRING		deviceTCPUnicodeString;
	OBJECT_ATTRIBUTES	TCP_object_attr;
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK		IoStatus;
	HANDLE				FileHandle = NULL;

	if (!FileObject ||
		!DeviceName)
	{
		return status;
	}

	RtlInitUnicodeString(&deviceTCPUnicodeString, DeviceName);

	InitializeObjectAttributes(&TCP_object_attr,
		&deviceTCPUnicodeString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		0,
		0
	);

	status = ZwCreateFile(
		&FileHandle,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&TCP_object_attr,
		&IoStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		0,
		0
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to open"));
		return STATUS_UNSUCCESSFUL;
	}

	 status = ObReferenceObjectByHandle(
		 FileHandle,
		 FILE_ANY_ACCESS,
		 *IoFileObjectType,
		 KernelMode,
		 (PVOID*)FileObject,
		 NULL
	 );

	if (pFileHandle)
	{
		*pFileHandle = FileHandle;
	}

	return status;
}

int nf_GetNetworkIpProcessInfo(
	PSYSNETWORKINFONODE pBuffer
)
{
	PIRP						pIrp = NULL;
	KEVENT						Event;
	NTSTATUS					statu = STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT				pDeviceObject = NULL;
	PFILE_OBJECT				FileObj = NULL;
	UNICODE_STRING				NsiDeviceName;
	IO_STATUS_BLOCK				StatusBlock;
	PIO_STACK_LOCATION			StackLocation = NULL;
	PINTERNAL_TCP_TABLE_ENTRY	pBuf1 = NULL;
	PNSI_STATUS_ENTRY			pBuf2 = NULL;
	PNSI_PROCESSID_INFO			pBuf3 = NULL;
	PINTERNAL_UDP_TABLE_ENTRY	pBuf4 = NULL;
	PNSI_PROCESSID_INFO			pBuf5 = NULL;
	HANDLE						hFile = NULL;
	NTSTATUS					ob1 = STATUS_UNSUCCESSFUL;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	RtlInitUnicodeString(&NsiDeviceName, L"\\Device\\Nsi");

	statu = IoGetDeviceObjectPointer(
		&NsiDeviceName,
		FILE_ALL_ACCESS,
		&FileObj,
		&pDeviceObject
	);
	if (!NT_SUCCESS(statu))
		return -1;

	NSI_PARAM paramTcp, paramUdp;
	RtlSecureZeroMemory(&paramTcp, sizeof(NSI_PARAM));
	RtlSecureZeroMemory(&paramUdp, sizeof(NSI_PARAM));

	unsigned char NPI_MS_TCP_MODULEID[24] = {
		0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
		0x03,0x4a,0x00,0xeb,0x1a,0x9b,0xd4,0x11,
		0x91,0x23,0x00,0x50,0x04,0x77,0x59,0xbc,
	};

	unsigned char NPI_MS_UDP_MODULEID[24] = {
		0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
		0x02,0x4a,0x00,0xeb,0x1a,0x9b,0xd4,0x11,
		0x91,0x23,0x00,0x50,0x04,0x77,0x59,0xbc,
	};

	paramTcp.UnknownParam3 = (ULONG_PTR)&NPI_MS_TCP_MODULEID;
	paramTcp.UnknownParam4 = 0x3;
	paramTcp.UnknownParam5 = 0x100000001;

	paramUdp.UnknownParam3 = (ULONG_PTR)&NPI_MS_UDP_MODULEID;
	paramUdp.UnknownParam4 = 0x1;
	paramUdp.UnknownParam5 = 0x100000001;

	do
	{
		/*
			Tdp -------------------------------
		*/
		pIrp = IoBuildDeviceIoControlRequest(
			IOCTL_NSI_GETALLPARAM,
			pDeviceObject,
			&paramTcp,
			sizeof(NSI_PARAM),
			&paramTcp,
			sizeof(NSI_PARAM),
			FALSE,
			&Event,
			&StatusBlock
		);

		if (!pIrp)
		{
			statu = STATUS_UNSUCCESSFUL;
			break;
		}

		StackLocation = IoGetNextIrpStackLocation(pIrp);
		StackLocation->FileObject = FileObj;
		StackLocation->DeviceObject = pDeviceObject;
		pIrp->RequestorMode = KernelMode;

		statu = IoCallDriver(pDeviceObject, pIrp);
		if (STATUS_PENDING == statu)
		{
			statu = KeWaitForSingleObject(
				&Event,
				Executive,
				KernelMode,
				FALSE,
				0
			);
		}
		if (!NT_SUCCESS(statu))
			break;

		ULONG_PTR Count = paramTcp.ConnCount + 2;
		pBuf1 = (PINTERNAL_TCP_TABLE_ENTRY)ExAllocatePoolWithTag(NonPagedPool, 0x38 * Count, 'TCMM');
		pBuf2 = (PNSI_STATUS_ENTRY)ExAllocatePoolWithTag(NonPagedPool, 0x10 * Count, 'TCMM');
		pBuf3 = (PNSI_PROCESSID_INFO)ExAllocatePoolWithTag(NonPagedPool, 0x20 * Count, 'TCMM');
		if (!pBuf1 || !pBuf2 || !pBuf3)
		{
			return -1;
		}

		RtlZeroMemory(pBuf1, 0x38 * Count);
		RtlZeroMemory(pBuf2, 0x10 * Count);
		RtlZeroMemory(pBuf3, 0x20 * Count);

		RtlSecureZeroMemory(&paramTcp, sizeof(NSI_PARAM));
		paramTcp.UnknownParam3 = (ULONG_PTR)&NPI_MS_TCP_MODULEID;
		paramTcp.UnknownParam4 = 0x3;
		paramTcp.UnknownParam5 = 0x100000001;
		paramTcp.UnknownParam6 = (ULONG_PTR)pBuf1;
		paramTcp.UnknownParam7 = 0x38;
		paramTcp.UnknownParam10 = (ULONG_PTR)pBuf2;
		paramTcp.UnknownParam11 = 0x10;
		paramTcp.UnknownParam12 = (ULONG_PTR)pBuf3;
		paramTcp.UnknownParam13 = 0x20;
		paramTcp.ConnCount = Count - 2;

		pIrp = IoBuildDeviceIoControlRequest(
			IOCTL_NSI_GETALLPARAM,
			pDeviceObject,
			&paramTcp,
			sizeof(NSI_PARAM),
			&paramTcp,
			sizeof(NSI_PARAM),
			FALSE,
			&Event,
			&StatusBlock
		);
		if (!pIrp)
			break;

		StackLocation = IoGetNextIrpStackLocation(pIrp);
		StackLocation->FileObject = FileObj;
		StackLocation->DeviceObject = pDeviceObject;
		pIrp->RequestorMode = KernelMode;

		statu = IoCallDriver(pDeviceObject, pIrp);
		if (STATUS_PENDING == statu)
		{
			statu = KeWaitForSingleObject(
				&Event,
				Executive,
				KernelMode,
				FALSE,
				0
			);
		}
		if (!NT_SUCCESS(statu))
			break;

		pBuffer->tcpcout = paramTcp.ConnCount;
		// TCP Data
		for (ULONG i = 0; i < paramTcp.ConnCount; i++)
		{
			RtlCopyMemory(&pBuffer->systcpinfo[i].socketStatus, &pBuf2[i], sizeof(NSI_STATUS_ENTRY));
			RtlCopyMemory(&pBuffer->systcpinfo[i].processinfo, &pBuf3[i], sizeof(PNSI_PROCESSID_INFO));
			RtlCopyMemory(&pBuffer->systcpinfo[i].TpcTable, &pBuf1[i], sizeof(INTERNAL_TCP_TABLE_ENTRY));
		}

		/*
			Udp -------------------------------
		*/
		pIrp = IoBuildDeviceIoControlRequest(
			IOCTL_NSI_GETALLPARAM,
			pDeviceObject,
			&paramUdp,
			sizeof(NSI_PARAM),
			&paramUdp,
			sizeof(NSI_PARAM),
			FALSE,
			&Event,
			&StatusBlock
		);

		if (!pIrp)
		{
			statu = STATUS_UNSUCCESSFUL;
			break;
		}

		StackLocation = IoGetNextIrpStackLocation(pIrp);
		StackLocation->FileObject = FileObj;
		StackLocation->DeviceObject = pDeviceObject;
		pIrp->RequestorMode = KernelMode;

		statu = IoCallDriver(pDeviceObject, pIrp);
		if (STATUS_PENDING == statu)
		{
			statu = KeWaitForSingleObject(
				&Event,
				Executive,
				KernelMode,
				FALSE,
				0
			);
		}
		if (!NT_SUCCESS(statu))
			break;

		Count = paramUdp.ConnCount + 2;
		pBuf4 = (PINTERNAL_UDP_TABLE_ENTRY)ExAllocatePoolWithTag(NonPagedPool, 0x1c * Count, 'UDMM');
		pBuf5 = (PNSI_PROCESSID_INFO)ExAllocatePoolWithTag(NonPagedPool, 0x20 * Count, 'UDMM');
		if (!pBuf4 || !pBuf5)
			break;

		RtlSecureZeroMemory(&paramUdp, sizeof(NSI_PARAM));
		paramUdp.UnknownParam3 = (ULONG_PTR)&NPI_MS_UDP_MODULEID;
		paramUdp.UnknownParam4 = 0x1;
		paramUdp.UnknownParam5 = 0x100000001;
		paramUdp.UnknownParam6 = (ULONG_PTR)pBuf4;
		paramUdp.UnknownParam7 = 0x1c;
		paramUdp.UnknownParam12 = (ULONG_PTR)pBuf5;
		paramUdp.UnknownParam13 = 0x20;
		paramUdp.ConnCount = Count - 2;

		pIrp = IoBuildDeviceIoControlRequest(
			IOCTL_NSI_GETALLPARAM,
			pDeviceObject,
			&paramUdp,
			sizeof(NSI_PARAM),
			&paramUdp,
			sizeof(NSI_PARAM),
			FALSE,
			&Event,
			&StatusBlock
		);

		StackLocation = IoGetNextIrpStackLocation(pIrp);
		StackLocation->FileObject = FileObj;
		StackLocation->DeviceObject = pDeviceObject;
		pIrp->RequestorMode = KernelMode;

		statu = IoCallDriver(pDeviceObject, pIrp);
		if (STATUS_PENDING == statu)
		{
			statu = KeWaitForSingleObject(
				&Event,
				Executive,
				KernelMode,
				FALSE,
				0
			);
		}
		if (!NT_SUCCESS(statu))
			break;

		// Udp
		pBuffer->udpcout = paramUdp.ConnCount;
		for (ULONG i = 0; i < paramUdp.ConnCount; i++)
		{
			RtlCopyMemory(&pBuffer->sysudpinfo[i].processinfo, &pBuf5[i], sizeof(PNSI_PROCESSID_INFO));
			RtlCopyMemory(&pBuffer->sysudpinfo[i].UdpTable, &pBuf4[i], sizeof(INTERNAL_UDP_TABLE_ENTRY));
		}

	} while (FALSE);

	// Release Buffer
	if (pBuf1)
	{
		ExFreePoolWithTag(pBuf1, 'TCMM');
		pBuf1 = NULL;
	}
	if (pBuf2)
	{
		ExFreePoolWithTag(pBuf2, 'TCMM');
		pBuf2 = NULL;
	}
	if (pBuf3)
	{
		ExFreePoolWithTag(pBuf3, 'TCMM');
		pBuf3 = NULL;
	}
	if (pBuf4)
	{
		ExFreePoolWithTag(pBuf4, 'UDMM');
		pBuf4 = NULL;
	}
	if (pBuf5)
	{
		ExFreePoolWithTag(pBuf5, 'UDMM');
		pBuf5 = NULL;
	}
	
	if (FileObj)
	{
		ObDereferenceObject(FileObj);
		FileObj = NULL;
	}
	//if (pDeviceObject)
	//{
	//	ObDereferenceObject(pDeviceObject);
	//	pDeviceObject = NULL;
	//}
	if (!NT_SUCCESS(statu))
	{
		return -1;
	}

	return 1;
}
