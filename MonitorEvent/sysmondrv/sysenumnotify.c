/*
	部分使用开源项目：ZhuHuiBeiShaDiaoARK(github)
*/

#include "public.h"
#include "sysenumnotify.h"
#include <fltkernel.h>

ULONG FltFilterOperationsOffset = 0;

VOID Enum_ProcessNotify(PNOTIFY_INFO pNotify)
{
	LONG			OffsetAddr = 0;
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	LONG			PspCreateProcessNotifyRoutine = 0;
	ULONG64			NotifyAddr = 0, MagicPtr = 0;
	// PNOTIFY_INFO	pNotify = NULL;
	SYSTEM_MODULE	Sysmodule = { 0 };

	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateProcessNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	memcpy(&OffsetAddr, (PUCHAR)pCheckArea + 4, 4);
	pCheckArea = (pCheckArea + 3) + 5 + OffsetAddr;
	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		// lea r14,xxxx
		if (*(PUCHAR)i == 0x4c && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x35)	
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			PspCreateProcessNotifyRoutine = OffsetAddr + 7 + i;
		}
	}
	if (FALSE == MmIsAddressValid((PVOID)PspCreateProcessNotifyRoutine))
		return;

	ULONG count = 0;
	for (i = 0; i < 64; i++)
	{
		MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);

			pNotify[count].CallbacksAddr = NotifyAddr;
			pNotify[count].CallbackType = 1; // creatrprocess
			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			//if (NT_SUCCESS(getSystemImageInfoByAddress(NotifyAddr, &Sysmodule)) &&
			//	strlen(Sysmodule.ImageName) < MAX_PATH)
			//{
			//	RtlCopyMemory(pNotify[count].ImgPath, Sysmodule.ImageName, MAX_PATH);
			//}
			count++;
		}
	}
	pNotify[0].Count = count;
}
VOID Enum_ThreadNotify(PNOTIFY_INFO pNotify)
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	RtlInitUnicodeString(&unstrFunc, L"PsSetLoadImageNotifyRoutine");
	ULONG64 PspLoadImageNotifyRoutine = 0;
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x48 && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x0d)	//lea rcx,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			PspLoadImageNotifyRoutine = OffsetAddr + 7 + i;
		}
	}

	if (FALSE == MmIsAddressValid((PVOID)PspLoadImageNotifyRoutine))
		return;

	ULONG count = 0;
	SYSTEM_MODULE Sysmodule = { 0 };
	ULONG64	NotifyAddr = 0, MagicPtr = 0;

	pNotify = ExAllocatePool(NonPagedPool, sizeof(NOTIFY_INFO) * 100);

	if (pNotify == NULL)
		return;

	if (!PspLoadImageNotifyRoutine)
		return;

	for (i = 0; i < 8; i++)
	{
		MagicPtr = PspLoadImageNotifyRoutine + i * 8;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
			pNotify[count].CallbacksAddr = NotifyAddr;
			pNotify[count].CallbackType = 0; // loadimage
			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			//if (NT_SUCCESS(getSystemImageInfoByAddress(NotifyAddr, &Sysmodule)) &&
			//	strlen(Sysmodule.ImageName) < MAX_PATH)
			//{
			//	RtlCopyMemory(pNotify[count].ImgPath, Sysmodule.ImageName, MAX_PATH);
			//}

			//DbgPrint("[LoadImage]%llx\n",NotifyAddr);
			count++;
		}
	}

	pNotify[0].Count = count;
}
VOID Enum_ImageModNotify(PNOTIFY_INFO pNotify)
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	ULONG64	PspLoadImageNotifyRoutine = 0;
	RtlInitUnicodeString(&unstrFunc, L"PsSetLoadImageNotifyRoutine");
	// Windows PsSetLoadImageNotifyRoutineEx才可以
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	//DbgPrint("PsSetLoadImageNotifyRoutine: %llx\n",pCheckArea);
	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x48 && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x0d)	//lea rcx,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			PspLoadImageNotifyRoutine = OffsetAddr + 7 + i;
		}
	}

	if (FALSE == MmIsAddressValid((PVOID)PspLoadImageNotifyRoutine))
		return;

	ULONG count = 0;
	SYSTEM_MODULE Sysmodule = { 0 };
	ULONG64	NotifyAddr = 0, MagicPtr = 0;
	//DbgPrint("PspLoadImageNotifyRoutine: %llx\n",PspLoadImageNotifyRoutine);
	pNotify = ExAllocatePool(NonPagedPool, sizeof(NOTIFY_INFO) * 100);

	if (pNotify == NULL)
		return;

	if (!PspLoadImageNotifyRoutine)
		return;

	for (i = 0; i < 8; i++)
	{
		MagicPtr = PspLoadImageNotifyRoutine + i * 8;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
			pNotify[count].CallbacksAddr = NotifyAddr;
			pNotify[count].CallbackType = 0; // loadimage
			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			//if (NT_SUCCESS(getSystemImageInfoByAddress(NotifyAddr, &Sysmodule)) &&
			//	strlen(Sysmodule.ImageName) < MAX_PATH)
			//{
			//	RtlCopyMemory(pNotify[count].ImgPath, Sysmodule.ImageName, MAX_PATH);
			//}

			//DbgPrint("[LoadImage]%llx\n",NotifyAddr);
			count++;
		}
	}

	pNotify[0].Count = count;
}
VOID Enum_ResiterNotify(PNOTIFY_INFO pNotify)
{

}
VOID Enum_ObCalloutNotify(PNOTIFY_INFO pNotify)
{
}
VOID Enum_MinifilterNotify(PMINIFILTER_INFO pFltInfo)
{
	long	ntStatus;
	ULONG	uNumber = 0;
	ULONG	IrpCount = 0;
	PVOID	pBuffer = NULL;
	ULONG	DrvCount = 0;
	PVOID	pCallBacks = NULL, pFilter = NULL;
	SYSTEM_MODULE	SysModuel = { 0 };
	PFLT_OPERATION_REGISTRATION pNode = NULL;


	pFltInfo = ExAllocatePool(NonPagedPool, sizeof(MINIFILTER_INFO) * 1000);
	if (pFltInfo == NULL)
		return;

	RtlZeroMemory(pFltInfo, sizeof(MINIFILTER_INFO) * 1000);

	do
	{
		if (pBuffer != NULL)
		{
			ExFreePool(pBuffer);
			pBuffer = NULL;
		}
		ntStatus = FltEnumerateFilters(NULL, 0, &uNumber);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL)
			break;
		pBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(PFLT_FILTER) * uNumber, 'mnft');
		if (pBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		ntStatus = FltEnumerateFilters(pBuffer, uNumber, &uNumber);
	} while (ntStatus == STATUS_BUFFER_TOO_SMALL);
	if (!NT_SUCCESS(ntStatus))
	{
		if (pBuffer != NULL)
			ExFreePool(pBuffer);
		return;
	}
	DbgPrint("MiniFilter Count: %ld\n", uNumber);
	pFltInfo[0].FltNum = uNumber;
	DbgPrint("------\n");
	__try
	{
		while (DrvCount < uNumber)
		{
			pFilter = (PVOID)(*(PULONG64)((PUCHAR)pBuffer + DrvCount * 8));
			pCallBacks = (PVOID)((PUCHAR)pFilter + FltFilterOperationsOffset);
			pNode = (PFLT_OPERATION_REGISTRATION)(*(PULONG64)pCallBacks);
			__try
			{
				while (pNode->MajorFunction != 0x80)	//IRP_MJ_OPERATION_END
				{
					if (pNode->MajorFunction < 28)	//MajorFunction id is 0~27
					{
						DbgPrint("Object=%p\tPreFunc=%p\tPostFunc=%p\tIRP=%d\n",
							pFilter,
							pNode->PreOperation,
							pNode->PostOperation,
							pNode->MajorFunction);


						pFltInfo[IrpCount].Irp = pNode->MajorFunction;
						pFltInfo[IrpCount].Object = pFilter;

						if (pNode->PreOperation != 0)
						{
							pFltInfo[IrpCount].PreFunc = pNode->PreOperation;

	/*						if (NT_SUCCESS(getSystemImageInfoByAddress(pFltInfo[IrpCount].PreFunc, &SysModuel)) && strlen(SysModuel.ImageName) < MAX_PATH)
							{
								RtlCopyMemory(pFltInfo[IrpCount].PreImgPath, SysModuel.ImageName, MAX_PATH);
							}*/

						}

						RtlZeroMemory(&SysModuel, sizeof(SYSTEM_MODULE));

						if (pNode->PostOperation != 0)
						{
							pFltInfo[IrpCount].PostFunc = pNode->PostOperation;
				/*			if (NT_SUCCESS(getSystemImageInfoByAddress(pFltInfo[IrpCount].PostFunc, &SysModuel)) && strlen(SysModuel.ImageName) < MAX_PATH)
							{
								RtlCopyMemory(pFltInfo[IrpCount].PostImgPath, SysModuel.ImageName, MAX_PATH);
							}*/
						}

						RtlZeroMemory(&SysModuel, sizeof(SYSTEM_MODULE));

						IrpCount++;
					}
					pNode++;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				FltObjectDereference(pFilter);
				DbgPrint("[EnumMiniFilter]EXCEPTION_EXECUTE_HANDLER: pNode->MajorFunction\n");
				ntStatus = GetExceptionCode();
				ExFreePool(pBuffer);
				ExFreePool(pFltInfo);
				return;
			}
			DrvCount++;
			FltObjectDereference(pFilter);
			DbgPrint("------\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		FltObjectDereference(pFilter);
		DbgPrint("[EnumMiniFilter]EXCEPTION_EXECUTE_HANDLER\n");
		ntStatus = GetExceptionCode();
		ExFreePool(pBuffer);
		ExFreePool(pFltInfo);
		return;
	}
	if (pBuffer != NULL)
	{
		pFltInfo[0].IrpCount = IrpCount;
		pFltInfo[0].FltNum = uNumber;
		ExFreePool(pBuffer);
		ntStatus = STATUS_SUCCESS;
	}
}