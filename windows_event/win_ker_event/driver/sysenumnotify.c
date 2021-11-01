/*
	枚举回调代码使用开源的项目：ZhuHuiBeiShaDiaoARK(github)
*/

#include "public.h"
#include "sysenumnotify.h"

VOID Enum_ProcessNotify()
{
	LONG			OffsetAddr = 0;
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	LONG			PspCreateProcessNotifyRoutine = 0;
	ULONG64			NotifyAddr = 0, MagicPtr = 0;
	PNOTIFY_INFO	pNotify = NULL;
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
	if (FALSE == MmIsAddressValid(PspCreateProcessNotifyRoutine))
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
}

VOID Enum_ThreadNotify()
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	RtlInitUnicodeString(&unstrFunc, L"PsSetLoadImageNotifyRoutine");
	ULONG64 PspLoadImageNotifyRoutine = 0;
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

	if (FALSE == MmIsAddressValid(PspLoadImageNotifyRoutine))
		return;

	ULONG count = 0;
	PNOTIFY_INFO pNotify = NULL;
	SYSTEM_MODULE Sysmodule = { 0 };
	ULONG64	NotifyAddr = 0, MagicPtr = 0;

	pNotify = ExAllocatePool(NonPagedPool, sizeof(NOTIFY_INFO) * 100);

	if (pNotify == NULL)
		return NULL;

	if (!PspLoadImageNotifyRoutine)
		return NULL;

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
			if (NT_SUCCESS(getSystemImageInfoByAddress(NotifyAddr, &Sysmodule)) &&
				strlen(Sysmodule.ImageName) < MAX_PATH)
			{
				RtlCopyMemory(pNotify[count].ImgPath, Sysmodule.ImageName, MAX_PATH);
			}

			//DbgPrint("[LoadImage]%llx\n",NotifyAddr);
			count++;
		}
	}

	pNotify[0].Count = count;
}

VOID Enum_ResiterNotify()
{

}

VOID Enum_ObCalloutNotify()
{
	ULONG c = 0;
	POBCALLBACKS_INFO pNotify = NULL;
	PLIST_ENTRY CurrEntry = NULL;
	POB_CALLBACK pObCallback;
	SYSTEM_MODULE Sysmodule = { 0 };
	ULONG64 ObProcessCallbackListHead = *(ULONG64*)PsProcessType + ObjectCallbackListOffset;
	ULONG64 ObThreadCallbackListHead = *(ULONG64*)PsThreadType + ObjectCallbackListOffset;

	pNotify = ExAllocatePool(NonPagedPool, sizeof(OBCALLBACKS_INFO) * 100);
	if (pNotify == NULL)
		return NULL;


	RtlZeroMemory(pNotify, sizeof(OBCALLBACKS_INFO) * 100);

	CurrEntry = ((PLIST_ENTRY)ObProcessCallbackListHead)->Flink;
	do
	{
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0) //list_head的数据是垃圾数据，忽略
		{
			//dprintf("ObHandle: %p\n", pObCallback->ObHandle);
			//dprintf("PreCall: %p\n", pObCallback->PreCall);
			//dprintf("PostCall: %p\n", pObCallback->PostCall);
			pNotify[c].PreCallbackAddr = pObCallback->PreCall;
			pNotify[c].PostCallbackAddr = pObCallback->PostCall;
			pNotify[c].ObHandle = pObCallback->ObHandle;
			pNotify[c].ObType = 0;

			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			if (NT_SUCCESS(getSystemImageInfoByAddress(pNotify[c].PreCallbackAddr, &Sysmodule)) &&
				strlen(Sysmodule.ImageName) < MAX_PATH)
			{
				RtlCopyMemory(pNotify[c].PreImgPath, Sysmodule.ImageName, MAX_PATH);
			}

			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			if (NT_SUCCESS(getSystemImageInfoByAddress(pNotify[c].PostCallbackAddr, &Sysmodule)) &&
				strlen(Sysmodule.ImageName) < MAX_PATH)
			{
				RtlCopyMemory(pNotify[c].PostImgPaht, Sysmodule.ImageName, MAX_PATH);
			}

			c++;
		}
		CurrEntry = CurrEntry->Flink;
	} while (CurrEntry != (PLIST_ENTRY)ObProcessCallbackListHead);

	// 线程
	CurrEntry = ((PLIST_ENTRY)ObThreadCallbackListHead)->Flink;	//list_head的数据是垃圾数据，忽略
	do
	{
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			//dprintf("ObHandle: %p\n", pObCallback->ObHandle);
			//dprintf("PreCall: %p\n", pObCallback->PreCall);
			//dprintf("PostCall: %p\n", pObCallback->PostCall);
			pNotify[c].PreCallbackAddr = pObCallback->PreCall;
			pNotify[c].PostCallbackAddr = pObCallback->PostCall;
			pNotify[c].ObHandle = pObCallback->ObHandle;
			pNotify[c].ObType = 1;

			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			if (NT_SUCCESS(getSystemImageInfoByAddress(pNotify[c].PreCallbackAddr, &Sysmodule)) &&
				strlen(Sysmodule.ImageName) < MAX_PATH)
			{
				RtlCopyMemory(pNotify[c].PreImgPath, Sysmodule.ImageName, MAX_PATH);
			}

			memset(&Sysmodule, 0, sizeof(SYSTEM_MODULE));
			if (NT_SUCCESS(getSystemImageInfoByAddress(pNotify[c].PostCallbackAddr, &Sysmodule)) &&
				strlen(Sysmodule.ImageName) < MAX_PATH)
			{
				RtlCopyMemory(pNotify[c].PostImgPaht, Sysmodule.ImageName, MAX_PATH);
			}
			c++;
		}
		CurrEntry = CurrEntry->Flink;
	} while (CurrEntry != (PLIST_ENTRY)ObThreadCallbackListHead);
	//dprintf("ObCallback count: %ld\n", c);

	pNotify[0].Count = c;
}

VOID Enum_MinifilterNotify()
{
}

VOID Enum_ImageModNotify()
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	ULONG64	PspLoadImageNotifyRoutine = 0;
	RtlInitUnicodeString(&unstrFunc, L"PsSetLoadImageNotifyRoutine");
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

	if (FALSE == MmIsAddressValid(PspLoadImageNotifyRoutine))
		return;

	ULONG count = 0;
	PNOTIFY_INFO pNotify = NULL;
	SYSTEM_MODULE Sysmodule = { 0 };
	ULONG64	NotifyAddr = 0, MagicPtr = 0;
	 = FindPspLoadImageNotifyRoutine();
	//DbgPrint("PspLoadImageNotifyRoutine: %llx\n",PspLoadImageNotifyRoutine);
	pNotify = ExAllocatePool(NonPagedPool, sizeof(NOTIFY_INFO) * 100);

	if (pNotify == NULL)
		return NULL;

	if (!PspLoadImageNotifyRoutine)
		return NULL;

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
			if (NT_SUCCESS(getSystemImageInfoByAddress(NotifyAddr, &Sysmodule)) &&
				strlen(Sysmodule.ImageName) < MAX_PATH)
			{
				RtlCopyMemory(pNotify[count].ImgPath, Sysmodule.ImageName, MAX_PATH);
			}

			//DbgPrint("[LoadImage]%llx\n",NotifyAddr);
			count++;
		}
	}

	pNotify[0].Count = count;
}

PMINIFILTER_INFO Enum_ImageModNotify()
{
	long	ntStatus;
	ULONG	uNumber = 0;
	ULONG	IrpCount = 0;
	PVOID	pBuffer = NULL;
	ULONG	DrvCount = 0;
	PVOID	pCallBacks = NULL, pFilter = NULL;
	SYSTEM_MODULE	SysModuel = { 0 };
	PMINIFILTER_INFO pFltInfo = NULL;
	PFLT_OPERATION_REGISTRATION pNode = NULL;


	pFltInfo = ExAllocatePool(NonPagedPool, sizeof(MINIFILTER_INFO) * 1000);
	if (pFltInfo == NULL)
		return NULL;

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
		return 0;
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

							if (NT_SUCCESS(getSystemImageInfoByAddress(pFltInfo[IrpCount].PreFunc, &SysModuel)) && strlen(SysModuel.ImageName) < MAX_PATH)
							{
								RtlCopyMemory(pFltInfo[IrpCount].PreImgPath, SysModuel.ImageName, MAX_PATH);
							}

						}

						RtlZeroMemory(&SysModuel, sizeof(SYSTEM_MODULE));

						if (pNode->PostOperation != 0)
						{
							pFltInfo[IrpCount].PostFunc = pNode->PostOperation;
							if (NT_SUCCESS(getSystemImageInfoByAddress(pFltInfo[IrpCount].PostFunc, &SysModuel)) && strlen(SysModuel.ImageName) < MAX_PATH)
							{
								RtlCopyMemory(pFltInfo[IrpCount].PostImgPath, SysModuel.ImageName, MAX_PATH);
							}
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
				return NULL;
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
		return NULL;
	}
	if (pBuffer != NULL)
	{
		pFltInfo[0].IrpCount = IrpCount;
		pFltInfo[0].FltNum = uNumber;
		ExFreePool(pBuffer);
		ntStatus = STATUS_SUCCESS;
	}

	return pFltInfo;
}