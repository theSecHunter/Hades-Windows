/*
	- 2018 year
	-- nf_EnumProcessHandle
	-- nf_EnumModuleByPid
	-- nf_KillProcess
	使用ZhuHuiBeiShaDiaoARK-master代码
	-- nf_DumpProcesss内核只需要查询出来地址和大小拷贝，修复PE工作在应用层进行。
*/
#include "public.h"
#include "sysprocessinfo.h"

typedef NTSTATUS(__fastcall* PSPTERMINATETHREADBYPOINTER)
(
	IN PETHREAD Thread,
	IN NTSTATUS ExitStatus,
	IN BOOLEAN DirectTerminate
	);
PSPTERMINATETHREADBYPOINTER PspTerminateThreadByPointer = NULL;

PHANDLE_INFO g_pHandleInfo = NULL;

VOID CharToWchar(PCHAR src, PWCHAR dst)
{
	UNICODE_STRING uString;
	ANSI_STRING aString;
	RtlInitAnsiString(&aString, src);
	RtlAnsiStringToUnicodeString(&uString, &aString, TRUE);
	wcscpy(dst, uString.Buffer);
	RtlFreeUnicodeString(&uString);
}
NTSTATUS GetProcessPathByPid(HANDLE pid, WCHAR* szProcessName)
{

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	PUNICODE_STRING szProcessPath;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &Process)))
	{
		return status;
	}

	status = SeLocateProcessImageName(Process, &szProcessPath);

	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(Process);
		return status;
	}


	//memcpy(szProcessName,szProcessPath->Buffer,szProcessPath->Length);
	//wcsncpy(szProcessName,szProcessPath->Buffer,szProcessPath->Length*2);
	__try {
		RtlCopyMemory(szProcessName, szProcessPath->Buffer, szProcessPath->Length * 2);
	}
	__except (1)
	{
		DbgPrint("GetProcessPathByPid error !\n");
	}


	ExFreePool(szProcessPath);

	ObDereferenceObject(Process);

	return STATUS_SUCCESS;

}

ULONG_PTR nf_EnumProcessHandle(HANDLE pid)
{
	PVOID Buffer;
	ULONG BufferSize = 0x20000, rtl = 0;
	NTSTATUS Status;
	NTSTATUS ns = STATUS_SUCCESS;
	ULONG64 i = 0;
	ULONG64 qwHandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO* p;
	OBJECT_BASIC_INFORMATION BasicInfo = { 0 };
	POBJECT_NAME_INFORMATION pNameInfo;
	POBJECT_TYPE_INFORMATION pTypeInfo;
	ULONG ulProcessID;
	HANDLE hProcess;
	HANDLE hHandle;
	HANDLE hDupObj;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;
	//CHAR szFile[260]={0};
	ULONG_PTR Count = 0;
	char* szProcessName = NULL;

	if (g_pHandleInfo)
	{
		ExFreePool(g_pHandleInfo);
		g_pHandleInfo = NULL;
	}

	g_pHandleInfo = (PHANDLE_INFO)ExAllocatePool(NonPagedPool, sizeof(HANDLE_INFO) * 1024 * 2);
	if (g_pHandleInfo == NULL)
		return 0x88888888;

	Buffer = malloc_np(BufferSize);
	memset(Buffer, 0, BufferSize);
	Status = ZwQuerySystemInformation(16, Buffer, BufferSize, 0);	//SystemHandleInformation
	while (Status == 0xC0000004)	//STATUS_INFO_LENGTH_MISMATCH
	{
		free_np(Buffer);
		BufferSize = BufferSize * 2;
		Buffer = malloc_np(BufferSize);
		memset(Buffer, 0, BufferSize);
		Status = ZwQuerySystemInformation(16, Buffer, BufferSize, 0);
	}
	if (!NT_SUCCESS(Status)) return 0x88888888;
	qwHandleCount = ((SYSTEM_HANDLE_INFORMATION*)Buffer)->NumberOfHandles;
	p = (SYSTEM_HANDLE_TABLE_ENTRY_INFO*)((SYSTEM_HANDLE_INFORMATION*)Buffer)->Handles;
	//clear array
	memset(g_pHandleInfo, 0, 1024 * sizeof(HANDLE_INFO) * 2);
	//ENUM HANDLE PROC
	for (i = 0; i < qwHandleCount; i++)
	{

		if ((ULONG)pid == (ULONG)p[i].UniqueProcessId)
		{
			ulProcessID = (ULONG)p[i].UniqueProcessId;
			cid.UniqueProcess = (HANDLE)ulProcessID;
			cid.UniqueThread = (HANDLE)0;
			hHandle = (HANDLE)p[i].HandleValue;
			InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
			ns = ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &oa, &cid);
			if (!NT_SUCCESS(ns))
			{
				KdPrint(("ZwOpenProcess : Fail "));
				continue;
			}
			ns = ZwDuplicateObject(hProcess, hHandle, NtCurrentProcess(), &hDupObj, PROCESS_ALL_ACCESS, 0, DUPLICATE_SAME_ACCESS);
			if (!NT_SUCCESS(ns))
			{
				if (ns == 0xc00000bb)
				{
					//KdPrint(( "This is EtwRegistration ZwDuplicateObject Fail Code :0x%x",ns ));
					g_pHandleInfo[Count].GrantedAccess = p[i].GrantedAccess;
					g_pHandleInfo[Count].HandleValue = p[i].HandleValue;
					wcsncpy(g_pHandleInfo[Count].HandleName, L" ", wcslen(L" "));
					g_pHandleInfo[Count].Object = (ULONG64)p[i].Object;
					g_pHandleInfo[Count].ObjectTypeIndex = p[i].ObjectTypeIndex;
					wcsncpy(g_pHandleInfo[Count].TypeName, L"EtwRegistration", wcslen(L"EtwRegistration"));
					g_pHandleInfo[Count].ReferenceCount = 0;
					wcsncpy(g_pHandleInfo[Count].ProcessName, L"System", wcslen(L"System"));
					Count++;
				}
				continue;
			}
			//get basic information
			ZwQueryObject(hDupObj, ObjectBasicInformation, &BasicInfo, sizeof(OBJECT_BASIC_INFORMATION), NULL);

			pTypeInfo = ExAllocatePool(PagedPool, 1024);
			RtlZeroMemory(pTypeInfo, 1024);
			ZwQueryObject(hDupObj, ObjectTypeInformation, pTypeInfo, 1024, NULL);
			//get name information
			pNameInfo = ExAllocatePoolWithTag(PagedPool, 1024, 'ONON');
			RtlZeroMemory(pNameInfo, 1024);
			ZwQueryObject(hDupObj, (OBJECT_INFORMATION_CLASS)ObjectNameInformation1, pNameInfo, 1024, &rtl);
			//get information and close handle
			//UnicodeStringToCharArray(&(pNameInfo->Name),szFile);	
			ZwClose(hDupObj);
			ZwClose(hProcess);
			//KdPrint(("HandleName:%wZ---ReferenceCount:%d----Object:0x%llx---Handle:0x%x---ObjeceType:%d\n",pNameInfo->Name,BasicInfo.ReferenceCount,p[i].Object,p[i].HandleValue,p[i].ObjectTypeIndex));	
			//KdPrint(("ObjectName:%wZ\n",pTypeInfo->TypeName));
			//KdPrint(("Access:0x%x\n",BasicInfo.DesiredAccess));
			if (p[i].ObjectTypeIndex == 7)//Process
			{
				//KdPrint(("Process:%s\n",PsGetProcessImageFileName((PEPROCESS)p[i].Object)));
				szProcessName = (PCHAR)PsGetProcessImageFileName((PEPROCESS)p[i].Object);
				CharToWchar(szProcessName, g_pHandleInfo[Count].ProcessName);
				//KdPrint(("%ws\n",pHandleInfo[Count].ProcessName));
			}
			else if (p[i].ObjectTypeIndex == 8)//Thread
			{
				//KdPrint(("Process:%s\n",PsGetProcessImageFileName(IoThreadToProcess((PETHREAD)p[i].Object))));
				szProcessName = (PCHAR)PsGetProcessImageFileName(IoThreadToProcess((PETHREAD)p[i].Object));
				CharToWchar(szProcessName, g_pHandleInfo[Count].ProcessName);
				//KdPrint(("%ws\n",pHandleInfo[Count].ProcessName));
			}
			g_pHandleInfo[Count].ObjectTypeIndex = p[i].ObjectTypeIndex;
			g_pHandleInfo[Count].ReferenceCount = BasicInfo.ReferenceCount;
			g_pHandleInfo[Count].GrantedAccess = BasicInfo.DesiredAccess;
			g_pHandleInfo[Count].HandleValue = p[i].HandleValue;
			g_pHandleInfo[Count].Object = (ULONG64)p[i].Object;
			wcsncpy(g_pHandleInfo[Count].HandleName, pNameInfo->Name.Buffer, pNameInfo->Name.Length * 2);
			wcsncpy(g_pHandleInfo[Count].TypeName, pTypeInfo->TypeName.Buffer, pTypeInfo->TypeName.Length * 2);

			ExFreePool(pNameInfo);
			ExFreePool(pTypeInfo);
			Count++;

			if (Count > 2000)
				return 0x88888888;

		}
	}
	g_pHandleInfo[0].CountNum = Count;
	return Count;
}

VOID nf_EnumModuleByPid(ULONG pid)
{
	SIZE_T Peb = 0, Ldr = 0, tmp = 0;
	PEPROCESS Process = NULL;
	PLIST_ENTRY ModListHead = 0;
	PLIST_ENTRY Module = 0;
	KAPC_STATE ks = { 0 };
	ULONG count = 0;

	//遍历LDR-NATIVE
#ifdef AMD64
	const int LdrInPebOffset = 0x18;
	const int ModListInPebOffset = 0x10;
#else
	const int LdrInPebOffset = 0xC;
	const int ModListInPebOffset = 0xC;
#endif

	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &eprocess)))
		return eprocess;
	else
		return NULL;

	Peb = PsGetProcessPeb(Process);
	KeStackAttachProcess(Process, &ks);
	__try
	{
		Ldr = Peb + (SIZE_T)LdrInPebOffset;
		ProbeForRead((CONST PVOID)Ldr, sizeof(void*), sizeof(void*));
		ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + ModListInPebOffset);
		ProbeForRead((CONST PVOID)ModListHead, sizeof(void*), sizeof(void*));
		Module = ModListHead->Flink;
		while (ModListHead != Module)
		{
			WCHAR ModuleName[260] = { 0 };
			memcpy(ModuleName,
				((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName.Buffer,
				((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName.Length);//DbgPrint("%S\n",ModuleName);
			DbgPrint("[64]Base=%llx Size=%ld Name=%S Path=%S\n",
				((PLDR_DATA_TABLE_ENTRY)Module)->DllBase,
				((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage,
				((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName.Buffer,
				((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName.Buffer);

			count++;

			//next module
			Module = Module->Flink;
			ProbeForRead((CONST PVOID)Module, 10 * sizeof(void*), sizeof(void*));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[EnumModule64]__except (EXCEPTION_EXECUTE_HANDLER)");
	}
#ifdef AMD64
	//遍历LDR-32 枚举32位进程的32位DLL
	tmp = (SIZE_T)PsGetProcessWow64Process(Process);
	if (tmp)
	{
		SIZE_T peb, ldr;
		PLIST_ENTRY32 ModListHead32 = 0;
		PLIST_ENTRY32 Module32 = 0;
		peb = tmp;
		__try
		{
			//peb->ldr
			ldr = *(PULONG)(peb + 0xC);//OFFSET_PEB_LDR
			ProbeForRead((CONST PVOID)ldr, 4, 4);
			//peb->Ldr->InLoadOrderModuleList
			ModListHead32 = (PLIST_ENTRY32)(*(PULONG)(ldr + 0xC));//OFFSET_LDR_InLoadOrderModuleList
			ProbeForRead((CONST PVOID)ModListHead32, 4, 4);
			//peb->Ldr->InLoadOrderModuleList->Flink
			Module32 = (PLIST_ENTRY32)(ModListHead32->Flink);//DbgPrint("Module32=%x\n",Module32);
			while (ModListHead32 != Module32)
			{
				if (((PLDR_DATA_TABLE_ENTRY32)Module32)->DllBase)
				{
					WCHAR ModuleName[260] = { 0 };
					memcpy(ModuleName,
						(PVOID)(((PLDR_DATA_TABLE_ENTRY32)Module32)->BaseDllName.Buffer),
						((PLDR_DATA_TABLE_ENTRY32)Module32)->BaseDllName.Length);//DbgPrint("ModuleName: %S\n",ModuleName);  
		 //打印信息：基址、大小、DLL路径
					DbgPrint("[32]Base=%x Size=%ld Name=%S Path=%S\n",
						((PLDR_DATA_TABLE_ENTRY32)Module32)->DllBase,
						((PLDR_DATA_TABLE_ENTRY32)Module32)->SizeOfImage,
						((PLDR_DATA_TABLE_ENTRY32)Module32)->BaseDllName.Buffer,
						((PLDR_DATA_TABLE_ENTRY32)Module32)->FullDllName.Buffer);
				}
				count++;
				Module32 = (PLIST_ENTRY32)(Module32->Flink);
				ProbeForRead((CONST PVOID)Module32, 40, 4);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrint("[EnumModule32]__except (EXCEPTION_EXECUTE_HANDLER)");
		}
	}
#endif
	KeUnstackDetachProcess(&ks);
	ObDereferenceObject(Process);
	KdPrint(("Count:%d\n\n", count));
}

int nf_DumpProcess(PKERNEL_COPY_MEMORY_OPERATION request)
{
	PEPROCESS targetProcess;

	if (NT_SUCCESS(PsLookupProcessByProcessId(request->targetProcessId, &targetProcess)))
	{
		PSIZE_T readBytes;
		MmCopyVirtualMemory(targetProcess, request->bufferAddress, PsGetCurrentProcess(), request->targetAddress, request->bufferSize, UserMode, &readBytes);
		ObDereferenceObject(targetProcess);
	}
}

int nf_KillProcess(ULONG pid)
{
	
	ULONG32 callcode = 0;
	ULONG64 AddressOfPspTTBP = 0, AddressOfPsTST = 0, i = 0;
	PETHREAD Thread = NULL;
	PEPROCESS tProcess = NULL;
	NTSTATUS status = 0;

	PEPROCESS pEProc;
	PsLookupProcessByProcessId((HANDLE)pid, &pEProc);
	if (!pEProc)
		return STATUS_UNSUCCESSFUL;
	
	if (PspTerminateThreadByPointer == NULL)
	{
		// PsTerminateSystemThread
		AddressOfPsTST = (ULONG64)MmGetSystemRoutineAddress(L"PsTerminateSystemThread");
		if (AddressOfPsTST == 0)
			return STATUS_UNSUCCESSFUL;
		for (i = 1; i < 0xff; i++)
		{
			if (MmIsAddressValid((PVOID)(AddressOfPsTST + i)) != FALSE)
			{
				if (*(unsigned char*)(AddressOfPsTST + i) == 0x01 && *(unsigned char*)(AddressOfPsTST + i + 1) == 0xe8) //目标地址-原始地址-5=机器码 ==> 目标地址=机器码+5+原始地址
				{
					RtlMoveMemory(&callcode, (PVOID)(AddressOfPsTST + i + 2), 4);
					AddressOfPspTTBP = (ULONG64)callcode + 5 + AddressOfPsTST + i + 1;
				}
			}
		}
		PspTerminateThreadByPointer = (PSPTERMINATETHREADBYPOINTER)AddressOfPspTTBP;
	}

	// 枚举线程
	for (i = 4; i < 0x40000; i += 4)
	{
		status = PsLookupThreadByThreadId((HANDLE)i, &Thread);
		if (NT_SUCCESS(status))
		{
			// 获取线程的进程结构
			tProcess = IoThreadToProcess(Thread);
			// 指针相同意味着属于该进程
			if (tProcess == pEProc)
				PspTerminateThreadByPointer(Thread, 0, 1);
			ObDereferenceObject(Thread);
		}
	}

	if (pEProc)
		ObDereferenceObject(pEProc);
	return STATUS_SUCCESS;
}