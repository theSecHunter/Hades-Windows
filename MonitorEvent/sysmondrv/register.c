#include "public.h"
#include "register.h"
#include "kflt.h"
#include "devctrl.h"
#include "utiltools.h"

static  BOOLEAN					g_reg_monitorprocess = FALSE;
static  KSPIN_LOCK				g_reg_monitorlock = 0;

static  BOOLEAN					g_reg_ips_monitorprocess = FALSE;
static  KSPIN_LOCK				g_reg_ips_monitorlock = 0;

static	PWCHAR					g_reg_ipsNameList = NULL;
static	KSPIN_LOCK				g_reg_ipsNameListlock = 0;

static	NPAGED_LOOKASIDE_LIST	g_registerlist;
static	KSPIN_LOCK              g_registelock = 0;

static	REGISTERDATA			g_regdata;

static 	LARGE_INTEGER			g_plareg;
static	UNICODE_STRING			g_regstring;

static NTSTATUS Process_NotifyRegister(
	_In_ PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	if (((FALSE == g_reg_monitorprocess) && (FALSE == g_reg_ips_monitorprocess)) || !Argument1 || !Argument2)
		return STATUS_SUCCESS;

	NTSTATUS status = STATUS_SUCCESS;
	WCHAR path[260 * 2] = { 0 };
	
	const ULONG processid = (int)PsGetCurrentProcessId();
	const ULONG threadid = (int)PsGetCurrentThreadId();

	BOOLEAN QueryPathStatus = FALSE;
	if (QueryProcessNamePath((DWORD)processid, path, sizeof(path)))
		QueryPathStatus = TRUE;
	if (!g_reg_monitorprocess && g_reg_ips_monitorprocess && !QueryPathStatus)
		return STATUS_SUCCESS;

	BOOLEAN bProcFlt = FALSE;
	if (QueryPathStatus)
		bProcFlt = Register_IsIpsProcessNameInList(path);
	if (!g_reg_monitorprocess && g_reg_ips_monitorprocess && !bProcFlt)
		return STATUS_SUCCESS;

	REGISTERINFO registerinfo;
	RtlSecureZeroMemory(&registerinfo, sizeof(REGISTERINFO));
	registerinfo.processid = processid;
	registerinfo.threadid = threadid;
	if (QueryPathStatus)
		RtlCopyMemory(registerinfo.ProcessPath, path, sizeof(WCHAR) * 260);

	// Argument1 = _REG_NOTIFY_CLASS 
	const ULONG lOperateType = (REG_NOTIFY_CLASS)Argument1;
	registerinfo.opeararg = lOperateType;

	// Argument2 = Argument1.Struct
	switch (lOperateType)
	{// 默认Ex解析结构是 >= Win7
		// 创建成功前
		case RegNtPreCreateKey:
		case RegNtPreOpenKey:
		{
			PREG_PRE_CREATE_KEY_INFORMATION RegCreateOpeninfo = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
			if (!RegCreateOpeninfo)
				break;
			if (RegCreateOpeninfo->CompleteName->Length && RegCreateOpeninfo->CompleteName->Length <= 260)
				RtlCopyMemory(registerinfo.CompleteName, RegCreateOpeninfo->CompleteName->Buffer, RegCreateOpeninfo->CompleteName->Length);
		}
		break;

		case RegNtPreCreateKeyEx:
		case RegNtPreOpenKeyEx:
		{
			PREG_CREATE_KEY_INFORMATION_V1 RegCreateOpenExinfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
			if (!RegCreateOpenExinfo)
				break;
			if (RegCreateOpenExinfo->CompleteName->Length && RegCreateOpenExinfo->CompleteName->Length <= 260)
				RtlCopyMemory(registerinfo.CompleteName, RegCreateOpenExinfo->CompleteName->Buffer, RegCreateOpenExinfo->CompleteName->Length);
			registerinfo.Attributes = RegCreateOpenExinfo->Attributes;
			// DesiredAccess - KEY_READ KEY_ALL_ACCESS
			registerinfo.DesiredAccess = RegCreateOpenExinfo->DesiredAccess;
			// REG_CREATED_NEW_KEY|REG_OPENED_EXISTING_KEY
			registerinfo.Disposition = RegCreateOpenExinfo->Disposition;
			// 
			registerinfo.GrantedAccess = RegCreateOpenExinfo->GrantedAccess;
			// Root
			registerinfo.RootObject = RegCreateOpenExinfo->RootObject;
			// CreateOptions
			registerinfo.Options = RegCreateOpenExinfo->Options;
			// Wow64
			registerinfo.Wow64Flags = RegCreateOpenExinfo->Wow64Flags;
		}
		break;

		// 创建成功后
		case RegNtPostCreateKey:
		case RegNtPostOpenKey:
		{
			PREG_POST_CREATE_KEY_INFORMATION RegCreateOpenPostinfo = (PREG_POST_CREATE_KEY_INFORMATION)Argument2;
			if (!RegCreateOpenPostinfo)
				break;
			if (STATUS_SUCCESS == RegCreateOpenPostinfo->Status)
				registerinfo.Object = RegCreateOpenPostinfo->Object;
			if (RegCreateOpenPostinfo->CompleteName->Length && RegCreateOpenPostinfo->CompleteName->Length <= 260)
				RtlCopyMemory(registerinfo.CompleteName, RegCreateOpenPostinfo->CompleteName->Buffer, RegCreateOpenPostinfo->CompleteName->Length);
		}
		break;

		case RegNtPostCreateKeyEx:
		case RegNtPostOpenKeyEx:
		{
			PREG_POST_OPERATION_INFORMATION RegCreateOpenPostExinfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
			if (STATUS_SUCCESS == RegCreateOpenPostExinfo->Status)
				registerinfo.Object = RegCreateOpenPostExinfo->Object;
			// _REG_CREATE_KEY_INFORMATION_V1
			if (RegCreateOpenPostExinfo->PreInformation)
			{
				PREG_CREATE_KEY_INFORMATION_V1 PerInfo = (PREG_CREATE_KEY_INFORMATION_V1)RegCreateOpenPostExinfo->PreInformation;
				if (!PerInfo)
					break;
				if (PerInfo->CompleteName->Length && PerInfo->CompleteName->Length <= 260)
					RtlCopyMemory(registerinfo.CompleteName, PerInfo->CompleteName->Buffer, PerInfo->CompleteName->Length);
			}
		}
		break;

		// 查询
		case RegNtQueryValueKey:
		{
			PREG_QUERY_VALUE_KEY_INFORMATION RegQueryValueinfo = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
			if (!RegQueryValueinfo)
				break;
			registerinfo.Object = RegQueryValueinfo->Object;
			registerinfo.KeyInformationClass = RegQueryValueinfo->KeyValueInformationClass;
			if (RegQueryValueinfo->ValueName->Buffer && (260 >= RegQueryValueinfo->ValueName->Length))
				RtlCopyMemory(registerinfo.CompleteName, RegQueryValueinfo->ValueName->Buffer, RegQueryValueinfo->ValueName->Length);
		}
		break;

		// 修改
		case RegNtSetValueKey:
		{
			PREG_SET_VALUE_KEY_INFORMATION RegSetValueinfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
			if (!RegSetValueinfo)
				break;
			registerinfo.Object = RegSetValueinfo->Object;
			if (RegSetValueinfo->ValueName->Buffer && (260 >= RegSetValueinfo->ValueName->Length))
				RtlCopyMemory(registerinfo.CompleteName, RegSetValueinfo->ValueName->Buffer, RegSetValueinfo->ValueName->Length);
			registerinfo.Type = RegSetValueinfo->Type;
			if (RegSetValueinfo->Data && (RegSetValueinfo->DataSize < 260))
				RtlCopyMemory(registerinfo.SetData, RegSetValueinfo->Data, RegSetValueinfo->DataSize);
		}
		break;

		// 删除
		case RegNtPreDeleteKey:
		{
			PREG_DELETE_KEY_INFORMATION RegDeleteValueinfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
			if (!RegDeleteValueinfo)
				break;
			registerinfo.Object = RegDeleteValueinfo->Object;
		}
		break;

		// 枚举
		case RegNtEnumerateKey:
		{
			PREG_ENUMERATE_KEY_INFORMATION RegEmumeratinfo = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
			if (!RegEmumeratinfo)
				break;
			registerinfo.Object = RegEmumeratinfo->Object;
			registerinfo.Index = RegEmumeratinfo->Index;
			registerinfo.KeyInformationClass = RegEmumeratinfo->KeyInformationClass;
		}
		break;

		// 重命名注册表
		case RegNtRenameKey:
		//case RegNtPostRenameKey:
		{
			PREG_RENAME_KEY_INFORMATION RegRenameinfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
			if (!RegRenameinfo)
				break;
			registerinfo.Object = RegRenameinfo->Object;
			if (RegRenameinfo->NewName->Buffer && (RegRenameinfo->NewName->Length <= 260))
				RtlCopyMemory(registerinfo.CompleteName, RegRenameinfo->NewName->Buffer, RegRenameinfo->NewName->Length);
		}
		break;

		default:
		{
			if (!g_reg_monitorprocess)
				return STATUS_SUCCESS;
		}
		break;
	}

	if (g_reg_ips_monitorprocess && g_reg_ipsNameList && bProcFlt)
	{
		//DbgBreakPoint();
		PHADES_NOTIFICATION  notification = NULL;
		do {
		    int replaybuflen = sizeof(HADES_REPLY);
		    int sendbuflen = sizeof(HADES_NOTIFICATION);
		    notification = (char*)ExAllocatePoolWithTag(NonPagedPool, sendbuflen, 'IPSR');
		    if (!notification)
		        break;
		    RtlZeroMemory(notification, sendbuflen);
		    notification->CommandId = 2; // MINIPORT_IPS_REGISTER
			RtlCopyMemory(&notification->Contents, &registerinfo, sizeof(REGISTERINFO));
		    NTSTATUS nSendRet = Fsflt_SendMsg(notification, sendbuflen, notification, &replaybuflen);
		    const DWORD  ReSafeToOpen = ((PHADES_REPLY)notification)->SafeToOpen;
		    // 拦截
			if (1 == ReSafeToOpen)
				status = STATUS_ACCESS_DENIED;
		} while (FALSE);
		if (notification)
		{
		    ExFreePoolWithTag(notification, 'IPSR');
		    notification = NULL;
		} 
	}
	if (FALSE == g_reg_monitorprocess)
		return STATUS_SUCCESS;

	KLOCK_QUEUE_HANDLE lh;
	REGISTERBUFFER* regbuf = (REGISTERBUFFER*)Register_PacketAllocate(sizeof(REGISTERINFO));
	if (!regbuf)
		return status;
	regbuf->dataLength = sizeof(REGISTERINFO);
	if (regbuf->dataBuffer)
		RtlCopyMemory(regbuf->dataBuffer, &registerinfo, sizeof(REGISTERINFO));

	sl_lock(&g_regdata.register_lock, &lh);
	InsertHeadList(&g_regdata.register_pending, &regbuf->pEntry);
	sl_unlock(&lh);
	devctrl_pushinfo(NF_REGISTERTAB_INFO);

	return status;
}

NTSTATUS Register_Init(PDRIVER_OBJECT pDriverObject)
{
	sl_init(&g_registelock);
	sl_init(&g_reg_monitorlock);
	sl_init(&g_reg_ips_monitorlock);
	//KeInitializeSpinLock(&g_reg_ipsmodlock);
	KeInitializeSpinLock(&g_reg_ipsNameListlock);

	sl_init(&g_regdata.register_lock);
	InitializeListHead(&g_regdata.register_pending);

	ExInitializeNPagedLookasideList(
		&g_registerlist,
		NULL,
		NULL,
		0,
		sizeof(REGISTERBUFFER),
		'REMM',
		0
	);

	RtlInitUnicodeString(&g_regstring, L"140831");
	
	// See: Available starting with Windows Vista.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex
	CmRegisterCallbackEx(
		Process_NotifyRegister,
		&g_regstring,
		pDriverObject,
		NULL,
		&g_plareg,
		NULL
	);
	return STATUS_SUCCESS;
}
void Register_Free(void)
{
	Register_Clean();
	ExDeleteNPagedLookasideList(&g_registerlist);
	if (0 < g_plareg.QuadPart)
	{
		CmUnRegisterCallback(g_plareg);
	}
}
void Register_Clean(void)
{
	KLOCK_QUEUE_HANDLE lh;
	REGISTERBUFFER* pData = NULL;
	int lock_status = 0;

	sl_lock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsNameList)
	{
		ExFreePool(g_reg_ipsNameList);
		g_reg_ipsNameList = NULL;
	}
	sl_unlock(&lh);

	try {
		sl_lock(&g_regdata.register_lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_regdata.register_pending))
		{
			pData = (REGISTERBUFFER*)RemoveHeadList(&g_regdata.register_pending);
			sl_unlock(&lh);
			lock_status = 0;
			Register_PacketFree(pData);
			pData = NULL;
			sl_lock(&g_regdata.register_lock, &lh);
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

void Register_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_monitorlock, &lh);
	g_reg_monitorprocess = code;
	sl_unlock(&lh);
}
void Register_SetIpsMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ips_monitorlock, &lh);
	g_reg_ips_monitorprocess = code;
	sl_unlock(&lh);
}
//void Register_SetIpsModEx(const int mods)
//{
//	KLOCK_QUEUE_HANDLE lh;
//	sl_lock(&g_reg_ipsmodlock, &lh);
//	g_reg_ipsmod = mods;
//	sl_unlock(&lh);
//}
void Register_ClrIpsProcess()
{
	Register_SetIpsMonitor(FALSE);
	//Register_SetIpsModEx(0);
	utiltools_sleep(1000);
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsNameList)
	{
		ExFreePool(g_reg_ipsNameList);
		g_reg_ipsNameList = NULL;
	}
	sl_unlock(&lh);
}
BOOLEAN Register_IsIpsProcessNameInList(const PWCHAR path)
{
	BOOLEAN bRet = FALSE;

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsNameList)
	{
		PWCHAR pName = wcsrchr(path, L'\\');
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsNameList;
			pName++;
			while (*pIpsName)
			{
				if (wcscmp(pIpsName, pName) == 0)
				{
					bRet = TRUE;
					break;
				}
				while (*pIpsName++);
			}
		}
	}
	sl_unlock(&lh);
	return bRet;
}
NTSTATUS Register_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	NTSTATUS status = STATUS_SUCCESS;

	Register_ClrIpsProcess();
	do
	{
		PWCHAR p1, p2;
		ULONG i;
		if (NULL == inputBuffer || inputBufferLength < sizeof(WCHAR))
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		p1 = (PWCHAR)inputBuffer;
		p2 = ExAllocatePoolWithTag(NonPagedPool, inputBufferLength, MEM_TAG_DK);
		if (NULL == p2)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlCopyMemory(p2, p1, inputBufferLength);
		inputBufferLength >>= 1;
		for (i = 0; i < inputBufferLength; i++)
		{
			if (p2[i] == L'|')
				p2[i] = 0;
		}
		p1 = g_reg_ipsNameList;
		g_reg_ipsNameList = p2;
		if (p1)
		{
			ExFreePool(p1);
		}
	} while (FALSE);

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

REGISTERBUFFER* Register_PacketAllocate(int lens)
{
	REGISTERBUFFER* regbuf = NULL;
	regbuf = (REGISTERBUFFER*)ExAllocateFromNPagedLookasideList(&g_registerlist);
	if (!regbuf)
		return NULL;

	memset(regbuf, 0, sizeof(REGISTERBUFFER));

	if (lens > 0)
	{
		regbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, 'REMM');
		if (!regbuf->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_registerlist, regbuf);
			return FALSE;
		}
	}
	return regbuf;
}
void Register_PacketFree(REGISTERBUFFER* packet)
{
	if (packet->dataBuffer)
	{
		free_np(packet->dataBuffer);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_registerlist, packet);
}
REGISTERDATA* registerctx_get()
{
	return &g_regdata;
}