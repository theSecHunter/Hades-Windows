#include "public.h"
#include "register.h"

#include "devctrl.h"

static  BOOLEAN					g_reg_monitorprocess = FALSE;
static  KSPIN_LOCK				g_reg_monitorlock = NULL;

static	KSPIN_LOCK              g_registelock = NULL;
static	NPAGED_LOOKASIDE_LIST	g_registerlist;

static	REGISTERDATA			g_regdata;

static 	LARGE_INTEGER			g_plareg;
static	UNICODE_STRING			g_regstring;


NTSTATUS Process_NotifyRegister(
	_In_ PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument2);

	if (FALSE == g_reg_monitorprocess)
		return STATUS_SUCCESS;

	REGISTERINFO registerinfo;
	KLOCK_QUEUE_HANDLE lh;
	LONG lOperateType = -1;
	RtlSecureZeroMemory(&registerinfo, sizeof(REGISTERINFO));

	registerinfo.processid = (int)PsGetCurrentProcessId();
	registerinfo.threadid = (int)PsGetCurrentThreadId();

	// Argument1 = _REG_NOTIFY_CLASS 
	if (Argument1)
		lOperateType = (REG_NOTIFY_CLASS)Argument1;
	registerinfo.opeararg = lOperateType;

	// Argument2 = Argument1.Struct
	switch (lOperateType)
	{
		// 创建Key
		case RegNtPreCreateKey:
		{

		}
		break;
		// 打开Key
		case RegNtPreOpenKey:
		{
		
		}
		break;

		// 修改Key
		case RegNtSetValueKey:
		{

		}
		// 删除Key
		case RegNtPreDeleteKey:
		{
		
		}
		break;

		// 枚举Key
		case RegNtEnumerateKey:
		{

		}
		break;

		// 重命名注册表
		case RegNtPostRenameKey:
		{
		
		}
		break;

		default:
			return STATUS_SUCCESS;
	}

	REGISTERBUFFER* regbuf = (REGISTERBUFFER*)Register_PacketAllocate(sizeof(REGISTERINFO));
	if (!regbuf)
		return;

	regbuf->dataLength = sizeof(REGISTERINFO);
	if (regbuf->dataBuffer)
	{
		memcpy(regbuf->dataBuffer, &registerinfo, sizeof(REGISTERINFO));
	}

	sl_lock(&g_regdata.register_lock, &lh);
	InsertHeadList(&g_regdata.register_pending, &regbuf->pEntry);
	sl_unlock(&lh);

	devctrl_pushinfo(NF_REGISTERTAB_INFO);

	return STATUS_SUCCESS;
}

int Register_Init(PDRIVER_OBJECT pDriverObject)
{
	sl_init(&g_reg_monitorlock);
	sl_init(&g_registelock);

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
	
	NTSTATUS status = CmRegisterCallbackEx(
		Process_NotifyRegister,
		&g_regstring,
		pDriverObject,
		NULL,
		&g_plareg,
		NULL
	);

	return 1;
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

	sl_lock(&g_regdata.register_lock, &lh);

	while (!IsListEmpty(&g_regdata.register_pending))
	{
		pData = (REGISTERBUFFER*)RemoveHeadList(&g_regdata.register_pending);
		sl_unlock(&lh);
		Register_PacketFree(pData);
		pData = NULL;
		sl_lock(&g_regdata.register_lock, &lh);
	}

	sl_unlock(&lh);
}

void Register_SetMonitor(BOOLEAN code)
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_monitorlock, &lh);
	g_reg_monitorprocess = code;
	sl_unlock(&lh);
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