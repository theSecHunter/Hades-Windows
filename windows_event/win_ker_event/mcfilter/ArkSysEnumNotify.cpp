#include <Windows.h>
#include "ArkSysEnumNotify.h"
#include "devctrl.h"

#define CTL_DEVCTRL_ARK_GETSYSENUMNOTIFYDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1030, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct sysnotifyobj;

typedef struct _NOTIFY_INFO
{
	ULONG	Count; // 0号索引存放个数
	ULONG	CallbackType;
	ULONG64	CallbacksAddr;
	ULONG64	Cookie; // just work to cmpcallback
	CHAR	ImgPath[MAX_PATH];
}NOTIFY_INFO, * PNOTIFY_INFO;

typedef struct _MINIFILTER_INFO
{
	ULONG	FltNum;	//过滤器的个数
	ULONG	IrpCount; // Irp的总数
	ULONG	Irp;
	ULONG64	Object;
	ULONG64	PreFunc;
	ULONG64	PostFunc;
	CHAR	PreImgPath[MAX_PATH];
	CHAR	PostImgPath[MAX_PATH];
}MINIFILTER_INFO, * PMINIFILTER_INFO;

ArkSysEnumNotify::ArkSysEnumNotify()
{

}

ArkSysEnumNotify::~ArkSysEnumNotify()
{

}

bool ArkSysEnumNotify::nf_GetSysNofityInfo()
{
	DWORD inSize = 0;
	DWORD dwSize = 0;
	char* outBuf = NULL;
	const DWORD SysNotifyinfosize = sizeof(NOTIFY_INFO) * 0x100 + sizeof(MINIFILTER_INFO) * 1000 + 100;
	outBuf = new char[SysNotifyinfosize];
	if (!outBuf)
		return false;
	RtlSecureZeroMemory(outBuf, SysNotifyinfosize);
	do {

		if (false == sysnotifyobj.devctrl_sendioct(
			CTL_DEVCTRL_ARK_GETSYSENUMNOTIFYDATA,
			NULL,
			inSize,
			outBuf,
			SysNotifyinfosize,
			dwSize)
			)
		{
			break;
		}

		if (dwSize < SysNotifyinfosize)
			return false;


	} while (false);
}
