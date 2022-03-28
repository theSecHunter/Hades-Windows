#include <Windows.h>
#include "ArkSysEnumNotify.h"
#include "devctrl.h"
#include "sysinfo.h"

#define CTL_DEVCTRL_ARK_GETSYSENUMNOTIFYDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1030, METHOD_BUFFERED, FILE_ANY_ACCESS)

static DevctrlIoct sysnotifyobj;

ArkSysEnumNotify::ArkSysEnumNotify()
{

}

ArkSysEnumNotify::~ArkSysEnumNotify()
{

}

bool ArkSysEnumNotify::nf_GetSysNofityInfo()
{
	DWORD	inSize = 0;
	DWORD	dwSize = 0;
	char*	outBuf = NULL;
	bool	status = false;
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
			status = false;
			break;
		}

		if (dwSize < SysNotifyinfosize)
		{
			status = false;
			break;
		}

		status = true;

	} while (false);

	if (outBuf)
	{
		delete[] outBuf;
		outBuf = NULL;
	}

	return status;
}
