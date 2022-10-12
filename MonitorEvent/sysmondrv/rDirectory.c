#include "public.h"
#include "rDirectory.h"
#include "utiltools.h"

static	PWCHAR					g_reg_ipsProcNameBlackList = NULL;
static	PWCHAR					g_reg_ipsProcNameWhiteList = NULL;
static	PWCHAR					g_reg_ipsDirectNameBlackList = NULL;
static	PWCHAR					g_reg_ipsDirectNameWhiteList = NULL;
static	KSPIN_LOCK				g_reg_ipsNameListlock = 0;

void rDirectory_IpsInit()
{
	KeInitializeSpinLock(&g_reg_ipsNameListlock);
}
void rDirectory_IpsClean()
{
	KLOCK_QUEUE_HANDLE lh;
	KeAcquireInStackQueuedSpinLock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsDirectNameBlackList)
	{
		ExFreePool(g_reg_ipsDirectNameBlackList);
		g_reg_ipsDirectNameBlackList = NULL;
	}
	if (g_reg_ipsDirectNameWhiteList)
	{
		ExFreePool(g_reg_ipsDirectNameWhiteList);
		g_reg_ipsDirectNameWhiteList = NULL;
	}
	if (g_reg_ipsProcNameBlackList)
	{
		ExFreePool(g_reg_ipsProcNameBlackList);
		g_reg_ipsProcNameBlackList = NULL;
	}
	if (g_reg_ipsProcNameWhiteList)
	{
		ExFreePool(g_reg_ipsProcNameWhiteList);
		g_reg_ipsProcNameWhiteList = NULL;
	}
	KeReleaseInStackQueuedSpinLock(&lh);
}
BOOLEAN rDirectory_IsIpsProcessNameInList(const PWCHAR path, const int mods)
{
	BOOLEAN bRet = FALSE;
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ipsNameListlock, &lh);
	if ((mods == 1) && g_reg_ipsProcNameWhiteList)
	{
		PWCHAR pName = wcsrchr(path, L'\\');
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsProcNameWhiteList;
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
	if ((mods == 2) && g_reg_ipsProcNameBlackList)
	{
		PWCHAR pName = wcsrchr(path, L'\\');
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsProcNameBlackList;
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
BOOLEAN rDirectory_IsIpsDirectNameInList(const PWCHAR path, int* mods)
{
	BOOLEAN bRet = FALSE;
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsDirectNameBlackList)
	{
		PWCHAR pName = wcsrchr(path, L'\\');
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsDirectNameBlackList;
			pName++;
			while (*pIpsName)
			{
				if (wcscmp(pIpsName, pName) == 0)
				{
					*mods = 2;
					bRet = TRUE;
					break;
				}
				while (*pIpsName++);
			}
		}
	}
	if (g_reg_ipsDirectNameWhiteList)
	{
		PWCHAR pName = wcsrchr(path, L'\\');
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsDirectNameWhiteList;
			pName++;
			while (*pIpsName)
			{
				if (wcscmp(pIpsName, pName) == 0)
				{
					*mods = 1;
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
NTSTATUS rDirectory_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	NTSTATUS status = STATUS_SUCCESS;

	rDirectory_IpsClean();
	{
	
	
	}
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

