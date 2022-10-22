#include "public.h"
#include "rDirectory.h"
#include "utiltools.h"
#include <stdlib.h>

static	PWCHAR					g_reg_ipsProcNameBlackList = NULL;
static	PWCHAR					g_reg_ipsProcNameWhiteList = NULL;
static	PWCHAR					g_reg_ipsDirectNameBlackList = NULL;
static	PWCHAR					g_reg_ipsDirectNameWhiteList = NULL;
static	KSPIN_LOCK				g_reg_ipsNameListlock = 0;

void rDirectory_IpsInit()
{
	KeInitializeSpinLock(&g_reg_ipsNameListlock);
}
void rDirectory_IpsCleanEx(const int flag)
{
	KLOCK_QUEUE_HANDLE lh;
	KeAcquireInStackQueuedSpinLock(&g_reg_ipsNameListlock, &lh);
	if ((flag == 1) && g_reg_ipsDirectNameBlackList)
	{
		ExFreePool(g_reg_ipsDirectNameBlackList);
		g_reg_ipsDirectNameBlackList = NULL;
	}
	else if ((flag == 2) && g_reg_ipsDirectNameWhiteList)
	{
		ExFreePool(g_reg_ipsDirectNameWhiteList);
		g_reg_ipsDirectNameWhiteList = NULL;
	}
	else if ((flag == 3) && g_reg_ipsProcNameBlackList)
	{
		ExFreePool(g_reg_ipsProcNameBlackList);
		g_reg_ipsProcNameBlackList = NULL;
	}
	else if ((flag == 4) && g_reg_ipsProcNameWhiteList)
	{
		ExFreePool(g_reg_ipsProcNameWhiteList);
		g_reg_ipsProcNameWhiteList = NULL;
	}
	KeReleaseInStackQueuedSpinLock(&lh);
}
void rDirectory_IpsClean() 
{
	rDirectory_IpsCleanEx(1);
	rDirectory_IpsCleanEx(2);
	rDirectory_IpsCleanEx(3);
	rDirectory_IpsCleanEx(4);
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
BOOLEAN rDirectory_IsIpsDirectNameInList(_In_ const PWCHAR FileDirectPath, _Out_ int* mods)
{
	if (!mods)
		return _Success_(FALSE);

	// Directory
	BOOLEAN bRet = FALSE;
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsDirectNameBlackList)
	{
		PWCHAR pName = wcsrchr(FileDirectPath, L'\\');
		pName[0] = '\x0';
		pName[1] = '\x0';
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsDirectNameBlackList;
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
	if (!bRet && g_reg_ipsDirectNameWhiteList)
	{
		PWCHAR pName = wcsrchr(FileDirectPath, L'\\');
		pName[0] = '\x0';
		pName[1] = '\x0';
		if (pName)
		{
			PWCHAR pIpsName = g_reg_ipsDirectNameWhiteList;
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
	return _Success_(bRet);
}
NTSTATUS rDirectory_SetIpsDirectRule(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status = STATUS_SUCCESS;
	do 
	{
		if (NULL == inputBuffer || inputBufferLength < sizeof(WCHAR))
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		PWCHAR p1, p2; ULONG i;
		p1 = (PWCHAR)inputBuffer;
		const CHAR chrflag = p1[0];
		const int dwflag = atoi(&chrflag);
		rDirectory_IpsCleanEx(dwflag);
		p2 = ExAllocatePoolWithTag(NonPagedPool, inputBufferLength, MEM_TAG_DK);
		if (NULL == p2)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		const PWCHAR pwPtr = p1 + 1;
		RtlCopyMemory(p2, pwPtr, inputBufferLength);
		inputBufferLength >>= 1;
		for (i = 0; i < inputBufferLength; i++)
		{
			if (p2[i] == L'|')
				p2[i] = 0;
		}
		switch (dwflag)
		{
			case 1:
			{
				p1 = g_reg_ipsProcNameWhiteList;
				g_reg_ipsProcNameWhiteList = p2;
			}
			break;
			case 2:
			{
				p1 = g_reg_ipsProcNameBlackList;
				g_reg_ipsProcNameBlackList = p2;
			}
			break;
			case 3:
			{
				p1 = g_reg_ipsDirectNameWhiteList;
				g_reg_ipsDirectNameWhiteList = p2;
			}
			break;
			case 4:
			{
				p1 = g_reg_ipsDirectNameBlackList;
				g_reg_ipsDirectNameBlackList = p2;
			}
			break;
		}
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

