#include "public.h"
#include "rRegister.h"
#include "utiltools.h"

static	PWCHAR					g_reg_ipsNameList = NULL;
static	KSPIN_LOCK				g_reg_ipsNameListlock = 0;

void rRegister_IpsInit()
{
	KeInitializeSpinLock(&g_reg_ipsNameListlock);
}
void rRegister_IpsClean()
{
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_reg_ipsNameListlock, &lh);
	if (g_reg_ipsNameList)
	{
		ExFreePool(g_reg_ipsNameList);
		g_reg_ipsNameList = NULL;
	}
	sl_unlock(&lh);
}
BOOLEAN rRegister_IsIpsProcessNameInList(const PWCHAR path)
{
	if (!g_reg_ipsNameList)
		return FALSE;

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
NTSTATUS rRegister_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		if (NULL == inputBuffer || inputBufferLength < sizeof(WCHAR))
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		rRegister_IpsClean();
		PWCHAR p1, p2; ULONG i;
		p1 = (PWCHAR)inputBuffer;
		p2 = VerifiExAllocatePoolTag(inputBufferLength, MEM_TAG_DK);
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