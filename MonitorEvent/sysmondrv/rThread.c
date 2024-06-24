#include "public.h"
#include "utiltools.h"
#include "rThread.h"

static  PWCHAR	    g_thrinject_ipsList = NULL;
static  KSPIN_LOCK  g_thrinject_ipsListlock = 0;

void rThrInject_IpsInit()
{
    sl_init(&g_thrinject_ipsListlock);
}
void rThrInject_IpsClean()
{
    KLOCK_QUEUE_HANDLE lh;
    sl_lock(&g_thrinject_ipsListlock, &lh);
    if (g_thrinject_ipsList)
    {
        ExFreePool(g_thrinject_ipsList);
        g_thrinject_ipsList = NULL;
    }
    sl_unlock(&lh);
}
BOOLEAN rThrInject_IsIpsProcessNameInList(const PWCHAR path)
{
    if (!g_thrinject_ipsList)
        return FALSE;
    BOOLEAN bRet = FALSE;
    KLOCK_QUEUE_HANDLE lh;
    sl_lock(&g_thrinject_ipsListlock, &lh);
    if (g_thrinject_ipsList)
    {
        PWCHAR pName = wcsrchr(path, L'\\');
        if (pName)
        {
            PWCHAR pIpsName = g_thrinject_ipsList;
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
NTSTATUS rThrInject_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    const PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    do
    {
        if (NULL == inputBuffer || inputBufferLength < sizeof(WCHAR))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        rThrInject_IpsClean();

        ULONG i = 0;
        PWCHAR p1 = NULL, p2 = NULL; 
        p1 = (PWCHAR)inputBuffer;
        if (!p1 || (p1 == NULL))
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        if (!NT_SUCCESS(MmIsAddressValid(p1))) {
            status = STATUS_INVALID_MEMBER;
            break;
        }
        p2 = VerifiExAllocatePoolTag(inputBufferLength, MEM_TAG_DK);
        if (!p2 || (p2 == NULL))
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        if (!NT_SUCCESS(MmIsAddressValid(p2))) {
            status = STATUS_INVALID_MEMBER;
            break;
        }
        RtlCopyMemory(p2, p1, inputBufferLength);
        inputBufferLength >>= 1;
        for (i = 0; i < inputBufferLength; i++)
        {
            if (p2[i] == L'|')
                p2[i] = 0;
        }
        p1 = g_thrinject_ipsList;
        g_thrinject_ipsList = p2;
        if (p1)
            ExFreePool(p1);
    } while (FALSE);

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}