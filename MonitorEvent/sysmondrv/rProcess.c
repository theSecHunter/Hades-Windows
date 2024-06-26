#include "public.h"
#include "rProcess.h" 
#include "utiltools.h"

static  PWCHAR	    g_proc_ipsList = NULL;
static  KSPIN_LOCK  g_proc_ipsListlock = 0;

void rProcess_IpsInit()
{
    sl_init(&g_proc_ipsListlock);
}
void rProcess_IpsClean()
{
    KLOCK_QUEUE_HANDLE lh;
    sl_lock(&g_proc_ipsListlock, &lh);
    if (g_proc_ipsList)
    {
        ExFreePool(g_proc_ipsList);
        g_proc_ipsList = NULL;
    }
    sl_unlock(&lh);
}
BOOLEAN rProcess_IsIpsProcessNameInList(const PWCHAR path)
{
    if (!g_proc_ipsList)
        return FALSE;
    BOOLEAN bRet = FALSE;
    KLOCK_QUEUE_HANDLE lh;
    sl_lock(&g_proc_ipsListlock, &lh);
    if (g_proc_ipsList)
    {
        PWCHAR pName = wcsrchr(path, L'\\');
        if (pName)
        {
            PWCHAR pIpsName = g_proc_ipsList;
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
NTSTATUS rProcess_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp)
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
        rProcess_IpsClean();

        ULONG i = 0;
        PWCHAR p1 = NULL, p2 = NULL;
        p1 = (PWCHAR)inputBuffer;
        if (p1 == NULL || (!p1))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!NT_SUCCESS(MmIsAddressValid(p1))) {
            status = STATUS_INVALID_MEMBER;
            break;
        }
        p2 = VerifiExAllocatePoolTag(inputBufferLength + 1, MEM_TAG_DK);
        if (NULL == p2 || (!p2))
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
            const WCHAR* pCompare = &p2[i];
            if (*pCompare == L'|')
                p2[i] = 0;
        }
        p1 = g_proc_ipsList;
        g_proc_ipsList = p2;
        if (p1)
            ExFreePool(p1);
    } while (FALSE);

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}