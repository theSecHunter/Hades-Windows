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
    const PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;
    do
    {
        if (NULL == inputBuffer || inputBufferLength < sizeof(WCHAR))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        rProcess_IpsClean();
        PWCHAR p1, p2; ULONG i;
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
        p1 = g_proc_ipsList;
        g_proc_ipsList = p2;
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