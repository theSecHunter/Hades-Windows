#include "public.h"
#include "sysidt.h"

#define MAKE_LONG64(a,b) ((a) + (b<<16))  // X64
#define MAX_IDT 0x100

static BOOLEAN		g_idtInitflag = FALSE;
static IDTR			g_idtr;
static PIDT_ENTRY	g_pIdtEntry = NULL;

ULONG64 Idt_GetAddr64(PIDT_ENTRY IdtBaseAddr, UCHAR Index)
{
	PIDT_ENTRY pIdter = IdtBaseAddr;
	pIdter = pIdter + Index;
	ULONG64 uOffsetHigh, uOffsetMiddle, uOffsetLow, ret;
	uOffsetHigh = (ULONG64)pIdter->idt.OffsetHigh << 32;
	uOffsetMiddle = pIdter->idt.OffsetMiddle << 16;
	uOffsetLow = pIdter->idt.OffsetLow;
	ret = uOffsetHigh + uOffsetMiddle + uOffsetLow;
	return ret;
}

int nf_IdtInit()
{
	RtlSecureZeroMemory(&g_idtr, sizeof(IDTR));
#ifdef _WIN64
    __sidt(&g_idtr);
#else

#endif
	if (MmIsAddressValid((PVOID)g_idtr.Base) == TRUE)
	{
		g_idtInitflag = TRUE;
		return 1;
	}
	else
		return -1;
}

int nf_GetIdtTableInfo(IDTINFO* MemBuffer)
{
	if ((g_idtInitflag == FALSE) &&
		(g_idtr.limit <= 0))
	{
		return -1;
	}

	g_pIdtEntry = (PIDT_ENTRY)g_idtr.Base;
    if (MmIsAddressValid(g_pIdtEntry) == FALSE) {
        return -1;
    }

    ULONGLONG uaddress = 0;
	IDTINFO* idtinfo = VerifiExAllocatePoolTag(sizeof(IDTINFO), 'IDMM');
	if (!idtinfo)
		return -1;

	RtlSecureZeroMemory(idtinfo, sizeof(IDTINFO));
    for (ULONG i = 0; i < MAX_IDT; ++i)
    {
		idtinfo->idt_id = i;
		uaddress = Idt_GetAddr64(g_pIdtEntry, i);
		if (MmIsAddressValid((PVOID)uaddress) == FALSE)
			break;

		idtinfo->idt_isrmemaddr = uaddress;
		uaddress = 0;
		RtlCopyMemory(&MemBuffer[i], idtinfo, sizeof(IDTINFO));
		RtlSecureZeroMemory(idtinfo, sizeof(IDTINFO));
    }

	if (idtinfo)
	{
		ExFreePoolWithTag(idtinfo, 'IDMM');
		idtinfo = NULL;
	}

	return 1;
}