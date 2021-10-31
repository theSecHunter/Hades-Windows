#include "public.h"
#include "sysidt.h"

#define MAKE_LONG64(a,b) ((a) + (b<<32))  // X64
#define MAX_IDT 0x100

static IDTR g_idtr;
static PIDT_ENTRY pIdtEntry = NULL;

int Idt_Init()
{
    DbgBreakPoint();
	RtlSecureZeroMemory(&g_idtr, sizeof(IDTR));
    // KeSetSystemAffinityThread(1);
	// KeRevertToUserAffinityThread();
    __sidt(&g_idtr);

	if (g_idtr.uhighBase && g_idtr.ulowBase)
		return 1;
	else
		return -1;
}

int Idt_GetTableInfo()
{
    DbgBreakPoint();
    pIdtEntry = (PIDT_ENTRY)MAKE_LONG64(g_idtr.ulowBase, g_idtr.uhighBase);
    if (!pIdtEntry)
        return -1;

    ULONGLONG uaddress = 0;
    for (ULONG i = 0; i < MAX_IDT; ++i)
    {
        // index=1 ; IDTAddr = uaddress;
        uaddress = MAKE_LONG64(pIdtEntry[i].idt.OffsetLow, pIdtEntry[i].idt.OffsetHigh);
    }

	return 1;
}