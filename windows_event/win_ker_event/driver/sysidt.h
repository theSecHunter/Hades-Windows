#ifndef _SYSIDT_H
#define _SYSIDT_H

#pragma pack(1)
typedef struct _IDTR
{
	USHORT limit;
	//ULONG32 ulowBase;
	//ULONG32 uhighBase;
	ULONG64 Base;
}IDTR, * PIDTR;

typedef union _IDT_ENTRY
{
	struct kidt
	{
		USHORT OffsetLow;
		USHORT Selector;
		USHORT IstIndex : 3;
		USHORT Reserved0 : 5;
		USHORT Type : 5;
		USHORT Dpl : 2;
		USHORT Present : 1;
		USHORT OffsetMiddle;
		ULONG OffsetHigh;
		ULONG Reserved1;
	}idt;
	UINT64 Alignment;
}IDT_ENTRY, * PIDT_ENTRY;
#pragma pack()

typedef struct _IDT_INFO
{
	ULONG		nIndex;
	ULONGLONG	pNowAddress;
	ULONGLONG	pOriginAddress;
	ULONGLONG	pInlineHookAddress;
}IDT_INFO, * PIDT_INFO;

typedef struct _IDTINFO
{
	int			    idt_id;
	ULONGLONG		idt_isrmemaddr;
}IDTINFO, * PIDTINFO;

int Idt_Init();
int Idt_GetTableInfo(IDTINFO* MemBuffer);

#endif // !_SYSIDT_H
