#ifndef _SYSDPCTIMER_H
#define _SYSDPCTIMER_H

typedef struct _DPC_TIMERINFO
{
	ULONG_PTR	dpc;
	ULONG_PTR	timerobject;
	ULONG_PTR	timeroutine;
	ULONG		period;
}DPC_TIMERINFO, * PDPC_TIMERINFO;

typedef struct _KTIMER_TABLE_ENTRY
{
	ULONG64			Lock;
	LIST_ENTRY		Entry;
	ULARGE_INTEGER	Time;
} KTIMER_TABLE_ENTRY, * PKTIMER_TABLE_ENTRY;

int nf_GetDpcTimerInfoData(DPC_TIMERINFO* MemBuffer);

#endif // !_SYSDPCTIMER_H
