#include "public.h"
#include "flowctl.h"


static LIST_ENTRY g_lFlowCtl;
static NPAGED_LOOKASIDE_LIST g_flowCtlLAList;
static KSPIN_LOCK g_sl;

typedef struct _NF_FLOW_CTL
{
	LIST_ENTRY	entry;

	tFlowControlHandle	id;
	// PHASH_TABLE_ENTRY	id_next;

	uint64_t	inLimit;
	uint64_t	outLimit;

	uint64_t	inBucket;
	uint64_t	outBucket;

	uint64_t	inCounter;
	uint64_t	outCounter;

	uint64_t	ts;
} NF_FLOW_CTL, * PNF_FLOW_CTL;


VOID flowctl_free()
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_FLOW_CTL pFlowCtl;

	sl_lock(&g_sl, &lh);

	while (!IsListEmpty(&g_lFlowCtl))
	{
		pFlowCtl = (PNF_FLOW_CTL)RemoveHeadList(&g_lFlowCtl);
		sl_unlock(&lh);
		ExFreeToNPagedLookasideList(&g_flowCtlLAList, pFlowCtl);
		sl_lock(&g_sl, &lh);
	}
	sl_unlock(&lh);

	ExDeleteNPagedLookasideList(&g_flowCtlLAList);
}

BOOLEAN flowctl_init()
{
    ExInitializeNPagedLookasideList(&g_flowCtlLAList,
        NULL,
        NULL,
        0,
        sizeof(NF_FLOW_CTL),
        MEM_TAG,
        0);
    InitializeListHead(&g_lFlowCtl);
    KeInitializeSpinLock(&g_sl);
    return TRUE;

}