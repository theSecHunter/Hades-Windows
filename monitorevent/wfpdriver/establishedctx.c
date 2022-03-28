#include "public.h"
#include "devctrl.h"
#include "establishedctx.h"

static NPAGED_LOOKASIDE_LIST	g_establishedList;
static NF_FLOWESTABLISHED_DATA	g_flowesobj;

NTSTATUS establishedctx_init()
{
	NTSTATUS status = STATUS_SUCCESS;

	ExInitializeNPagedLookasideList(
		&g_establishedList,
		NULL,
		NULL,
		0,
		sizeof(NF_FLOWESTABLISHED_BUFFER),
		'SWSW',
		0
	);

	KeInitializeSpinLock(&g_flowesobj.lock);
	InitializeListHead(&g_flowesobj.pendedPackets);

	return status;
}

VOID establishedctx_clean()
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_FLOWESTABLISHED_BUFFER p_flowdata = NULL;
	sl_lock(&g_flowesobj.lock, &lh);
	while (!IsListEmpty(&g_flowesobj.pendedPackets))
	{
		p_flowdata = RemoveHeadList(&g_flowesobj.pendedPackets);
		sl_unlock(&lh);
		establishedctx_packfree(p_flowdata);
		p_flowdata = NULL;
		sl_lock(&g_flowesobj.lock, &lh);
	}
	sl_unlock(&lh);
}

VOID establishedctx_free()
{
	establishedctx_clean();
	ExDeleteNPagedLookasideList(&g_establishedList);
}

NF_FLOWESTABLISHED_BUFFER* establishedctx_packallocte(int lens)
{
	if (lens < 0)
		return NULL;

	PNF_FLOWESTABLISHED_BUFFER pNfdatalink = NULL;
	pNfdatalink = (PNF_FLOWESTABLISHED_BUFFER)ExAllocateFromNPagedLookasideList(&g_establishedList);
	if (!pNfdatalink)
		return FALSE;

	memset(pNfdatalink, 0, sizeof(NF_FLOWESTABLISHED_BUFFER));

	if (lens > 0)
	{
		pNfdatalink->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'DPLC');
		if (!pNfdatalink->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_establishedList, pNfdatalink);
			return FALSE;
		}
	}
	return pNfdatalink;
}

VOID establishedctx_packfree(
	PNF_FLOWESTABLISHED_BUFFER pPacket
)
{
	if (pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_establishedList, pPacket);
}

NTSTATUS establishedctx_pushflowestablishedctx(
	PVOID64 pBuffer, 
	int lens
)
{
	KLOCK_QUEUE_HANDLE lh;
	NTSTATUS status = STATUS_SUCCESS;
	PNF_FLOWESTABLISHED_BUFFER flowbuf = NULL;

	if (!pBuffer && (lens < 1))
		return FALSE;

	flowbuf = establishedctx_packallocte(lens);
	if (!flowbuf)
		return STATUS_UNSUCCESSFUL;

	flowbuf->dataLength = lens;
	RtlCopyMemory(flowbuf->dataBuffer, pBuffer, lens);

	sl_lock(&g_flowesobj.lock, &lh);
	InsertHeadList(&g_flowesobj.pendedPackets, &flowbuf->pEntry);
	sl_unlock(&lh);

	devctrl_pushEventQueryLisy(NF_FLOWCTX_PACKET);

	return status;
}

NF_FLOWESTABLISHED_DATA* establishedctx_get()
{
	return &g_flowesobj;
}