#include "public.h"
#include "devctrl.h"
#include "establishedctx.h"

static NF_FLOWESTABLISHED_DATA	g_flowesobj;
static NPAGED_LOOKASIDE_LIST	g_establishedList;

NTSTATUS establishedctx_init()
{
	NTSTATUS status = STATUS_SUCCESS;

	VerifiExInitializeNPagedLookasideList(
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
	PNF_FLOWESTABLISHED_BUFFER pFlowData = NULL;

	sl_lock(&g_flowesobj.lock, &lh);
	while (!IsListEmpty(&g_flowesobj.pendedPackets))
	{
		pFlowData = (PNF_FLOWESTABLISHED_BUFFER)RemoveHeadList(&g_flowesobj.pendedPackets);
		if (pFlowData) {
			sl_unlock(&lh);
			establishedctx_packfree(pFlowData);
			pFlowData = NULL;
			sl_lock(&g_flowesobj.lock, &lh);
		}
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

	PNF_FLOWESTABLISHED_BUFFER pEsTabData = NULL;
	pEsTabData = (PNF_FLOWESTABLISHED_BUFFER)ExAllocateFromNPagedLookasideList(&g_establishedList);
	if (!pEsTabData)
		return NULL;

	RtlSecureZeroMemory(pEsTabData, sizeof(NF_FLOWESTABLISHED_BUFFER));

	if (lens > 0)
	{
#if (NTDDI_VERSION >= NTDDI_WIN8)
		pEsTabData->dataBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, lens, 'DPLC');
#else
		pEsTabData->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'DPLC');
#endif
		if (!pEsTabData->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_establishedList, pEsTabData);
			return NULL;
		}
	}
	return pEsTabData;
}

VOID establishedctx_packfree(PNF_FLOWESTABLISHED_BUFFER pPacket)
{
	if (pPacket && pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	if (pPacket)
		ExFreeToNPagedLookasideList(&g_establishedList, pPacket);
}

NTSTATUS establishedctx_pushflowestablishedctx(PVOID64 pBuffer, int lens)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_FLOWESTABLISHED_BUFFER pFlowPacket = NULL;

	if (!pBuffer && (lens < 1))
		return STATUS_UNSUCCESSFUL;

	pFlowPacket = establishedctx_packallocte(lens);
	if (!pFlowPacket || !pFlowPacket->dataBuffer)
		return STATUS_UNSUCCESSFUL;

	pFlowPacket->dataLength = lens;
	RtlCopyMemory(pFlowPacket->dataBuffer, pBuffer, lens);

	sl_lock(&g_flowesobj.lock, &lh);
	InsertHeadList(&g_flowesobj.pendedPackets, &pFlowPacket->pEntry);
	sl_unlock(&lh);

	devctrl_pushEventQueryLisy(NF_ESTABLISHED_LAYER_PACKET);

	return STATUS_SUCCESS;
}

NF_FLOWESTABLISHED_DATA* establishedctx_get()
{
	return &g_flowesobj;
}