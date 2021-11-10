#include "public.h"
#include "devctrl.h"
#include "tcpctx.h"

static LIST_ENTRY	g_lTcpCtx;
static KSPIN_LOCK	g_slTcpCtx;

static PHASH_TABLE	g_phtTcpCtxById = NULL;
static PHASH_TABLE	g_phtTcpCtxByHandle = NULL;

static NPAGED_LOOKASIDE_LIST	g_tcpctxPacketsList;
static NF_TCPCTX_DATA			g_tcpctx_data;
static __int64					g_nextTcpCtxId;
static NPAGED_LOOKASIDE_LIST	g_tcpCtxLAList;

NF_TCPCTX_DATA* tcpctx_get()
{
	return &g_tcpctx_data;
}
NTSTATUS tcpctxctx_init()
{
	NTSTATUS status = STATUS_SUCCESS;
	ExInitializeNPagedLookasideList(
		&g_tcpctxPacketsList,
		NULL,
		NULL,
		0,
		sizeof(NF_TCPCTX_BUFFER),
		MEM_TAG_NETWORK,
		0
	);

	ExInitializeNPagedLookasideList(
		&g_tcpCtxLAList,
		NULL,
		NULL,
		0,
		sizeof(TCPCTX),
		MEM_TAG_TCP_PACKET,
		0
	);
	
	sl_init(&g_slTcpCtx);
	InitializeListHead(&g_lTcpCtx);

	sl_init(&g_tcpctx_data.lock);
	InitializeListHead(&g_tcpctx_data.pendedPackets);

	return status;
}

PNF_TCPCTX_BUFFER tcpctxctx_packallocate(
	int lens
)
{
	if (lens < 0)
		return NULL;
	PNF_TCPCTX_BUFFER pTcpctx = NULL;
	pTcpctx = ExAllocateFromNPagedLookasideList(&g_tcpctxPacketsList);
	if (!pTcpctx)
		return FALSE;

	memset(pTcpctx, 0, sizeof(NF_TCPCTX_BUFFER));

	if (lens > 0)
	{
		pTcpctx->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'TCLC');
		if (!pTcpctx->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_tcpctxPacketsList, pTcpctx);
			return FALSE;
		}
	}
	return pTcpctx;
}


PTCPCTX tcpctxctx_packallocatectx()
{
	KLOCK_QUEUE_HANDLE lh;
	PTCPCTX pTcpCtx = NULL;
	pTcpCtx = ExAllocateFromNPagedLookasideList(&g_tcpCtxLAList);
	if (!pTcpCtx)
		return FALSE;
	memset(pTcpCtx, 0, sizeof(TCPCTX));

	sl_init(&pTcpCtx->lock);
	pTcpCtx->refCount = 1;

	InitializeListHead(&pTcpCtx->pendedPackets);
	InitializeListHead(&pTcpCtx->injectPackets);

	sl_lock(&g_slTcpCtx, &lh);
	pTcpCtx->id = g_nextTcpCtxId++;
	ht_add_entry(g_phtTcpCtxById, (PHASH_TABLE_ENTRY)&pTcpCtx->id);
	InsertTailList(&g_lTcpCtx, &pTcpCtx->entry);
	sl_unlock(&lh);

	return pTcpCtx;
}

VOID tcpctx_release(PTCPCTX pTcpCtx)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slTcpCtx, &lh);

	if (pTcpCtx->refCount == 0)
	{
		sl_unlock(&lh);
		return;
	}

	pTcpCtx->refCount--;

	if (pTcpCtx->refCount > 0)
	{
		sl_unlock(&lh);
		return;
	}

	ht_remove_entry(g_phtTcpCtxById, pTcpCtx->id);
	RemoveEntryList(&pTcpCtx->entry);

	sl_unlock(&lh);

	if (pTcpCtx->transportEndpointHandle)
	{
		tcpctx_removeFromHandleTable(pTcpCtx);
		pTcpCtx->transportEndpointHandle = 0;
	}

	if (pTcpCtx->inInjectQueue)
	{
		ASSERT(0);
		KdPrint((DPREFIX"tcpctx_release orphan TCPCTX %I64u in inject queue\n", pTcpCtx->id));
	}

	tcpctx_purgeRedirectInfo(pTcpCtx);

	ExFreeToNPagedLookasideList(&g_tcpCtxLAList, pTcpCtx);
}

VOID tcpctxctx_packfree(
	PNF_TCPCTX_BUFFER pPacket
)
{
	if (pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_tcpctxPacketsList, pPacket);
}
NTSTATUS push_tcpRedirectinfo(
	PVOID64 packet,
	int lens
)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;
	PNF_TCPCTX_BUFFER ptcpctxinfo = NULL;

	if (!packet && (lens < 1))
		return FALSE;

	// Allocate 
	ptcpctxinfo = tcpctxctx_packallocate(lens);
	if (!ptcpctxinfo)
	{
		return FALSE;
	}

	ptcpctxinfo->dataLength = lens;
	RtlCopyMemory(ptcpctxinfo->dataBuffer, packet, lens);

	sl_lock(&g_tcpctx_data.lock, &lh);
	InsertHeadList(&g_tcpctx_data.pendedPackets, &ptcpctxinfo->pEntry);
	sl_unlock(&lh);

	devctrl_pushTcpCtxBuffer(NF_TCPREDIRECTCONNECT_PACKET);

	return status;
}

VOID tcpctxctx_clean()
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_TCPCTX_BUFFER pTcpCtx;

	sl_lock(&g_tcpctx_data.lock, &lh);
	while (!IsListEmpty(&g_tcpctx_data.pendedPackets))
	{
		pTcpCtx = (PNF_TCPCTX_BUFFER)RemoveHeadList(&g_tcpctx_data.pendedPackets);
		sl_unlock(&lh);
		tcpctxctx_packfree(pTcpCtx);
		pTcpCtx = NULL;
		sl_lock(&g_tcpctx_data.lock, &lh);
	}
	sl_unlock(&lh);
}
VOID tcpctxctx_free()
{
	tcpctxctx_clean();
	ExDeleteNPagedLookasideList(&g_tcpctxPacketsList);
}

PTCPCTX tcpctx_find(UINT64 id)
{
	PTCPCTX pTcpCtx = NULL;
	PHASH_TABLE_ENTRY phte;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slTcpCtx, &lh);
	phte = ht_find_entry(g_phtTcpCtxById, id);
	if (phte)
	{
		pTcpCtx = (PTCPCTX)CONTAINING_RECORD(phte, TCPCTX, id);
		pTcpCtx->refCount++;
	}
	sl_unlock(&lh);

	return pTcpCtx;
}
PTCPCTX tcpctx_findByHandle(UINT64 handle)
{
	PTCPCTX pTcpCtx = NULL;
	PHASH_TABLE_ENTRY phte;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slTcpCtx, &lh);
	phte = ht_find_entry(g_phtTcpCtxByHandle, handle);
	if (phte)
	{
		pTcpCtx = (PTCPCTX)CONTAINING_RECORD(phte, TCPCTX, transportEndpointHandle);
		pTcpCtx->refCount++;
	}
	sl_unlock(&lh);

	return pTcpCtx;
}
void add_tcpHandle(PTCPCTX ptcpctx)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slTcpCtx, &lh);
	ht_add_entry(g_phtTcpCtxByHandle, (PHASH_TABLE_ENTRY)&ptcpctx->transportEndpointHandle);
	sl_unlock(&lh);
}
void remove_tcpHandle(PTCPCTX ptcpctx)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slTcpCtx, &lh);
	ht_remove_entry(g_phtTcpCtxByHandle, ptcpctx->transportEndpointHandle);
	sl_unlock(&lh);
}
void tcpctx_purgeRedirectInfo(PTCPCTX pTcpCtx)
{
	UINT64 classifyHandle = pTcpCtx->redirectInfo.classifyHandle;

	if (classifyHandle)
	{
		pTcpCtx->redirectInfo.classifyHandle = 0;

		if (pTcpCtx->redirectInfo.isPended)
		{
			FwpsCompleteClassify(classifyHandle,
				0,
				&pTcpCtx->redirectInfo.classifyOut);

			pTcpCtx->redirectInfo.isPended = FALSE;
		}

#ifdef USE_NTDDI
#if (NTDDI_VERSION >= NTDDI_WIN8)
		if (pTcpCtx->redirectInfo.redirectHandle)
		{
			FwpsRedirectHandleDestroy(pTcpCtx->redirectInfo.redirectHandle);
			pTcpCtx->redirectInfo.redirectHandle = 0;
		}
#endif
#endif

		FwpsReleaseClassifyHandle(classifyHandle);
	}
}

