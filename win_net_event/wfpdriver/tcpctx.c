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
static NPAGED_LOOKASIDE_LIST	g_packetsLAList;

typedef struct _NF_PACKET
{
	LIST_ENTRY			entry;
	PTCPCTX				pTcpCtx;
	UINT32				calloutId;
	BOOLEAN				isClone;
	FWPS_STREAM_DATA	streamData;			// Packet data
	char*				flatStreamData;		// Flat buffer for large packets
	UINT64				flatStreamOffset;	// Current offset in flatStreamData
} NF_PACKET, * PNF_PACKET;

// 申请缓冲及消息队列结构
PNF_TCPCTX_BUFFER tcpctxctx_packallocate(int lens)
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
VOID tcpctxctx_packfree(PNF_TCPCTX_BUFFER pPacket)
{
	if (pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_tcpctxPacketsList, pPacket);
}
NTSTATUS push_tcpRedirectinfo(PVOID64 packet, int lens)
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

	devctrl_pushEventQueryLisy(NF_TCPREDIRECTCONNECT_PACKET);

	return status;
}

// 申请ctx结构体结构
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
		remove_tcpHandle(pTcpCtx);
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

void tcpctx_freePacket(PNF_PACKET pPacket)
{
	KdPrint((DPREFIX"tcpctx_freePacket %I64x\n", (unsigned __int64)pPacket));

	if (pPacket->streamData.netBufferListChain)
	{
		if (pPacket->isClone)
		{
			BOOLEAN isDispatch = (KeGetCurrentIrql() == DISPATCH_LEVEL) ? TRUE : FALSE;
			FwpsDiscardClonedStreamData(pPacket->streamData.netBufferListChain, 0, isDispatch);
		} else
		{
			FwpsFreeNetBufferList(pPacket->streamData.netBufferListChain);

			if (pPacket->streamData.dataOffset.mdl != NULL)
			{
				free_np(pPacket->streamData.dataOffset.mdl->MappedSystemVa);
				IoFreeMdl(pPacket->streamData.dataOffset.mdl);
			}
		}
		pPacket->streamData.netBufferListChain = NULL;
	}
	if (pPacket->flatStreamData)
	{
		free_np(pPacket->flatStreamData);
		pPacket->flatStreamData = NULL;
	}

	ExFreeToNPagedLookasideList( &g_packetsLAList, pPacket );
}

void tcpctx_cleanupFlows()
{
	KLOCK_QUEUE_HANDLE lh, lhp;
	PTCPCTX pTcpCtx;
	NF_PACKET* pPacket;
	LIST_ENTRY packets;

	KdPrint((DPREFIX"tcpctx_cleanupFlows\n"));

	InitializeListHead(&packets);

	sl_lock(&g_slTcpCtx, &lh);

	pTcpCtx = (PTCPCTX)g_lTcpCtx.Flink;

	while (pTcpCtx != (PTCPCTX)&g_lTcpCtx)
	{
		sl_lock(&pTcpCtx->lock, &lhp);
		while (!IsListEmpty(&pTcpCtx->pendedPackets))
		{
			pPacket = (PNF_PACKET)RemoveHeadList(&pTcpCtx->pendedPackets);
			InsertTailList(&packets, &pPacket->entry);
			KdPrint((DPREFIX"tcpctx_cleanupFlows packet in TCPCTX %I64u\n", pTcpCtx->id));
		}
		while (!IsListEmpty(&pTcpCtx->injectPackets))
		{
			pPacket = (PNF_PACKET)RemoveHeadList(&pTcpCtx->injectPackets);
			InsertTailList(&packets, &pPacket->entry);
			KdPrint((DPREFIX"tcpctx_cleanupFlows reinject packet in TCPCTX %I64u\n", pTcpCtx->id));
		}
		sl_unlock(&lhp);

		pTcpCtx = (PTCPCTX)pTcpCtx->entry.Flink;
	}

	sl_unlock(&lh);

	while (!IsListEmpty(&packets))
	{
		pPacket = (PNF_PACKET)RemoveHeadList(&packets);
		tcpctx_freePacket(pPacket);
	}
}
void tcpctx_removeFromFlows()
{
	KLOCK_QUEUE_HANDLE lh;
	PTCPCTX pTcpCtx;
	NTSTATUS status;

	KdPrint((DPREFIX"tcpctx_removeFromFlows\n"));

	tcpctx_cleanupFlows();

	sl_lock(&g_slTcpCtx, &lh);

	while (!IsListEmpty(&g_lTcpCtx))
	{
		pTcpCtx = (PTCPCTX)RemoveHeadList(&g_lTcpCtx);

		InitializeListHead(&pTcpCtx->entry);

		KdPrint((DPREFIX"tcpctx_removeFromFlows(): TCPCTX [%I64d]\n", pTcpCtx->id));

		pTcpCtx->refCount++;

		sl_unlock(&lh);

		status = FwpsFlowRemoveContext(pTcpCtx->flowHandle,
			pTcpCtx->layerId,
			pTcpCtx->sendCalloutId);
		ASSERT(NT_SUCCESS(status));

		status = FwpsFlowRemoveContext(pTcpCtx->flowHandle,
			pTcpCtx->layerId,
			pTcpCtx->recvCalloutId);
		ASSERT(NT_SUCCESS(status));

		status = FwpsFlowRemoveContext(pTcpCtx->flowHandle,
			pTcpCtx->layerId,
			pTcpCtx->recvProtCalloutId);
		ASSERT(NT_SUCCESS(status));

		status = FwpsFlowRemoveContext(pTcpCtx->flowHandle,
			pTcpCtx->transportLayerIdOut,
			pTcpCtx->transportCalloutIdOut);
		ASSERT(NT_SUCCESS(status));

		status = FwpsFlowRemoveContext(pTcpCtx->flowHandle,
			pTcpCtx->transportLayerIdIn,
			pTcpCtx->transportCalloutIdIn);
		ASSERT(NT_SUCCESS(status));

		if (pTcpCtx->transportEndpointHandle != 0)
		{
			tcpctx_release(pTcpCtx);
		}

		tcpctx_release(pTcpCtx);

		sl_lock(&g_slTcpCtx, &lh);
	}

	sl_unlock(&lh);
}
void tcpctx_releaseFlows()
{
	KLOCK_QUEUE_HANDLE lh;
	PTCPCTX pTcpCtx;

	KdPrint((DPREFIX"tcpctx_releaseFlows\n"));

	sl_lock(&g_slTcpCtx, &lh);

	while (!IsListEmpty(&g_lTcpCtx))
	{
		pTcpCtx = (PTCPCTX)g_lTcpCtx.Flink;

		sl_unlock(&lh);

		tcpctx_release(pTcpCtx);

		sl_lock(&g_slTcpCtx, &lh);
	}

	sl_unlock(&lh);
}

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
		MEM_TAG_TCP,
		0
	);

	ExInitializeNPagedLookasideList(
		&g_packetsLAList,
		NULL,
		NULL,
		0,
		sizeof(NF_PACKET),
		MEM_TAG_TCP_PACKET,
		0);

	sl_init(&g_slTcpCtx);
	InitializeListHead(&g_lTcpCtx);

	sl_init(&g_tcpctx_data.lock);
	InitializeListHead(&g_tcpctx_data.pendedPackets);

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

	tcpctx_removeFromFlows();
	devctrl_sleep(1000);

	tcpctx_releaseFlows();
}
VOID tcpctxctx_free()
{
	tcpctxctx_clean();

	if (g_phtTcpCtxById)
	{
		hash_table_free(g_phtTcpCtxById);
		g_phtTcpCtxById = NULL;
	}

	if (g_phtTcpCtxByHandle)
	{
		hash_table_free(g_phtTcpCtxByHandle);
		g_phtTcpCtxByHandle = NULL;
	}

	ExDeleteNPagedLookasideList(&g_tcpCtxLAList);
	ExDeleteNPagedLookasideList(&g_packetsLAList);
	ExDeleteNPagedLookasideList(&g_tcpctxPacketsList);
}

/*
	散列表操作
*/
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


