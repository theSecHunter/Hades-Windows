#include "public.h"
#include "devctrl.h"
#include "tcpctx.h"

static LIST_ENTRY	g_lTcpCtx;
static KSPIN_LOCK	g_slTcpCtx;

static PHASH_TABLE	g_phtTcpCtxById = NULL;
static PHASH_TABLE	g_phtTcpCtxByHandle = NULL;

static NPAGED_LOOKASIDE_LIST	g_tcpctxPacketsBufList;

static NF_TCPCTX_DATA			g_tcpctx_data;
static __int64					g_nextTcpCtxId;
static NPAGED_LOOKASIDE_LIST	g_tcpCtxLAList;
static NPAGED_LOOKASIDE_LIST	g_packetsLAList;

static BOOLEAN		g_initialized = FALSE;

typedef struct _NF_PACKET
{
    LIST_ENTRY			entry;
    PTCPCTX				pTcpCtx;
    UINT32				calloutId;
    BOOLEAN				isClone;
    FWPS_STREAM_DATA	streamData;			// Packet data
    char*               flatStreamData;		// Flat buffer for large packets
    UINT64				flatStreamOffset;	// Current offset in flatStreamData
} NF_PACKET, * PNF_PACKET;

// 申请缓冲及消息队列结构
PNF_TCP_BUFFER tcp_packallocate(int lens)
{
	if (lens < 0)
		return NULL;
	PNF_TCP_BUFFER pTcpctx = NULL;
	pTcpctx = ExAllocateFromNPagedLookasideList(&g_tcpctxPacketsBufList);
	if (!pTcpctx)
		return NULL;
	RtlSecureZeroMemory(pTcpctx, sizeof(NF_TCP_BUFFER));

	if (lens > 0)
	{
		pTcpctx->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'TCLC');
		if (!pTcpctx->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_tcpctxPacketsBufList, pTcpctx);
			return NULL;
		}
	}
	return pTcpctx;
}
VOID tcp_packfree(PNF_TCP_BUFFER pPacket)
{
	if (pPacket && pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	if (pPacket)
		ExFreeToNPagedLookasideList(&g_tcpctxPacketsBufList, pPacket);
}
NTSTATUS push_tcpRedirectinfo(PVOID packet, int lens)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_TCP_BUFFER pTcpCtxInfo = NULL;

	if (!packet && (lens < 1))
		return STATUS_UNSUCCESSFUL;

	// Allocate 
	pTcpCtxInfo = tcp_packallocate(lens);
	if (!pTcpCtxInfo || !pTcpCtxInfo->dataBuffer)
		return STATUS_UNSUCCESSFUL;

	pTcpCtxInfo->dataLength = lens;
	RtlCopyMemory(pTcpCtxInfo->dataBuffer, packet, lens);

	sl_lock(&g_tcpctx_data.lock, &lh);
	InsertHeadList(&g_tcpctx_data.pendedPackets, &pTcpCtxInfo->pEntry);
	sl_unlock(&lh);

	devctrl_pushEventQueryLisy(NF_TCPREDIRECT_LAYER_PACKET);
	return STATUS_SUCCESS;
}

// 申请ctx结构体结构
PTCPCTX tcp_packallocatectx()
{
	KLOCK_QUEUE_HANDLE lh;
	PTCPCTX pTcpCtx = NULL;

	pTcpCtx = ExAllocateFromNPagedLookasideList(&g_tcpCtxLAList);
	if (!pTcpCtx)
		return NULL;
	RtlSecureZeroMemory(pTcpCtx, sizeof(TCPCTX));

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
void tcp_purgeRedirectInfo(PTCPCTX pTcpCtx)
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
VOID tcp_release(PTCPCTX pTcpCtx)
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

	tcp_purgeRedirectInfo(pTcpCtx);

	ExFreeToNPagedLookasideList(&g_tcpCtxLAList, pTcpCtx);
}

void tcp_freePacket(PNF_PACKET pPacket)
{
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

void tcp_cleanupFlows()
{
	KLOCK_QUEUE_HANDLE lh, lhp;
	PTCPCTX pTcpCtx = NULL;
	NF_PACKET* pPacket = NULL;
	LIST_ENTRY packets;

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
		}
		while (!IsListEmpty(&pTcpCtx->injectPackets))
		{
			pPacket = (PNF_PACKET)RemoveHeadList(&pTcpCtx->injectPackets);
			InsertTailList(&packets, &pPacket->entry);
		}
		sl_unlock(&lhp);
		pTcpCtx = (PTCPCTX)pTcpCtx->entry.Flink;
	}
	sl_unlock(&lh);

	while (!IsListEmpty(&packets))
	{
		pPacket = (PNF_PACKET)RemoveHeadList(&packets);
		tcp_freePacket(pPacket);
	}
}
void tcp_removeFromFlows()
{
	KLOCK_QUEUE_HANDLE lh;
	PTCPCTX pTcpCtx = NULL;
	NTSTATUS status;

	tcp_cleanupFlows();
	sl_lock(&g_slTcpCtx, &lh);
	while (!IsListEmpty(&g_lTcpCtx))
	{
		pTcpCtx = (PTCPCTX)RemoveHeadList(&g_lTcpCtx);
		InitializeListHead(&pTcpCtx->entry);
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
			tcp_release(pTcpCtx);
		}

		tcp_release(pTcpCtx);

		sl_lock(&g_slTcpCtx, &lh);
	}
	sl_unlock(&lh);
}
void tcp_releaseFlows()
{
	KLOCK_QUEUE_HANDLE lh;
	PTCPCTX pTcpCtx = NULL;


	sl_lock(&g_slTcpCtx, &lh);
	while (!IsListEmpty(&g_lTcpCtx))
	{
		pTcpCtx = (PTCPCTX)g_lTcpCtx.Flink;

		sl_unlock(&lh);

		tcp_release(pTcpCtx);

		sl_lock(&g_slTcpCtx, &lh);
	}
	sl_unlock(&lh);
}

NF_TCPCTX_DATA* tcp_Get()
{
	return &g_tcpctx_data;
}
NTSTATUS tcp_init()
{
	NTSTATUS status = STATUS_SUCCESS;
	ExInitializeNPagedLookasideList(
		&g_tcpctxPacketsBufList,
		NULL,
		NULL,
		0,
		sizeof(NF_TCP_BUFFER),
		MEM_TAG_TCP_DATA,
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

	g_phtTcpCtxById = hash_table_new(DEFAULT_HASH_SIZE);
	if (!g_phtTcpCtxById)
	{
		return FALSE;
	}

	g_phtTcpCtxByHandle = hash_table_new(DEFAULT_HASH_SIZE);
	if (!g_phtTcpCtxByHandle)
	{
		return FALSE;
	}

	g_nextTcpCtxId = 1;

	g_initialized = TRUE;

	return status;
}
VOID tcp_clean()
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_TCP_BUFFER pTcpCtx = NULL;

	sl_lock(&g_tcpctx_data.lock, &lh);
	while (!IsListEmpty(&g_tcpctx_data.pendedPackets))
	{
		pTcpCtx = (PNF_TCP_BUFFER)RemoveHeadList(&g_tcpctx_data.pendedPackets);
		sl_unlock(&lh);
		if (pTcpCtx) {
			tcp_packfree(pTcpCtx);
			pTcpCtx = NULL;
		}
		sl_lock(&g_tcpctx_data.lock, &lh);
	}
	sl_unlock(&lh);

	tcp_removeFromFlows();
	devctrl_sleep(1000);
	tcp_releaseFlows();
}
VOID tcp_free()
{
	tcp_clean();

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
	ExDeleteNPagedLookasideList(&g_tcpctxPacketsBufList);
}

// Hash
PTCPCTX tcp_find(UINT64 id)
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
PTCPCTX tcp_findByHandle(UINT64 handle)
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


