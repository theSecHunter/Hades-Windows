#include "public.h"
#include "devctrl.h"
#include "udpctx.h"

static NF_UDPPEND_PACKET		g_udp_pendPacket;
static NPAGED_LOOKASIDE_LIST	g_udpctxPacketsBufList;

static NPAGED_LOOKASIDE_LIST	g_udpPacketDataList;

static __int64					g_nextUdpCtxId;
static NPAGED_LOOKASIDE_LIST	g_udpCtxList;

static KSPIN_LOCK				g_slUdpCtx;
static LIST_ENTRY				g_lUdpCtx;

static PHASH_TABLE				g_phtUdpCtxById = NULL;
static PHASH_TABLE				g_phtUdpCtxByHandle = NULL;

// packetData
NF_UDP_PACKET* const udp_packetAllocatData(const int lens)
{
	NF_UDP_PACKET* const pUdpPacket = ExAllocateFromNPagedLookasideList(&g_udpPacketDataList);
	if (pUdpPacket) {
		RtlSecureZeroMemory(pUdpPacket, sizeof(NF_UDP_PACKET));
		if (lens) {
			pUdpPacket->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, MEM_TAG_UDP_DATA_COPY);
			if (!pUdpPacket->dataBuffer) {
				ExFreeToNPagedLookasideList(&g_udpPacketDataList, pUdpPacket);
				return NULL;
			}
		}
		return pUdpPacket;
	}
	return NULL;
}
VOID udp_freePacketData(NF_UDP_PACKET* const pPacket)
{
	if (pPacket) {
		if (pPacket->dataBuffer) {
			ExFreePoolWithTag(pPacket->dataBuffer, MEM_TAG_UDP_DATA_COPY);
			pPacket->dataBuffer = NULL;
		}
		if (pPacket->controlData) {
			ExFreePoolWithTag(pPacket->controlData, MEM_TAG_UDP_DATA);
			pPacket->controlData = NULL;
		}
		ExFreeToNPagedLookasideList(&g_udpPacketDataList, pPacket);
	}
}

// buf
NF_UDP_BUFFER* const udp_packAllocatebuf(const int lens) {
	if (lens < 0)
		return NULL;
	PNF_UDP_BUFFER pUcpctx = NULL;
	pUcpctx = ExAllocateFromNPagedLookasideList(&g_udpctxPacketsBufList);
	if (!pUcpctx)
		return NULL;
	RtlSecureZeroMemory(pUcpctx, sizeof(NF_UDP_BUFFER));

	// ²»ÐèÒªÉêÇëdataBuffer
	if (lens == 0) {
		pUcpctx->dataBuffer = NULL;
		return pUcpctx;
	}

	pUcpctx->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'UDPF');
	if (!pUcpctx->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_udpctxPacketsBufList, pUcpctx);
		return NULL;
	}
	return pUcpctx;
}
VOID udp_freebuf(PNF_UDP_BUFFER pPacket, const int lens){
	if (pPacket && pPacket->dataBuffer)
	{
		if (lens == 0)
			udp_freePacketData(pPacket->dataBuffer);
		else
			free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	if (pPacket)
		ExFreeToNPagedLookasideList(&g_udpctxPacketsBufList, pPacket);
}

// ctx
UDPCTX* const udp_packetAllocatCtx(){
	UDPCTX* const pUdpCtx = ExAllocateFromLookasideListEx(&g_udpCtxList);
	if (!pUdpCtx)
		return NULL;
	RtlSecureZeroMemory(pUdpCtx, sizeof(UDPCTX));

	sl_init(&pUdpCtx->lock);
	pUdpCtx->refCount = 1;

	InitializeListHead(&pUdpCtx->pendedSendPackets);
	InitializeListHead(&pUdpCtx->pendedRecvPackets);
	InitializeListHead(&pUdpCtx->auxEntry);

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_slUdpCtx, &lh);
	pUdpCtx->id = g_nextUdpCtxId++;
	ht_add_entry(g_phtUdpCtxById, (PHASH_TABLE_ENTRY)&pUdpCtx->id);
	InsertTailList(&g_lUdpCtx, &pUdpCtx->entry);
	sl_unlock(&lh);

	return pUdpCtx;
}
UDPCTX* const udp_packetAllocatCtxHandle(UINT64 transportEndpointHandle)
{
	KLOCK_QUEUE_HANDLE lh;
	PUDPCTX pUdpCtx = NULL;

	if (!transportEndpointHandle)
		return NULL;

	pUdpCtx = (PUDPCTX)ExAllocateFromNPagedLookasideList(&g_udpCtxList);
	if (!pUdpCtx)
		return NULL;

	memset(pUdpCtx, 0, sizeof(UDPCTX));

	sl_init(&pUdpCtx->lock);
	pUdpCtx->refCount = 1;

	InitializeListHead(&pUdpCtx->pendedSendPackets);
	InitializeListHead(&pUdpCtx->pendedRecvPackets);

	pUdpCtx->transportEndpointHandle = transportEndpointHandle;

	sl_lock(&g_slUdpCtx, &lh);

	pUdpCtx->id = g_nextUdpCtxId++;

	KdPrint((DPREFIX"udpctx_alloc id=[%I64u]\n", pUdpCtx->id));

	ht_add_entry(g_phtUdpCtxByHandle, (PHASH_TABLE_ENTRY)&pUdpCtx->transportEndpointHandle);
	ht_add_entry(g_phtUdpCtxById, (PHASH_TABLE_ENTRY)&pUdpCtx->id);

	InsertTailList(&g_lUdpCtx, &pUdpCtx->entry);

	sl_unlock(&lh);
	
	return pUdpCtx;
}
VOID udp_freeCtx(PUDPCTX pUdpCtx) {
	KLOCK_QUEUE_HANDLE lh;

	if (!pUdpCtx)
		return;

	sl_lock(&g_slUdpCtx, &lh);

	if (pUdpCtx->refCount == 0)
	{
		sl_unlock(&lh);
		return;
	}

	pUdpCtx->refCount--;

	if (pUdpCtx->refCount > 0)
	{
		sl_unlock(&lh);
		return;
	}

	if (g_phtUdpCtxById)
		ht_remove_entry(g_phtUdpCtxById, pUdpCtx->id);
	RemoveEntryList(&pUdpCtx->entry);

	sl_unlock(&lh);

	if (pUdpCtx->transportEndpointHandle)
	{
		remove_udpHandle(pUdpCtx);
		pUdpCtx->transportEndpointHandle = 0;
	}
	ExFreeToNPagedLookasideList(&g_udpCtxList, pUdpCtx);
}

NTSTATUS push_udpPacketinfo(PVOID packet, int lens, BOOLEAN isSend)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_UDP_BUFFER pUDPBuffer = NULL;

	if (!packet || (lens < 1))
		return STATUS_UNSUCCESSFUL;

	// Allocate 
	pUDPBuffer = udp_packAllocatebuf(0);
	if (!pUDPBuffer)
		return STATUS_UNSUCCESSFUL;

	pUDPBuffer->dataLength = lens;
	pUDPBuffer->dataBuffer = packet;

	sl_lock(&g_udp_pendPacket.lock, &lh);
	InsertHeadList(&g_udp_pendPacket.pendedPackets, &pUDPBuffer->pEntry);
	sl_unlock(&lh);

	devctrl_pushEventQueryLisy((isSend == TRUE) ? NF_UDP_SEND : NF_UDP_RECV);
	return STATUS_SUCCESS;
}

NTSTATUS udp_init() {
	NTSTATUS status = STATUS_SUCCESS;
	ExInitializeNPagedLookasideList(
		&g_udpctxPacketsBufList,
		NULL,
		NULL,
		0,
		sizeof(NF_UDP_BUFFER),
		MEM_TAG_UDP_DATA,
		0
	);

	ExInitializeNPagedLookasideList(
		&g_udpCtxList,
		NULL,
		NULL,
		0,
		sizeof(UDPCTX),
		MEM_TAG_UDP,
		0
	);

	ExInitializeNPagedLookasideList(
		&g_udpPacketDataList,
		NULL,
		NULL,
		0,
		sizeof(NF_UDP_PACKET),
		MEM_TAG_UDP_PACKET,
		0
	);

	sl_init(&g_slUdpCtx);
	InitializeListHead(&g_lUdpCtx);

	sl_init(&g_udp_pendPacket.lock);
	InitializeListHead(&g_udp_pendPacket.pendedPackets);

	g_phtUdpCtxById = hash_table_new(DEFAULT_HASH_SIZE);
	if (!g_phtUdpCtxById)
		return FALSE;

	g_phtUdpCtxByHandle = hash_table_new(DEFAULT_HASH_SIZE);
	if (!g_phtUdpCtxByHandle)
		return FALSE;

	g_nextUdpCtxId = 1;
	return status;
}
NF_UDPPEND_PACKET* const udp_Get() {
	return &g_udp_pendPacket;
}
VOID udp_clean() {
	KLOCK_QUEUE_HANDLE lh;
	PNF_UDP_BUFFER pUdpBuffer = NULL;

	sl_lock(&g_udp_pendPacket.lock, &lh);
	while (!IsListEmpty(&g_udp_pendPacket.pendedPackets))
	{
		pUdpBuffer = (PNF_UDP_BUFFER)RemoveHeadList(&g_udp_pendPacket.pendedPackets);
		sl_unlock(&lh);
		if (pUdpBuffer) {
			udp_freebuf(pUdpBuffer, 0);
			pUdpBuffer = NULL;
		}
		sl_lock(&g_udp_pendPacket.lock, &lh);
	}
	sl_unlock(&lh);
}
VOID udp_free() {
	udp_clean();

	if (g_phtUdpCtxById)
	{
		hash_table_free(g_phtUdpCtxById);
		g_phtUdpCtxById = NULL;
	}

	if (g_phtUdpCtxByHandle)
	{
		hash_table_free(g_phtUdpCtxByHandle);
		g_phtUdpCtxByHandle = NULL;
	}

	ExDeleteNPagedLookasideList(&g_udpCtxList);
	ExDeleteNPagedLookasideList(&g_udpPacketDataList);
	ExDeleteNPagedLookasideList(&g_udpctxPacketsBufList);
}

// Hash
PUDPCTX udp_find(UINT64 id)
{
	PUDPCTX pUcpCtx = NULL;
	PHASH_TABLE_ENTRY phte;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slUdpCtx, &lh);
	phte = ht_find_entry(g_phtUdpCtxById, id);
	if (phte)
	{
		pUcpCtx = (PUDPCTX)CONTAINING_RECORD(phte, UDPCTX, id);
		if (pUcpCtx)
			pUcpCtx->refCount++;
	}
	sl_unlock(&lh);

	return pUcpCtx;
}
PUDPCTX udp_findByHandle(UINT64 handle)
{
	PUDPCTX pUcpCtx = NULL;
	PHASH_TABLE_ENTRY phte;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slUdpCtx, &lh);
	phte = ht_find_entry(g_phtUdpCtxByHandle, handle);
	if (phte)
	{
		pUcpCtx = (PUDPCTX)CONTAINING_RECORD(phte, UDPCTX, transportEndpointHandle);
		if (pUcpCtx)
			pUcpCtx->refCount++;
	}
	sl_unlock(&lh);

	return pUcpCtx;
}
void add_udpHandle(PUDPCTX pudpctx)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slUdpCtx, &lh);
	ht_add_entry(g_phtUdpCtxByHandle, (PHASH_TABLE_ENTRY)&pudpctx->transportEndpointHandle);
	sl_unlock(&lh);
}
void remove_udpHandle(PUDPCTX pudpctx)
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_slUdpCtx, &lh);
	ht_remove_entry(g_phtUdpCtxByHandle, pudpctx->transportEndpointHandle);
	sl_unlock(&lh);
}

