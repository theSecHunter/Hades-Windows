#include "public.h"
#include "datalinkctx.h"
#include <ws2def.h>
#include "devctrl.h"

static NF_DATALINK_DATA			g_datalink_data;
static NPAGED_LOOKASIDE_LIST	g_dataLinkPacketsList;

NF_DATALINK_DATA* datalink_get()
{
	return &g_datalink_data;
}

NTSTATUS datalinkctx_init()
{
	NTSTATUS status = STATUS_SUCCESS;
	VerifiExInitializeNPagedLookasideList(
		&g_dataLinkPacketsList,
		NULL,
		NULL,
		0,
		sizeof(NF_DATALINK_BUFFER),
		MEM_TAG_NETWORK,
		0
	);

	sl_init(&g_datalink_data.lock);
	InitializeListHead(&g_datalink_data.pendedPackets);

	return status;
}

PNF_DATALINK_BUFFER datalinkctx_packallocate(int lens)
{
	if (lens < 0)
		return NULL;

	PNF_DATALINK_BUFFER pDataLink = NULL;
	pDataLink = ExAllocateFromNPagedLookasideList(&g_dataLinkPacketsList);
	if (!pDataLink)
		return NULL;

	RtlSecureZeroMemory(pDataLink, sizeof(NF_DATALINK_BUFFER));
	if (lens > 0)
	{
#if (NTDDI_VERSION >= NTDDI_WIN8)
		pDataLink->dataBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, lens, 'DPLC');
#else
		pDataLink->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'DPLC');
#endif
		if (!pDataLink->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_dataLinkPacketsList, pDataLink);
			return NULL;
		}
	}
	return pDataLink;
}

VOID datalinkctx_packfree(PNF_DATALINK_BUFFER pPacket)
{
	if (pPacket && pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	if (pPacket)
		ExFreeToNPagedLookasideList(&g_dataLinkPacketsList, pPacket);
}

NTSTATUS datalinkctx_pushdata(PVOID64 packet, int lens)
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_DATALINK_BUFFER pDataLinkInfo = NULL;

	if (!packet && (lens < 1))
		return STATUS_UNSUCCESSFUL;

	// Allocate 
	pDataLinkInfo = datalinkctx_packallocate(lens);
	if (!pDataLinkInfo || !pDataLinkInfo->dataBuffer)
		return STATUS_UNSUCCESSFUL;

	pDataLinkInfo->dataLength = lens;
	RtlCopyMemory(pDataLinkInfo->dataBuffer, packet, lens);

	sl_lock(&g_datalink_data.lock, &lh);
	InsertHeadList(&g_datalink_data.pendedPackets, &pDataLinkInfo->pEntry);
	sl_unlock(&lh);

	devctrl_pushEventQueryLisy(NF_DATALINKMAC_LAYER_PACKET);

	return STATUS_SUCCESS;
}

VOID datalinkctx_clean()
{
	KLOCK_QUEUE_HANDLE lh;
	PNF_DATALINK_BUFFER pDataCtl;

	sl_lock(&g_datalink_data.lock, &lh);
	while (!IsListEmpty(&g_datalink_data.pendedPackets))
	{
		pDataCtl = (PNF_DATALINK_BUFFER)RemoveHeadList(&g_datalink_data.pendedPackets);
		sl_unlock(&lh);
		datalinkctx_packfree(pDataCtl);
		pDataCtl = NULL;
		sl_lock(&g_datalink_data.lock, &lh);
	}
	sl_unlock(&lh);
}

VOID datalinkctx_free()
{
	datalinkctx_clean();
	ExDeleteNPagedLookasideList(&g_dataLinkPacketsList);
}