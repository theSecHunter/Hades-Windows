#include "public.h"
#include "datalinkctx.h"

#include <ws2def.h>

#include "devctrl.h"

static NPAGED_LOOKASIDE_LIST	g_dataLinkPacketsList;
static NF_DATALINK_DATA			g_datalink_data;

NF_DATALINK_DATA* datalink_get()
{
	return &g_datalink_data;
}

NTSTATUS datalinkctx_init()
{
	NTSTATUS status = STATUS_SUCCESS;
	ExInitializeNPagedLookasideList(
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

PNF_DATALINK_BUFFER datalinkctx_packallocate(
	int lens
)
{
	if (lens < 0)
		return NULL;
	PNF_DATALINK_BUFFER pNfdatalink = NULL;
	pNfdatalink = ExAllocateFromNPagedLookasideList(&g_dataLinkPacketsList);
	if (!pNfdatalink)
		return FALSE;

	memset(pNfdatalink, 0, sizeof(NF_DATALINK_BUFFER));

	if (lens > 0)
	{
		pNfdatalink->dataBuffer = ExAllocatePoolWithTag(NonPagedPool, lens, 'DPLC');
		if (!pNfdatalink->dataBuffer)
		{
			ExFreeToNPagedLookasideList(&g_dataLinkPacketsList, pNfdatalink);
			return FALSE;
		}
	}
	return pNfdatalink;
}

VOID datalinkctx_packfree(
	PNF_DATALINK_BUFFER pPacket
)
{
	if (pPacket->dataBuffer)
	{
		free_np(pPacket->dataBuffer);
		pPacket->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_dataLinkPacketsList, pPacket);
}

NTSTATUS datalinkctx_pushdata(
	PVOID64 packet,
	int lens
)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;
	PNF_DATALINK_BUFFER pdatalinkinfo = NULL;

	if (!packet && (lens < 1))
		return FALSE;

	// Allocate 
	pdatalinkinfo = datalinkctx_packallocate(lens);
	if (!pdatalinkinfo)
	{
		return FALSE;
	}

	pdatalinkinfo->dataLength = lens;
	RtlCopyMemory(pdatalinkinfo->dataBuffer, packet, lens);

	sl_lock(&g_datalink_data.lock, &lh);
	InsertHeadList(&g_datalink_data.pendedPackets, &pdatalinkinfo->pEntry);
	sl_unlock(&lh);

	devctrl_pushDataLinkCtxBuffer(NF_DATALINK_PACKET);

	return status;
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