#ifndef _DATALINKCTX_H
#define _DATALINKCTX_H

typedef struct _NF_DATALINK_BUFFER
{
	LIST_ENTRY			pEntry;
	char*				dataBuffer;
	ULONG				dataLength;
}NF_DATALINK_BUFFER,*PNF_DATALINK_BUFFER;

typedef struct _NF_DATALINK_DATA
{
	LIST_ENTRY		pendedPackets;		// Linkage
	KSPIN_LOCK		lock;				// Context spinlock
}NF_DATALINK_DATA, * PNF_DATALINK_DATA;

NF_DATALINK_DATA* datalink_get();
NTSTATUS datalinkctx_init();
VOID datalinkctx_free();
VOID datalinkctx_clean();
PNF_DATALINK_BUFFER datalinkctx_packallocate(int lens);
VOID datalinkctx_packfree(PNF_DATALINK_BUFFER pPacket);
NTSTATUS datalinkctx_pushdata(PVOID64 packet, int lens);

#endif // !_DATALINKCTX_H
