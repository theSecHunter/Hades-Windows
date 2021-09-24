#ifndef _ESTABLISHEDCTX_H
#define _ESTABLISHEDCTX_H

typedef struct _NF_FLOWESTABLISHED_BUFFER
{
	LIST_ENTRY			pEntry;
	char*				dataBuffer;
	ULONG				dataLength;
}NF_FLOWESTABLISHED_BUFFER, * PNF_FLOWESTABLISHED_BUFFER;

typedef struct _NF_FLOWESTABLISHED_DATA
{
	LIST_ENTRY		pendedPackets;		// Linkage
	KSPIN_LOCK		lock;				// Context spinlock
}NF_FLOWESTABLISHED_DATA, * PNF_FLOWESTABLISHED_DATA;

NTSTATUS establishedctx_init();
VOID establishedctx_free();
VOID establishedctx_clean();

NF_FLOWESTABLISHED_BUFFER* establishedctx_packallocte(int lens);
VOID establishedctx_packfree(PNF_FLOWESTABLISHED_BUFFER pPacket);

NTSTATUS establishedctx_pushflowestablishedctx(PVOID64 pBuffer, int lens);
NF_FLOWESTABLISHED_DATA* establishedctx_get();

#endif // !_ESTABLISHEDCTX_H
