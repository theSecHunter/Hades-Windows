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
typedef struct _NF_CALLOUT_FLOWESTABLISHED_INFO
{
	ADDRESS_FAMILY addressFamily;
#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
	union
	{
		FWP_BYTE_ARRAY16 localAddr;
		UINT32 ipv4LocalAddr;
	};
#pragma warning(pop)
	UINT16 toLocalPort;

	UINT8 protocol;
	UINT64 flowId;
	UINT16 layerId;
	UINT32 calloutId;
	UINT64	transportEndpointHandle;

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
	union
	{
		FWP_BYTE_ARRAY16 RemoteAddr;
		UINT32 ipv4toRemoteAddr;
	};
#pragma warning(pop)
	UINT16 toRemotePort;

	WCHAR  processPath[MAX_PATH * 2];
	int	   processPathSize;
	UINT64 processId;

	LONG refCount;
}NF_CALLOUT_FLOWESTABLISHED_INFO, * PNF_CALLOUT_FLOWESTABLISHED_INFO;

NTSTATUS establishedctx_init();
VOID establishedctx_free();
VOID establishedctx_clean();

NF_FLOWESTABLISHED_BUFFER* establishedctx_packallocte(int lens);
VOID establishedctx_packfree(PNF_FLOWESTABLISHED_BUFFER pPacket);

NTSTATUS establishedctx_pushflowestablishedctx(PVOID64 pBuffer, int lens);
NF_FLOWESTABLISHED_DATA* establishedctx_get();

#endif // !_ESTABLISHEDCTX_H
