#ifndef _UDPCTX_H
#define _UDPCTX_H

#include "hashtable.h"

typedef struct _NF_UDP_BUFFER
{
	LIST_ENTRY			pEntry;
	char*				dataBuffer;
	ULONG				dataLength;
}NF_UDP_BUFFER, * PNF_UDP_BUFFER;

typedef struct _NF_UDPCTX_DATA
{
	LIST_ENTRY		pendedPackets;		// Linkage
	KSPIN_LOCK		lock;				// Context spinlock
}NF_UDPPEND_PACKET, * PNF_UDPPEND_PACKET;

typedef struct _UDPCTX
{
	LIST_ENTRY			entry;

	UINT64				id;
	PHASH_TABLE_ENTRY	id_next;

	UINT64				transportEndpointHandle;
	PHASH_TABLE_ENTRY	transportEndpointHandle_next;

	BOOLEAN		closed;			// TRUE if the context is disassociated from WFP flow

	ULONG		filteringFlag;	// Values from NF_FILTERING_FLAG
	ULONG		processId;		// Process identifier
	USHORT		ip_family;		// AF_INET or AF_INET6
	UCHAR		localAddr[NF_MAX_ADDRESS_LENGTH];	// Local address
	UCHAR		remoteAddr[NF_MAX_ADDRESS_LENGTH];	// Remote address
	USHORT      ipProto;		// protocol

	UINT16		layerId;		// WFP layer id
	UINT32		calloutId;		// WFP callout id

	LIST_ENTRY	pendedSendPackets;	// List of outbound packets
	LIST_ENTRY	pendedRecvPackets;	// List of inbound packets

	ULONG		pendedSendBytes;	// Number of bytes in outbound packets from pendedSendPackets
	ULONG		pendedRecvBytes;	// Number of bytes in inbound packets from pendedRecvPackets

	ULONG		injectedSendBytes;	// Number of bytes in injected outbound packets
	ULONG		injectedRecvBytes;	// Number of bytes in injected inbound packets

	BOOLEAN		sendInProgress;		// TRUE if the number of injected outbound bytes reaches a limit
	BOOLEAN		recvInProgress;		// TRUE if the number of injected inbound bytes reaches a limit

	//UDP_REDIRECT_INFO	redirectInfo;
	BOOLEAN		seenPackets;
	BOOLEAN		redirected;

	int				fcHandle;
	uint64_t		inLastTS;
	uint64_t		outLastTS;

	uint64_t		inCounter;
	uint64_t		outCounter;

	uint64_t		inCounterTotal;
	uint64_t		outCounterTotal;

	BOOLEAN			filteringDisabled;

	wchar_t			processName[MAX_PATH];

	ULONG			refCount;			// Reference counter

	LIST_ENTRY		auxEntry;			// List entry for adding context to temp lists

	KSPIN_LOCK		lock;				// Context spinlock
}UDPCTX, *PUDPCTX;

NTSTATUS udpctx_init();
NF_UDPPEND_PACKET* const udpctx_Get();
VOID udpctx_clean();
VOID udpctx_free();

UDPCTX* const udpctx_packetAllocatCtx();
VOID udpctx_freeCtx(PUDPCTX pUdpCtx);

NF_UDP_BUFFER* const udp_packAllocatebuf(const int lens);
VOID udp_freebuf(PNF_UDP_BUFFER pPacket);

PUDPCTX udpctx_find(UINT64 id);
PUDPCTX udpctx_findByHandle(UINT64 handle);
void remove_udpHandle(PUDPCTX pudpctx);
#endif