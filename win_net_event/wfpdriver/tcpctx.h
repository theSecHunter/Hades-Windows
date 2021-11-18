#ifndef _TCPCTX_H
#define _TCPCTX_H

#include "hashtable.h"

#define NF_MAX_ADDRESS_LENGTH		28
#define NF_MAX_IP_ADDRESS_LENGTH	16

typedef unsigned __int64 uint64_t;

typedef struct _NF_TCPCTX_BUFFER
{
	LIST_ENTRY			pEntry;
	char*				dataBuffer;
	ULONG				dataLength;
}NF_TCPCTX_BUFFER, * PNF_TCPCTX_BUFFER;

typedef struct _NF_TCPCTX_DATA
{
	LIST_ENTRY		pendedPackets;		// Linkage
	KSPIN_LOCK		lock;				// Context spinlock
}NF_TCPCTX_DATA, * PNF_TCPCTX_DATA;

typedef UNALIGNED struct _NF_TCP_CONN_INFO
{
	unsigned long	filteringFlag;	// See NF_FILTERING_FLAG
	unsigned long	pflag;
	unsigned long	processId;		// Process identifier
	unsigned char	direction;		// See NF_DIRECTION
	unsigned short	ip_family;		// AF_INET for IPv4 and AF_INET6 for IPv6

	// Local address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	localAddress[NF_MAX_ADDRESS_LENGTH];

	// Remote address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	remoteAddress[NF_MAX_ADDRESS_LENGTH];

} NF_TCP_CONN_INFO, * PNF_TCP_CONN_INFO;

typedef enum _UMT_FILTERING_STATE
{
	UMFS_NONE,
	UMFS_DISABLE,
	UMFS_DISABLED
} UMT_FILTERING_STATE;

typedef struct _REDIRECT_INFO
{
	UINT64				classifyHandle;
	UINT64				filterId;
	FWPS_CLASSIFY_OUT	classifyOut;
	BOOLEAN				isPended;

#ifdef USE_NTDDI
#if(NTDDI_VERSION >= NTDDI_WIN8)
	HANDLE				redirectHandle;
#endif 
#endif
} REDIRECT_INFO, * PREDIRECT_INFO;

typedef struct _TCPCTX
{
	LIST_ENTRY entry;
	LIST_ENTRY	injectQueueEntry; // Inject queue list entry

	LIST_ENTRY	pendedPackets;	// List of queued packets
	LIST_ENTRY	injectPackets;	// List of packets to inject

	UINT64		id;
	PHASH_TABLE_ENTRY id_next;

	UINT64				transportEndpointHandle;
	PHASH_TABLE_ENTRY	transportEndpointHandle_next;

	BOOLEAN		closed;			// TRUE if the context is disassociated from WFP flow

	ULONG		filteringFlag;	// Values from NF_FILTERING_FLAG
	ULONG		pflag;
	ULONG		processId;		// Process identifier
	ULONG		processPathSize;
	WCHAR		processPath[MAX_PATH * 2];
	USHORT		ip_family;		// AF_INET or AF_INET6
	UCHAR		localAddr[NF_MAX_ADDRESS_LENGTH];	// Local address
	UCHAR		remoteAddr[NF_MAX_ADDRESS_LENGTH];	// Remote address
	UCHAR		direction;		// Connection direction (NF_D_IN or NF_D_OUT)
	USHORT      ipProto;		// protocol

	UINT64      flowHandle;		// WFP flow handle
	UINT16		layerId;		// WFP layer id
	UINT32		sendCalloutId;		// WFP send callout id
	UINT32		recvCalloutId;		// WFP receive callout id
	UINT32		recvProtCalloutId;		// WFP receive protection callout id

	BOOLEAN		recvCalloutInjectable;
	BOOLEAN		recvCalloutBypass;
	BOOLEAN		sendCalloutInjectable;
	BOOLEAN		sendCalloutBypass;

	UINT16		transportLayerIdOut;		// WFP outbound transport layer id
	UINT32		transportCalloutIdOut;		// WFP outbound transport callout id
	UINT16		transportLayerIdIn;		// WFP inbound transport layer id
	UINT32		transportCalloutIdIn;		// WFP inbound transport callout id 

	BOOLEAN		inInjectQueue;	// TRUE if the context is in inject queue

	ULONG		pendedSendBytes;	// Number of bytes in outbound packets from pendedSendPackets
	ULONG		pendedRecvBytes;	// Number of bytes in inbound packets from pendedRecvPackets

	ULONG		injectedSendBytes;	// Number of bytes in injected outbound packets
	ULONG		injectedRecvBytes;	// Number of bytes in injected inbound packets

	BOOLEAN		recvDeferred;		// TRUE if connection is deferred

	BOOLEAN		sendDisconnectPending;	// TRUE if outbound disconnect request is received
	BOOLEAN		recvDisconnectPending;	// TRUE if inbound disconnect request is received 
	BOOLEAN		abortConnection;		// TRUE if the connection must be aborted

	BOOLEAN		sendDisconnectCalled;	// TRUE if outbound disconnect request is sent
	BOOLEAN		recvDisconnectCalled;	// TRUE if inbound disconnect request is sent

	BOOLEAN		sendInProgress;		// TRUE if the number of injected outbound bytes reaches a limit
	BOOLEAN		recvInProgress;		// TRUE if the number of injected inbound bytes reaches a limit

	BOOLEAN		noDelay;		// TRUE if no delay flag must be applied to outbound packets

	BOOLEAN		finReceived;	// TRUE if FIN packet received
	BOOLEAN		finWithData;	// TRUE if FIN packet with non-zero length received

	ULONG		pendedRecvProtBytes;	// Number of bytes in inbound packets on the fly from recvProt sublayer
	BOOLEAN		finReceivedOnRecvProt;	// TRUE if FIN packet is received on recvProt sublayer

	int				fcHandle;
	uint64_t		inLastTS;
	uint64_t		outLastTS;

	uint64_t		inCounter;
	uint64_t		outCounter;

	uint64_t		inCounterTotal;
	uint64_t		outCounterTotal;

	REDIRECT_INFO	redirectInfo;

	UMT_FILTERING_STATE	filteringState;

	wchar_t			processName[MAX_PATH];

	ULONG		refCount;		// Reference counter

	KSPIN_LOCK	lock;			// Context spinlock
} TCPCTX, * PTCPCTX;

void add_tcpHandle(PTCPCTX ptcpctx);
void remove_tcpHandle(PTCPCTX ptcpctx);
PTCPCTX tcpctx_find(UINT64 id);
void tcpctx_purgeRedirectInfo(PTCPCTX pTcpCtx);

NTSTATUS push_tcpRedirectinfo(PVOID64 packet, int lens);

PTCPCTX tcpctxctx_packallocatectx();
VOID tcpctx_release(PTCPCTX pTcpCtx);

NF_TCPCTX_DATA* tcpctx_get();
NTSTATUS tcpctxctx_init();
VOID tcpctxctx_packfree(PNF_TCPCTX_BUFFER pPacket);
VOID tcpctxctx_clean();
VOID tcpctxctx_free();

#endif // !_TCPHEAD_H
