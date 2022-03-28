#ifndef _TCPCTX_H
#define _TCPCTX_H

typedef UINT64 HASH_ID;
typedef UINT32 FWP_ACTION_TYPE;

#define NF_MAX_ADDRESS_LENGTH		28
#define NF_MAX_IP_ADDRESS_LENGTH	16

typedef struct _HASH_TABLE_ENTRY
{
	HASH_ID		id;
	struct _HASH_TABLE_ENTRY* pNext;
} HASH_TABLE_ENTRY, * PHASH_TABLE_ENTRY;
typedef struct FWPS_CLASSIFY_OUT0_
{
	FWP_ACTION_TYPE actionType;
	UINT64 outContext;
	UINT64 filterId;
	UINT32 rights;
	UINT32 flags;
	UINT32 reserved;
} 	FWPS_CLASSIFY_OUT0;
typedef struct _REDIRECT_INFO
{
	UINT64				classifyHandle;
	UINT64				filterId;
	FWPS_CLASSIFY_OUT0	classifyOut;
	BOOLEAN				isPended;

#ifdef USE_NTDDI
#if(NTDDI_VERSION >= NTDDI_WIN8)
	HANDLE				redirectHandle;
#endif 
#endif
} REDIRECT_INFO, * PREDIRECT_INFO;
typedef enum _UMT_FILTERING_STATE
{
	UMFS_NONE,
	UMFS_DISABLE,
	UMFS_DISABLED
} UMT_FILTERING_STATE;
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

#endif // !_TCPCTX_H
