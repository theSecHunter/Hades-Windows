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

typedef struct _ETHERNET_HEADER_INFO
{
	unsigned char    pDestinationAddress[6];
	unsigned char    pSourceAddress[6];
	unsigned short  type;
}ETHERNET_HEADER_INFO, * PETHERNET_HEADER_INFO;

typedef struct _NF_CALLOUT_MAC_INFO
{
	int code;
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

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
	union
	{
		FWP_BYTE_ARRAY16 RemoteAddr;
		UINT32 ipv4toRemoteAddr;
	};
#pragma warning(pop)
	UINT16 toRemotePort;

	ETHERNET_HEADER_INFO mac_info;
}NF_CALLOUT_MAC_INFO, * PNF_CALLOUT_MAC_INFO;

NF_DATALINK_DATA* datalink_get();
NTSTATUS datalinkctx_init();
VOID datalinkctx_free();
VOID datalinkctx_clean();
PNF_DATALINK_BUFFER datalinkctx_packallocate(int lens);
VOID datalinkctx_packfree(PNF_DATALINK_BUFFER pPacket);
NTSTATUS datalinkctx_pushdata(PVOID64 packet, int lens);

#endif // !_DATALINKCTX_H
