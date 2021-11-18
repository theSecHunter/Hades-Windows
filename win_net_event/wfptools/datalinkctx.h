#ifndef _DATALINKCTX_H
#define _DATALINKCTX_H

/*
* Callouts Buffer - DataLink Layer
*/
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

#endif // !_DATALINKCTX_H
