#ifndef _ESTABLISHEDCTX_H
#define _ESTABLISHEDCTX_H

typedef struct FWP_BYTE_ARRAY16_
{
	UINT8 byteArray16[16];
} 	FWP_BYTE_ARRAY16;
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

#endif // !_ESTABLISHEDCTX_H
