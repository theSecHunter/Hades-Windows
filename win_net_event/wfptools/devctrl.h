#ifndef _DEVCTRL_H
#define _DEVCTRL_H

extern HANDLE g_deviceHandle;

typedef USHORT ADDRESS_FAMILY;

#define FWP_BYTE_ARRAY6_SIZE 6

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

class DevctrlIoct
{
public:
	DevctrlIoct();
	~DevctrlIoct();

	int devctrl_init();
	int devctrl_opendeviceSylink(const char* devSylinkName);
	int devctrl_workthread();
	// int devctrl_Alpcworkthread();
	int devctrl_waitSingeObject();
	void devctrl_clean();
	int devctrl_InitshareMem();
	void nf_setWfpCheckEventHandler(PVOID64 pHandler);
	int devctrl_OnMonitor();

private:
	HANDLE m_devhandler;
	HANDLE m_threadobjhandler;
	HANDLE m_alpcthreadobjhandler;
	HANDLE m_listthreadobjhandler;
	DWORD  m_dwthreadid;
	DWORD  m_dwthreadid1;

	// ·¢ËÍ¿ØÖÆÂë
	int devctrl_sendioct(const int ioctcode);
	int devctrl_writeio();
	PVOID get_eventhandler();

};

#endif // !_DEVCTRL_H