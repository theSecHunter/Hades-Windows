//
// 	WFPDRIVER 
// 	Copyright (C) 2021 Vitaly Sidorov
//	All rights reserved.
//
//  ¹«¹²Í·
//

#ifndef _PUBLIC_H
#define _PUBLIC_H

#ifdef _NXPOOLS
#ifdef USE_NTDDI
#if (NTDDI_VERSION >= NTDDI_WIN8)
#define POOL_NX_OPTIN 1
#endif
#endif
#endif

#include <ntifs.h>
#include <ntstrsafe.h>

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <stdlib.h>

#undef ASSERT
#define ASSERT(x)

#define MEM_TAG		'3TLF'
#define MEM_TAG_TCP	'TTLF'
#define MEM_TAG_TCP_PACKET	'PTLF'
#define MEM_TAG_TCP_DATA	'DTLF'
#define MEM_TAG_TCP_DATA_COPY	'CTLF'
#define MEM_TAG_TCP_INJECT	'ITLF'
#define MEM_TAG_UDP	'UULF'
#define MEM_TAG_UDP_PACKET	'PULF'
#define MEM_TAG_UDP_DATA	'DULF'
#define MEM_TAG_UDP_DATA_COPY	'CULF'
#define MEM_TAG_UDP_INJECT	'IULF'
#define MEM_TAG_QUEUE	'QTLF'
#define MEM_TAG_IP_PACKET	'PILF'
#define MEM_TAG_IP_DATA_COPY 'DILF'
#define MEM_TAG_IP_INJECT	'IILF'
#define MEM_TAG_NETWORK	'SWSW'

#define MEM_TAG_DK	'UDDK'

#define malloc_np(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
#define free_np(p) ExFreePool(p);

#define sl_init(x) KeInitializeSpinLock(x)
#define sl_lock(x, lh) KeAcquireInStackQueuedSpinLock(x, lh)
#define sl_unlock(lh) KeReleaseInStackQueuedSpinLock(lh)

#define htonl(x) (((((ULONG)(x))&0xffL)<<24)           | \
	((((ULONG)(x))&0xff00L)<<8)        | \
	((((ULONG)(x))&0xff0000L)>>8)        | \
	((((ULONG)(x))&0xff000000L)>>24))

#define htons(_x_) ((((unsigned char*)&_x_)[0] << 8) & 0xFF00) | ((unsigned char*)&_x_)[1] 

#define DPREFIX "[DK]-"

#define DEFAULT_HASH_SIZE 3019

#define MAX_PROCESS_PATH_LEN 300
#define MAX_PROCESS_NAME_LEN 64

extern DWORD g_dwLogLevel;
extern BOOLEAN g_monitorflag;

#define NF_MAX_ADDRESS_LENGTH		28
#define NF_MAX_IP_ADDRESS_LENGTH	16

typedef unsigned __int64 uint64_t;

typedef enum _NF_DATA_CODE
{
    NF_DATALINKMAC_LAYER_PACKET = 1,	// 
    NF_ESTABLISHED_LAYER_PACKET,		// 
    NF_TCPREDIRECT_LAYER_PACKET,		// Tcp Connect Packet


    NF_TCP_CONNECT_REQUEST,				// Outgoing TCP connect request
    NF_UDP_SEND,                        // Udp Send Packet
    NF_UDP_RECV                         // Udp Recv Packet
}NF_DATA_CODE;

#pragma pack(push, 1)

typedef enum _NF_FILTERING_FLAG
{
    NF_ALLOW = 0,		// Allow the activity without filtering transmitted packets
    NF_BLOCK = 1,		// Block the activity
    NF_FILTER = 2,		// Filter the transmitted packets
    NF_SUSPENDED = 4,	// Suspend receives from server and sends from client
    NF_OFFLINE = 8,		// Emulate establishing a TCP connection with remote server
    NF_INDICATE_CONNECT_REQUESTS = 16, // Indicate outgoing connect requests to API
    NF_DISABLE_REDIRECT_PROTECTION = 32, // Disable blocking indicating connect requests for outgoing connections of local proxies
    NF_PEND_CONNECT_REQUEST = 64,	// Pend outgoing connect request to complete it later using nf_complete(TCP|UDP)ConnectRequest
    NF_FILTER_AS_IP_PACKETS = 128,	// Indicate the traffic as IP packets via ipSend/ipReceive
    NF_READONLY = 256,				// Don't block the IP packets and indicate them to ipSend/ipReceive only for monitoring
    NF_CONTROL_FLOW = 512,			// Use the flow limit rules even without NF_FILTER flag
} NF_FILTERING_FLAG;

typedef UNALIGNED struct _NF_DATA
{
    int					code;
    unsigned __int64	id;
    unsigned long		bufferSize;
    char 				buffer[1];
} NF_DATA, * PNF_DATA;

typedef UNALIGNED struct _NF_READ_RESULT
{
	unsigned __int64 length;
} NF_READ_RESULT, * PNF_READ_RESULT;

typedef UNALIGNED struct _NF_BUFFERS
{
	unsigned __int64 inBuf;
	unsigned __int64 inBufLen;
	unsigned __int64 outBuf;
	unsigned __int64 outBufLen;
} NF_BUFFERS, * PNF_BUFFERS;

typedef struct _ETHERNET_HEADER_
{
    unsigned char    pDestinationAddress[6];
    unsigned char    pSourceAddress[6];
    unsigned short  type;
}ETHERNET_HEADER, *PETHERNET_HEADER;

typedef struct _IP_HEADER_V4_
{
    union
    {
        unsigned char  versionAndHeaderLength;
        struct
        {
            unsigned char  headerLength : 4;
            unsigned char  version : 4;
        };
    };
    union
    {
        unsigned char   typeOfService;
        unsigned char   differentiatedServicesCodePoint;
        struct
        {
            unsigned char  explicitCongestionNotification : 2;
            unsigned char  typeOfService6bit : 6;
        };
    };
    unsigned short  totalLength;
    unsigned short  identification;
    union
    {
        unsigned short  flagsAndFragmentOffset;
        struct
        {
            unsigned short  fragmentOffset : 13;
            unsigned short  flags : 3;
        };
    };
    unsigned char   timeToLive;
    unsigned char   protocol;
    unsigned short  checksum;
    unsigned char    pSourceAddress[sizeof(unsigned int)];
    unsigned char    pDestinationAddress[sizeof(unsigned int)];
}IP_HEADER_V4, * PIP_HEADER_V4;

struct iphdr
{
    unsigned char  HdrLength : 4;
    unsigned char  Version : 4;
    unsigned char  TOS;
    unsigned short Length;
    unsigned short Id;
    unsigned short FragOff0;
    unsigned char  TTL;
    unsigned char  Protocol;
    unsigned short Checksum;
    unsigned int SrcAddr;
    unsigned int DstAddr;
};

typedef struct _IP_HEADER_V6_
{
    union
    {
        unsigned char pVersionTrafficClassAndFlowLabel[4];
        struct
        {
            unsigned char r1 : 4;
            unsigned char value : 4;
            unsigned char r2;
            unsigned char r3;
            unsigned char r4;
        }version;
    };
    unsigned short payloadLength;
    unsigned char  nextHeader;
    unsigned char  hopLimit;
    unsigned char    pSourceAddress[16];
    unsigned char    pDestinationAddress[16];
} IP_HEADER_V6, * PIP_HEADER_V6;

typedef struct _TCP_HEADER_
{
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned int sequenceNumber;
    unsigned int acknowledgementNumber;
    union
    {
        unsigned char dataOffsetReservedAndNS;
        struct
        {
            unsigned char nonceSum : 1;
            unsigned char reserved : 3;
            unsigned char dataOffset : 4;
        }dORNS;
    };
    union
    {
        unsigned char controlBits;
        struct
        {
            unsigned char FIN : 1;
            unsigned char SYN : 1;
            unsigned char RST : 1;
            unsigned char PSH : 1;
            unsigned char ACK : 1;
            unsigned char URG : 1;
            unsigned char ECE : 1;
            unsigned char CWR : 1;
        };
    };
    unsigned short window;
    unsigned short checksum;
    unsigned short urgentPointer;
}TCP_HEADER, * PTCP_HEADER;

typedef struct UDP_HEADER_
{
    UINT16 srcPort;
    UINT16 destPort;
    UINT16 length;
    UINT16 checksum;
} UDP_HEADER, * PUDP_HEADER;
#pragma pack(pop)
#endif