/*
*	应用层数据交互
*/
#include "public.h"
#include "devctrl.h"
#include "datalinkctx.h"
#include "establishedctx.h"
#include "tcpctx.h"
#include "udpctx.h"
#include "callouts.h"

typedef struct _SHARED_MEMORY
{
	PMDL					mdl;
	PVOID					userVa;
	PVOID					kernelVa;
	UINT64					bufferLength;
} SHARED_MEMORY, * PSHARED_MEMORY;

// i/o
static LIST_ENTRY					g_IoQueryHead;
static NPAGED_LOOKASIDE_LIST		g_IoQueryList;
static LIST_ENTRY					g_pendedIoRequests;
static KSPIN_LOCK					g_sIolock;
static PVOID						g_ioThreadObject = NULL;
static KEVENT						g_ioThreadEvent;
static BOOLEAN						g_shutdown = FALSE;

// Inject Thread Notify
static LIST_ENTRY					g_tInjectQueue;
static KSPIN_LOCK					g_sTInjectQueue;
static PVOID						g_threadObject = NULL;
static KEVENT						g_threadIoEvent;

// Read/Write Memory
static SHARED_MEMORY g_inBuf;
static SHARED_MEMORY g_outBuf;

// Tcp Inject Handle
static HANDLE g_injectionHandle = NULL;
// IP NetWork
static HANDLE g_netInjectionHandleV4 = NULL;
static HANDLE g_netInjectionHandleV6 = NULL;
// Udp Inject Handle
static BOOLEAN g_udpNwInject = FALSE;
static HANDLE g_udpInjectionHandle = NULL;
static HANDLE g_udpNwInjectionHandleV4 = NULL;
static HANDLE g_udpNwInjectionHandleV6 = NULL;
typedef struct _NF_UDP_INJECT_CONTEXT
{
	UINT64	id;
	int		code;
	PMDL	mdl;
	PUDPCTX	pUdpCtx;
	PNF_UDP_PACKET pPacket;
} NF_UDP_INJECT_CONTEXT, * PNF_UDP_INJECT_CONTEXT;
static NPAGED_LOOKASIDE_LIST g_udpInjectContextLAList;

static NDIS_HANDLE g_netBufferListPool = NULL;
static PNDIS_GENERIC_OBJECT g_ndisGenericObj = NULL;

typedef struct _NF_QUEUE_ENTRY
{
	LIST_ENTRY		entry;		// Linkage
	int				code;		// IO code
} NF_QUEUE_ENTRY, * PNF_QUEUE_ENTRY;

// Handle Thread
void devctrl_ioThread(IN PVOID StartContext);
void devctrl_injectThread(IN PVOID StartContext);

NTSTATUS devctrl_create(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(irpSp);

	NTSTATUS status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}
void devctrl_freeSharedMemory(PSHARED_MEMORY pSharedMemory)
{
	if (pSharedMemory->mdl)
	{
		__try
		{
			if (pSharedMemory->userVa)
			{
				MmUnmapLockedPages(pSharedMemory->userVa, pSharedMemory->mdl);
			}
			if (pSharedMemory->kernelVa)
			{
				MmUnmapLockedPages(pSharedMemory->kernelVa, pSharedMemory->mdl);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		MmFreePagesFromMdl(pSharedMemory->mdl);
		IoFreeMdl(pSharedMemory->mdl);

		memset(pSharedMemory, 0, sizeof(SHARED_MEMORY));
	}
}
NTSTATUS devctrl_createSharedMemory(PSHARED_MEMORY pSharedMemory, UINT64 len)
{
	PMDL  mdl;
	PVOID userVa = NULL;
	PVOID kernelVa = NULL;
	PHYSICAL_ADDRESS lowAddress;
	PHYSICAL_ADDRESS highAddress;

	memset(pSharedMemory, 0, sizeof(SHARED_MEMORY));

	lowAddress.QuadPart = 0;
	highAddress.QuadPart = 0xFFFFFFFFFFFFFFFF;

	mdl = MmAllocatePagesForMdl(lowAddress, highAddress, lowAddress, (SIZE_T)len);
	if (!mdl)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		kernelVa = VerifiMmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
		if (!kernelVa)
		{
			MmFreePagesFromMdl(mdl);
			IoFreeMdl(mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		//
		// The preferred way to map the buffer into user space
		//
#if (NTDDI_VERSION >= NTDDI_WIN8)
		userVa = MmMapLockedPagesSpecifyCache(mdl,          // MDL
			UserMode,     // Mode
			MmCached,     // Caching
			NULL,         // Address
			FALSE,        // Bugcheck?
			HighPagePriority | MdlMappingNoExecute); // Priority
#else
		userVa = MmMapLockedPagesSpecifyCache(mdl,          // MDL
			UserMode,     // Mode
			MmCached,     // Caching
			NULL,         // Address
			FALSE,        // Bugcheck?
			HighPagePriority); // Priority
#endif
		if (!userVa)
		{
			MmUnmapLockedPages(kernelVa, mdl);
			MmFreePagesFromMdl(mdl);
			IoFreeMdl(mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	//
	// If we get NULL back, the request didn't work.
	// I'm thinkin' that's better than a bug check anyday.
	//
	if (!userVa || !kernelVa)
	{
		if (userVa)
		{
			MmUnmapLockedPages(userVa, mdl);
		}
		if (kernelVa)
		{
			MmUnmapLockedPages(kernelVa, mdl);
		}
		MmFreePagesFromMdl(mdl);
		IoFreeMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Return the allocated pointers
	//
	pSharedMemory->mdl = mdl;
	pSharedMemory->userVa = userVa;
	pSharedMemory->kernelVa = kernelVa;
	pSharedMemory->bufferLength = MmGetMdlByteCount(mdl);

	return STATUS_SUCCESS;
}
NTSTATUS devctrl_openMem(PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PVOID ioBuffer = NULL;
	ioBuffer = irp->AssociatedIrp.SystemBuffer;
	if (!ioBuffer)
	{
		ioBuffer = irp->UserBuffer;
	}
	ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (ioBuffer && (outputBufferLength >= sizeof(NF_BUFFERS)))
	{
		NTSTATUS status;

		for (;;)
		{
			if (!g_inBuf.mdl)
			{
				status = devctrl_createSharedMemory(&g_inBuf, NF_UDP_PACKET_BUF_SIZE * 50);
				if (!NT_SUCCESS(status))
				{
					break;
				}
			}

			if (!g_outBuf.mdl)
			{
				status = devctrl_createSharedMemory(&g_outBuf, NF_UDP_PACKET_BUF_SIZE * 2);
				if (!NT_SUCCESS(status))
				{
					break;
				}
			}

			status = STATUS_SUCCESS;

			break;
		}

		if (!NT_SUCCESS(status))
		{
			devctrl_freeSharedMemory(&g_inBuf);
			devctrl_freeSharedMemory(&g_outBuf);
		}
		else
		{
			PNF_BUFFERS pBuffers = (PNF_BUFFERS)ioBuffer;

			pBuffers->inBuf = (UINT64)g_inBuf.userVa;
			pBuffers->inBufLen = g_inBuf.bufferLength;
			pBuffers->outBuf = (UINT64)g_outBuf.userVa;
			pBuffers->outBufLen = g_outBuf.bufferLength;

			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(NF_BUFFERS);
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_SUCCESS;
		}
	}

	irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_UNSUCCESSFUL;
}

// read packet to r3
VOID devctrl_cancelRead(IN PDEVICE_OBJECT deviceObject, IN PIRP irp)
{
	KLOCK_QUEUE_HANDLE lh;

	UNREFERENCED_PARAMETER(deviceObject);

	IoReleaseCancelSpinLock(irp->CancelIrql);

	sl_lock(&g_sIolock, &lh);

	RemoveEntryList(&irp->Tail.Overlay.ListEntry);

	sl_unlock(&lh);

	irp->IoStatus.Status = STATUS_CANCELLED;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}
NTSTATUS devctrl_readEx(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;

	for (;;)
	{
		if (irp->MdlAddress == NULL)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (VerifiMmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL ||
			irpSp->Parameters.Read.Length < sizeof(NF_READ_RESULT))
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		sl_lock(&g_sIolock, &lh);

		IoSetCancelRoutine(irp, devctrl_cancelRead);

		if (irp->Cancel &&
			IoSetCancelRoutine(irp, NULL))
		{
			status = STATUS_CANCELLED;
		}
		else
		{
			// pending请求
			IoMarkIrpPending(irp);
			InsertTailList(&g_pendedIoRequests, &irp->Tail.Overlay.ListEntry);
			status = STATUS_PENDING;
		}

		sl_unlock(&lh);

		// 激活处理事件
		KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);

		break;
	}

	if (status != STATUS_PENDING)
	{
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}
NTSTATUS devctrl_read(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(irpSp);
	NTSTATUS 	status = STATUS_SUCCESS;

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

void NTAPI devctrl_udpInjectCompletion(IN void* context,IN OUT NET_BUFFER_LIST* netBufferList,IN BOOLEAN dispatchLevel)
{
	PNF_UDP_INJECT_CONTEXT inject_context = (PNF_UDP_INJECT_CONTEXT)context;
	PUDPCTX pUdpCtx = NULL;
	KLOCK_QUEUE_HANDLE lh;

	UNREFERENCED_PARAMETER(dispatchLevel);
	// Clearn
	if (netBufferList)
	{
		// GetLastError
		//KdPrint((DPREFIX"[UDP] Inject Completion Code %u\n", netBufferList->Status));
		PMDL pMdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(netBufferList));
		if (pMdl != inject_context->mdl)
		{
			IoFreeMdl(pMdl);
		}
		FwpsFreeNetBufferList(netBufferList);
	}

	if (inject_context != NULL)
	{
		if (inject_context->mdl != NULL)
		{
			free_np(inject_context->mdl->MappedSystemVa);
			IoFreeMdl(inject_context->mdl);
			inject_context->mdl = NULL;
		}
		pUdpCtx = inject_context->pUdpCtx;

		sl_lock(&pUdpCtx->lock, &lh);
		if (inject_context->code == NF_UDP_SEND)
		{
			pUdpCtx->injectedSendBytes -= inject_context->pPacket->dataLength;
			if (pUdpCtx->injectedSendBytes <= UDP_PEND_LIMIT)
			{
				pUdpCtx->sendInProgress = FALSE;
			}

			pUdpCtx->outCounter += inject_context->pPacket->dataLength;
			pUdpCtx->outCounterTotal += inject_context->pPacket->dataLength;
		}
		else
		{
			pUdpCtx->injectedRecvBytes -= inject_context->pPacket->dataLength;
			if (pUdpCtx->injectedRecvBytes <= UDP_PEND_LIMIT)
			{
				pUdpCtx->recvInProgress = FALSE;
			}

			pUdpCtx->inCounter += inject_context->pPacket->dataLength;
			pUdpCtx->inCounterTotal += inject_context->pPacket->dataLength;
		}
		sl_unlock(&lh);

		if (inject_context->pPacket)
		{
			udp_freePacketData(inject_context->pPacket);
		}
		udp_freeCtx(pUdpCtx);
		ExFreeToNPagedLookasideList(&g_udpInjectContextLAList, inject_context);
	}
}
ULONG devctrl_processInjectUDPPacket(PNF_DATA pData)
{
	// Check Buffer Size
	const ULONG nErrRet = sizeof(NF_DATA) - 1 + pData->bufferSize;
	if (pData->bufferSize < (NF_MAX_ADDRESS_LENGTH + sizeof(NF_UDP_PACKET_OPTIONS)))
		return nErrRet;

	// find by id
	PUDPCTX pUdpCtx = NULL;
	pUdpCtx = udp_findById(pData->id);
	if (!pUdpCtx) {
		// Recv Failuer Packet
		if (pData->code != NF_UDP_SEND)
			return nErrRet;

		// Send Handler == 0
		pUdpCtx = udp_packetAllocatCtxHandle(0);
		if (!pUdpCtx)
			return nErrRet;
	}

	// Close
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&pUdpCtx->lock, &lh);
	if (pUdpCtx->closed)
	{
		sl_unlock(&lh);
		udp_freeCtx(pUdpCtx);
		return nErrRet;
	}

	// PendList
	if ((pData->code == NF_UDP_SEND && pUdpCtx->sendInProgress) ||
		(pData->code == NF_UDP_RECV && pUdpCtx->recvInProgress))
	{
		sl_unlock(&lh);
		udp_freeCtx(pUdpCtx);
		return 0;
	}

	sl_unlock(&lh);

	/* NF_DATA + OPTION + REMOTEADDR + CONTROLDATA + UDPDATA*/
	NTSTATUS nStus = STATUS_UNSUCCESSFUL;
	ULONG uoffset = 0, uDataLength = 0, uResult = 0;
	PVOID pUDataCopy = NULL;
	PNF_UDP_PACKET pPacket = NULL;
	PNF_UDP_INJECT_CONTEXT pInjectCtx = NULL;

	PMDL pMdL = NULL;
	NET_BUFFER* netBuffer = NULL;
	NET_BUFFER_LIST* pNetBufferList = NULL;

	UDP_HEADER* pUDPHeader = NULL;
	UCHAR* pRemoteAddr = NULL;
	UCHAR* pLocalAddr = NULL;
	do
	{
		pPacket = udp_packetAllocatData(0);
		if (!pPacket)
			break;

		// Option
		RtlCopyMemory(&pPacket->options, pData->buffer + uoffset, sizeof(NF_UDP_PACKET_OPTIONS));
		uoffset += sizeof(NF_UDP_PACKET_OPTIONS);
		
		// Remote
		RtlCopyMemory(pPacket->remoteAddr, pData->buffer + uoffset, NF_MAX_ADDRESS_LENGTH);
		uoffset += NF_MAX_ADDRESS_LENGTH;

		// ControlData
		if (pPacket->options.controlDataLength > 0)
		{
#pragma warning(push)
#pragma warning(disable: 28197) 
#if (NTDDI_VERSION >= NTDDI_WIN8)
			pPacket->controlData = (WSACMSGHDR*)
				ExAllocatePoolWithTag(NonPagedPoolNx, pPacket->options.controlDataLength, MEM_TAG_UDP_DATA);
#else
			pPacket->controlData = (WSACMSGHDR*)
				ExAllocatePoolWithTag(NonPagedPool, pPacket->options.controlDataLength, MEM_TAG_UDP_DATA);
#endif
#pragma warning(pop)

			if (!pPacket->controlData)
			{
				nStus = STATUS_NO_MEMORY;
				break;
			}
			
			RtlCopyMemory(pPacket->controlData, pData->buffer + uoffset, pPacket->options.controlDataLength);
			uoffset += pPacket->options.controlDataLength;
		}
		else
		{
			pPacket->controlData = NULL;
		}
		
		// UDPData Size
		uDataLength = pData->bufferSize - uoffset;
		if (uDataLength <= 0) {
			nStus = STATUS_NO_MEMORY;
			break;
		}
		pPacket->dataLength = uDataLength;

		// Allocat UdpData 
#if (NTDDI_VERSION >= NTDDI_WIN8)
		pUDataCopy = ExAllocatePoolWithTag(NonPagedPoolNx, uDataLength, MEM_TAG_UDP_DATA_COPY);
#else
		pUDataCopy = ExAllocatePoolWithTag(NonPagedPool, uDataLength, MEM_TAG_UDP_DATA_COPY);
#endif
		if (pUDataCopy == NULL)
		{
			nStus = STATUS_NO_MEMORY;
			break;
		}
		RtlCopyMemory(pUDataCopy, pData->buffer + uoffset, uDataLength);

		// Allocat Inject 
		pInjectCtx = (PNF_UDP_INJECT_CONTEXT)ExAllocateFromNPagedLookasideList(&g_udpInjectContextLAList);
		if (pInjectCtx == NULL)
		{
			nStus = STATUS_NO_MEMORY;
			break;
		}
		
		// MDL
		pMdL = IoAllocateMdl(
			pUDataCopy,
			uDataLength,
			FALSE,
			FALSE,
			NULL);
		if (pMdL == NULL)
		{
			nStus = STATUS_NO_MEMORY;
			break;
		}
		MmBuildMdlForNonPagedPool(pMdL);

		nStus = FwpsAllocateNetBufferAndNetBufferList(
			g_netBufferListPool,
			0,
			0,
			pMdL,
			0,
			uDataLength,
			&pNetBufferList); // Fix **
		if (!NT_SUCCESS(nStus))
			break;

		netBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
		if (!netBuffer) {
			nStus = STATUS_NO_MEMORY;
			break;
		}

		pInjectCtx->id = pData->id;
		pInjectCtx->code = pData->code;
		pInjectCtx->mdl = pMdL;
		pInjectCtx->pUdpCtx = pUdpCtx;
		pInjectCtx->pPacket = pPacket;
		
		// ref add one
		udpctx_addRef(pUdpCtx);

		// Set Inject Buffer Size
		sl_lock(&pUdpCtx->lock, &lh);
		if (pData->code == NF_UDP_SEND)
		{
			pUdpCtx->injectedSendBytes += pPacket->dataLength;
			if (pUdpCtx->injectedSendBytes > UDP_PEND_LIMIT)
			{
				pUdpCtx->sendInProgress = TRUE;
			}
		}
		else
		{
			pUdpCtx->injectedRecvBytes += pPacket->dataLength;
			if (pUdpCtx->injectedRecvBytes > UDP_PEND_LIMIT)
			{
				pUdpCtx->recvInProgress = TRUE;
			}
		}
		sl_unlock(&lh);

		if (pData->code == NF_UDP_SEND)
		{
			RtlSecureZeroMemory(&pPacket->sendArgs, sizeof(pPacket->sendArgs));
			pUDPHeader = (UDP_HEADER*)NdisGetDataBuffer(
				netBuffer,
				sizeof(UDP_HEADER),
				NULL,
				1,
				0
			);
			ASSERT(pUDPHeader != NULL);
			if (!pUDPHeader)
			{
				nStus = STATUS_NO_MEMORY;
				break;
			}

			if (pUdpCtx->transportEndpointHandle == 0)
			{
				struct sockaddr_in* pAddr = (struct sockaddr_in*)pPacket->remoteAddr;
				pUdpCtx->ip_family = pAddr->sin_family;
				pUdpCtx->ipProto = IPPROTO_UDP;
				RtlCopyMemory(&pUdpCtx->localAddr, &pPacket->options.localAddr, NF_MAX_ADDRESS_LENGTH);
			}

			if (pUdpCtx->ip_family == AF_INET)
			{
				struct sockaddr_in* pAddr = (struct sockaddr_in*)pPacket->remoteAddr;
				pUDPHeader->destPort = pAddr->sin_port;
				pUDPHeader->length = htons(uDataLength);
				pUDPHeader->checksum = 0;
				pPacket->sendArgs.remoteAddress = (UCHAR*)&pAddr->sin_addr;
				pRemoteAddr = (UCHAR*)&pAddr->sin_addr;
				pAddr = (struct sockaddr_in*)pUdpCtx->localAddr;
				pLocalAddr = (UCHAR*)&pAddr->sin_addr;
			}
			else
			{
				struct sockaddr_in6* pAddr = (struct sockaddr_in6*)pPacket->remoteAddr;
				pUDPHeader->destPort = pAddr->sin6_port;
				pUDPHeader->length = htons(uDataLength);
				pUDPHeader->checksum = 0;
				pPacket->sendArgs.remoteAddress = (UCHAR*)&pAddr->sin6_addr;
				pRemoteAddr = (UCHAR*)&pAddr->sin6_addr;
				pAddr = (struct sockaddr_in6*)pUdpCtx->localAddr;
				pLocalAddr = (UCHAR*)&pAddr->sin6_addr;
			}

			pPacket->sendArgs.remoteScopeId = pPacket->options.remoteScopeId;
			pPacket->sendArgs.controlData = pPacket->controlData;
			pPacket->sendArgs.controlDataLength = pPacket->options.controlDataLength;

			if (g_udpNwInject || (pUdpCtx->transportEndpointHandle == 0))
			{
				// Construct a new IP header
				nStus = FwpsConstructIpHeaderForTransportPacket0(
					pNetBufferList,
					0,
					pUdpCtx->ip_family,
					pLocalAddr,
					pRemoteAddr,
					(IPPROTO)pUdpCtx->ipProto,
					0,
					pPacket->controlData,
					pPacket->options.controlDataLength,
					0,
					NULL,
					pPacket->options.interfaceIndex,
					pPacket->options.subInterfaceIndex
				);

				if (!NT_SUCCESS(nStus))
					break;

				// Inject Packet
				if (pUdpCtx->ip_family == AF_INET)
				{
					nStus = FwpsInjectNetworkSendAsync0(
						g_udpNwInjectionHandleV4,
						NULL,
						0,
						pPacket->options.compartmentId,
						pNetBufferList,
						devctrl_udpInjectCompletion,
						pInjectCtx
					);
				}
				else
				{
					nStus = FwpsInjectNetworkSendAsync0(
						g_udpNwInjectionHandleV6,
						NULL,
						0,
						pPacket->options.compartmentId,
						pNetBufferList,
						devctrl_udpInjectCompletion,
						pInjectCtx
					);
				}
			}
			else
			{
				nStus = FwpsInjectTransportSendAsync0(
					g_udpInjectionHandle,
					NULL,
					pPacket->options.endpointHandle,
					0,
					&pPacket->sendArgs,
					pUdpCtx->ip_family,
					pPacket->options.compartmentId,
					pNetBufferList,
					devctrl_udpInjectCompletion,
					pInjectCtx
				);
			}

			if (NT_SUCCESS(nStus))
			{
				uResult = sizeof(NF_DATA) - 1 + pData->bufferSize;
				pPacket = NULL;
				pNetBufferList = NULL;
			}
		}
		else
		{
			// NF_UDP_RECV
			pUDPHeader = (UDP_HEADER*)NdisGetDataBuffer(
				netBuffer,
				sizeof(UDP_HEADER),
				NULL,
				1,
				0
			);
			ASSERT(pUDPHeader != NULL);
			if (!pUDPHeader)
			{
				nStus = STATUS_NO_MEMORY;
				break;
			}
			if (pUdpCtx->ip_family == AF_INET)
			{
				struct sockaddr_in* pAddr = (struct sockaddr_in*)pPacket->remoteAddr;
				pUDPHeader->srcPort = pAddr->sin_port;
				pUDPHeader->length = htons(uDataLength);
				pUDPHeader->checksum = 0;
				pRemoteAddr = (UCHAR*)&pAddr->sin_addr;
				pAddr = (struct sockaddr_in*)pUdpCtx->localAddr;
				pLocalAddr = (UCHAR*)&pAddr->sin_addr;
				pUDPHeader->destPort = pAddr->sin_port;
			}
			else
			{
				struct sockaddr_in6* pAddr = (struct sockaddr_in6*)pPacket->remoteAddr;
				pUDPHeader->srcPort = pAddr->sin6_port;
				pUDPHeader->length = htons(uDataLength);
				pUDPHeader->checksum = 0;
				pRemoteAddr = (UCHAR*)&pAddr->sin6_addr;
				pAddr = (struct sockaddr_in6*)pUdpCtx->localAddr;
				pLocalAddr = (UCHAR*)&pAddr->sin6_addr;
				pUDPHeader->destPort = pAddr->sin6_port;
			}

			nStus = FwpsConstructIpHeaderForTransportPacket0(
				pNetBufferList,
				0,
				pUdpCtx->ip_family,
				pRemoteAddr,
				pLocalAddr,
				(IPPROTO)pUdpCtx->ipProto,
				0,
				NULL,
				0,
				0,
				NULL,
				0, //pPacket->options.interfaceIndex,
				0  //pPacket->options.subInterfaceIndex
			);

			if (!NT_SUCCESS(nStus))
				break;
			
			nStus = FwpsInjectTransportReceiveAsync0(
				g_udpInjectionHandle,
				NULL,
				NULL,
				0,
				pUdpCtx->ip_family,
				pPacket->options.compartmentId,
				pPacket->options.interfaceIndex,
				pPacket->options.subInterfaceIndex,
				pNetBufferList,
				devctrl_udpInjectCompletion,
				pInjectCtx
			);

			if (NT_SUCCESS(nStus))
			{
				uResult = sizeof(NF_DATA) + pData->bufferSize - 1;
				pPacket = NULL;
				pNetBufferList = NULL;
			}
		}

		if (!NT_SUCCESS(nStus))
		{
			sl_lock(&pUdpCtx->lock, &lh);
			if (pData->code == NF_UDP_SEND)
			{
				pUdpCtx->injectedSendBytes -= pPacket->dataLength;
				if (pUdpCtx->injectedSendBytes <= UDP_PEND_LIMIT)
				{
					pUdpCtx->sendInProgress = FALSE;
				}
			}
			else
			{
				pUdpCtx->injectedRecvBytes -= pPacket->dataLength;
				if (pUdpCtx->injectedRecvBytes <= UDP_PEND_LIMIT)
				{
					pUdpCtx->recvInProgress = FALSE;
				}
			}
			sl_unlock(&lh);
			
			udp_freeCtx(pUdpCtx);
		}

	} while (FALSE);

	// Clear
	if (!NT_SUCCESS(nStus))
	{
		if (pNetBufferList != NULL)
		{
			FwpsFreeNetBufferList(pNetBufferList);
			pNetBufferList = NULL;
		}
		if (pMdL != NULL)
		{
			IoFreeMdl(pMdL);
			pMdL = NULL;
		}
		if (pUDataCopy != NULL)
		{
			free_np(pUDataCopy);
			pUDataCopy = NULL;
		}
		if (pInjectCtx != NULL)
		{
			ExFreeToNPagedLookasideList(&g_udpInjectContextLAList, pInjectCtx);
			pInjectCtx = NULL;
		}
		if (pPacket != NULL)
		{
			udp_freePacketData(pPacket);
			pPacket = NULL;
		}
	}	

	if (pUdpCtx)
		udp_freeCtx(pUdpCtx);

	return uResult;

}
ULONG devctrl_processUdpHandler(const NF_DATA_CODE nfCode, PNF_DATA pData)
{
	if (nfCode == NF_UDP_SEND) {
		return devctrl_processInjectUDPPacket(pData);
	}
	else if (nfCode == NF_UDP_RECV) {
		return devctrl_processInjectUDPPacket(pData);
	}
	return 0;
}
ULONG devctrl_processTcpConnect(PNF_DATA pData)
/*
* FwpsPendClassify0 -->
	FwpsApplyModifiedLayerData --> FwpsCompleteClassify
*/
{
	PTCPCTX				pTcpCtx = NULL;
	PNF_TCP_CONN_INFO	pInfo = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	pInfo = (PNF_TCP_CONN_INFO)pData->buffer;

	if (!pInfo)
		return 0;

	pTcpCtx = tcp_find(pData->id);
	if (!pTcpCtx)
	{
		return 0;
	}

	if (pTcpCtx->redirectInfo.isPended)
	{
		FWPS_CONNECT_REQUEST* pConnectRequest = NULL;
		int addrLen = 0;

		pTcpCtx->filteringFlag = pInfo->filteringFlag;

		if (pTcpCtx->ip_family == AF_INET)
		{
			addrLen = sizeof(struct sockaddr_in);
		}
		else
		{
			addrLen = sizeof(struct sockaddr_in6);
		}
		if ((memcmp(pTcpCtx->remoteAddr, pInfo->remoteAddress, addrLen) != 0) ||
			(pTcpCtx->filteringFlag & NF_BLOCK))
		{
			status = FwpsAcquireWritableLayerDataPointer(
				pTcpCtx->redirectInfo.classifyHandle,
				pTcpCtx->redirectInfo.filterId,
				0,
				(PVOID*)&pConnectRequest,
				&pTcpCtx->redirectInfo.classifyOut);
			if (NT_SUCCESS(status) && pConnectRequest)  {
				if (pTcpCtx->filteringFlag & NF_BLOCK)
					RtlSecureZeroMemory(&pConnectRequest->remoteAddressAndPort, NF_MAX_ADDRESS_LENGTH);
				else
					memcpy(&pConnectRequest->remoteAddressAndPort, pInfo->remoteAddress, NF_MAX_ADDRESS_LENGTH);
				pConnectRequest->localRedirectTargetPID = pInfo->processId;
#ifdef USE_NTDDI
#if (NTDDI_VERSION >= NTDDI_WIN8)
				pConnectRequest->localRedirectHandle = pTcpCtx->redirectInfo.redirectHandle;
#endif
#endif
				FwpsApplyModifiedLayerData(pTcpCtx->redirectInfo.classifyHandle,
					pConnectRequest,
					0);
			}
		}

		if (pTcpCtx->filteringFlag & NF_BLOCK)
		{
			pTcpCtx->redirectInfo.classifyOut.actionType = FWP_ACTION_BLOCK;
		}
		else
		{
			pTcpCtx->redirectInfo.classifyOut.actionType = FWP_ACTION_PERMIT;
		}
		tcp_purgeRedirectInfo(pTcpCtx);
	}
	tcp_release(pTcpCtx);
	return sizeof(NF_DATA) - 1;
}
// write packet from r3
ULONG devctrl_processRequest(ULONG bufferSize)
{
	PNF_DATA pData = (PNF_DATA)g_outBuf.kernelVa;
	if (!pData) {
		return 0;
	}

	if (bufferSize < (sizeof(NF_DATA) + pData->bufferSize - 1)) {
		return 0;
	}

	switch (pData->code)
	{
	case NF_TCP_CONNECT_REQUEST:
		return devctrl_processTcpConnect(pData);
	case NF_UDP_SEND:
	case NF_UDP_RECV:
		return devctrl_processUdpHandler(pData->code, pData);
	default:
		break;
	}
	return 0;
}
NTSTATUS devctrl_write(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PNF_READ_RESULT pRes = NULL;
	ULONG bufferLength = irpSp->Parameters.Write.Length;

	pRes = (PNF_READ_RESULT)VerifiMmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
	if (!pRes || bufferLength < sizeof(NF_READ_RESULT))
	{
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irp->IoStatus.Information = devctrl_processRequest((ULONG)pRes->length);
	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// manage
NTSTATUS devctrl_close(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS 	status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(irpSp);

	// cloes需要清理 - 关闭共享内存
	devctrl_setmonitor(0);
	establishedctx_clean();
	//datalinkctx_clean();
	tcp_clean();
	udp_clean();
	devctrl_clean();

	devctrl_freeSharedMemory(&g_inBuf);
	devctrl_freeSharedMemory(&g_outBuf);

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}
NTSTATUS devctrl_setmonitor(int flag)
{
	// 设置打印标签
	if (0 == flag)
		g_monitorflag = FALSE;
	else if (1 == flag)
		g_monitorflag = TRUE;
	else
		g_monitorflag = FALSE;
	return STATUS_SUCCESS;
}
NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	PIO_STACK_LOCATION irpSp;

	UNREFERENCED_PARAMETER(DeviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);
	ASSERT(irpSp);

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_CREATE:
		return devctrl_create(irp, irpSp);

	case IRP_MJ_READ:
	{
		return devctrl_readEx(irp, irpSp);
	}

	case IRP_MJ_WRITE:
		return devctrl_write(irp, irpSp);

	case IRP_MJ_CLOSE:
	{
		return devctrl_close(irp, irpSp);
	}


	case IRP_MJ_DEVICE_CONTROL:
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case CTL_DEVCTRL_ENABLE_MONITOR:
			devctrl_setmonitor(1);
			break;
		case CTL_DEVCTRL_DISENTABLE_MONITOR:
			devctrl_setmonitor(0);
			break;
		case CTL_DEVCTRL_OPEN_SHAREMEM:
		{	
			return devctrl_openMem(DeviceObject, irp, irpSp);
		}
		default:
			break;
		}
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(NF_BUFFERS);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS devctrl_init(PDRIVER_OBJECT pDriverObject)
{
	HANDLE threadHandle;
	NTSTATUS status = STATUS_SUCCESS;

	// Init List
	InitializeListHead(&g_pendedIoRequests);
	InitializeListHead(&g_IoQueryHead);
	VerifiExInitializeNPagedLookasideList(&g_IoQueryList, NULL, NULL, 0, sizeof(NF_QUEUE_ENTRY), 'NFQU', 0);
	KeInitializeSpinLock(&g_sIolock);
	
	// Init I/O handler Thread
	KeInitializeEvent(
		&g_ioThreadEvent,
		SynchronizationEvent,
		FALSE
	);

	status = PsCreateSystemThread(
		&threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		devctrl_ioThread,
		NULL
	);

	if (NT_SUCCESS(status))
	{
		KPRIORITY priority = HIGH_PRIORITY;

		ZwSetInformationThread(threadHandle, ThreadPriority, &priority, sizeof(priority));

		status = ObReferenceObjectByHandle(
			threadHandle,
			0,
			NULL,
			KernelMode,
			&g_ioThreadObject,
			NULL
		);
		ASSERT(NT_SUCCESS(status));

		ZwClose(threadHandle);
	}

	// Init Inject handler Thread
	KeInitializeSpinLock(&g_sTInjectQueue);
	InitializeListHead(&g_tInjectQueue);

	KeInitializeEvent(
		&g_threadIoEvent,
		SynchronizationEvent,
		FALSE
	);

	status = PsCreateSystemThread(
		&threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		devctrl_injectThread,
		NULL
	);

	if (NT_SUCCESS(status)) {
		KPRIORITY priority = HIGH_PRIORITY;

		ZwSetInformationThread(threadHandle, ThreadPriority, &priority, sizeof(priority));

		status = ObReferenceObjectByHandle(
			threadHandle,
			0,
			NULL,
			KernelMode,
			&g_threadObject,
			NULL
		);
		ASSERT(NT_SUCCESS(status));
		ZwClose(threadHandle);
	}

	VerifiExInitializeNPagedLookasideList(&g_udpInjectContextLAList,
		NULL,
		NULL,
		0,
		sizeof(NF_UDP_INJECT_CONTEXT),
		MEM_TAG_UDP_INJECT,
		0);

	// Craete Inject Handle
	do
	{
		NET_BUFFER_LIST_POOL_PARAMETERS nblPoolParams = { 0 };

		g_ndisGenericObj = NdisAllocateGenericObject(pDriverObject, MEM_TAG, 0);
		if (g_ndisGenericObj == NULL)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		nblPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		nblPoolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		nblPoolParams.Header.Size = sizeof(nblPoolParams);
		nblPoolParams.fAllocateNetBuffer = TRUE;
		nblPoolParams.DataSize = 0;
		nblPoolParams.PoolTag = MEM_TAG;

		g_netBufferListPool = NdisAllocateNetBufferListPool(g_ndisGenericObj, &nblPoolParams);
		if (g_netBufferListPool == NULL)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		// stream tcp
		status = FwpsInjectionHandleCreate(
			AF_UNSPEC,
			FWPS_INJECTION_TYPE_STREAM,
			&g_injectionHandle);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		// network v4
		status = FwpsInjectionHandleCreate(
			AF_INET,
			FWPS_INJECTION_TYPE_NETWORK,
			&g_netInjectionHandleV4);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		// network v6
		status = FwpsInjectionHandleCreate(
			AF_INET6,
			FWPS_INJECTION_TYPE_NETWORK,
			&g_netInjectionHandleV6);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		// udp
		status = FwpsInjectionHandleCreate(
			AF_UNSPEC,
			FWPS_INJECTION_TYPE_TRANSPORT,	// 传输
			&g_udpInjectionHandle);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		status = FwpsInjectionHandleCreate(
			AF_INET,
			FWPS_INJECTION_TYPE_NETWORK,
			&g_udpNwInjectionHandleV4);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		// udp6
		status = FwpsInjectionHandleCreate(
			AF_INET6,
			FWPS_INJECTION_TYPE_NETWORK,
			&g_udpNwInjectionHandleV6);
		if (!NT_SUCCESS(status))
		{
			break;
		}
	} while (0);

	return status;
}
VOID devctrl_clean()
{
	PNF_QUEUE_ENTRY pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_sIolock, &lh);
	while (!IsListEmpty(&g_IoQueryHead))
	{
		pQuery = (PNF_QUEUE_ENTRY)RemoveHeadList(&g_IoQueryHead);
		sl_unlock(&lh);

		ExFreeToNPagedLookasideList(&g_IoQueryList, pQuery);
		pQuery = NULL;
		sl_lock(&g_sIolock, &lh);
	}
	sl_unlock(&lh);

	// clearn pennding read
	PIRP                irp = NULL;
	PLIST_ENTRY         pIrpEntry;
	sl_lock(&g_sIolock, &lh);
	if (IsListEmpty(&g_pendedIoRequests))
	{
		sl_unlock(&lh);
		return;
	}
	pIrpEntry = g_pendedIoRequests.Flink;
	while (pIrpEntry != &g_pendedIoRequests)
	{
		irp = CONTAINING_RECORD(pIrpEntry, IRP, Tail.Overlay.ListEntry);

		if (IoSetCancelRoutine(irp, NULL))
		{
			// 移除
			RemoveEntryList(pIrpEntry);
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return;
			break;
		}
		else
		{
			pIrpEntry = pIrpEntry->Flink;
		}
	}
	sl_unlock(&lh);
}
VOID devctrl_free()
{
	devctrl_clean();

	ExDeleteNPagedLookasideList(&g_IoQueryList);
	
	if (g_ioThreadObject)
	{
		KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);

		KeWaitForSingleObject(
			g_ioThreadObject,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		ObDereferenceObject(g_ioThreadObject);
		g_ioThreadObject = NULL;
	}

	if (g_threadObject)
	{
		KeSetEvent(&g_threadIoEvent, IO_NO_INCREMENT, FALSE);

		KeWaitForSingleObject(
			g_threadObject,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		ObDereferenceObject(g_threadObject);
		g_threadObject = NULL;
	}

	if (g_injectionHandle != NULL) {
		FwpsInjectionHandleDestroy(g_injectionHandle);
		g_injectionHandle = NULL;
	}
	if (g_netInjectionHandleV4 != NULL) {
		FwpsInjectionHandleDestroy(g_netInjectionHandleV4);
		g_netInjectionHandleV4 = NULL;
	}
	if (g_netInjectionHandleV6 != NULL) {
		FwpsInjectionHandleDestroy(g_netInjectionHandleV6);
		g_netInjectionHandleV6 = NULL;
	}
	if (g_udpInjectionHandle != NULL)
	{
		FwpsInjectionHandleDestroy(g_udpInjectionHandle);
		g_udpInjectionHandle = NULL;
	}
	if (g_udpNwInjectionHandleV4 != NULL) {
		FwpsInjectionHandleDestroy(g_udpNwInjectionHandleV4);
		g_udpNwInjectionHandleV4 = NULL;
	}
	if (g_udpNwInjectionHandleV6 != NULL) {
		FwpsInjectionHandleDestroy(g_udpNwInjectionHandleV6);
		g_udpNwInjectionHandleV6 = NULL;
	}
	if (g_netBufferListPool != NULL)
	{
		NdisFreeNetBufferListPool(g_netBufferListPool);
		g_netBufferListPool = NULL;
	}
	if (g_ndisGenericObj != NULL)
	{
		NdisFreeGenericObject(g_ndisGenericObj);
		g_ndisGenericObj = NULL;
	}

	ExDeleteNPagedLookasideList(&g_udpInjectContextLAList);
	return;
}
VOID devctrl_setShutdown()
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_sIolock, &lh);
	g_shutdown = TRUE;
	sl_unlock(&lh);
}
void devctrl_sleep(UINT ttw)
{
	NDIS_EVENT  _SleepEvent;
	NdisInitializeEvent(&_SleepEvent);
	NdisWaitEvent(&_SleepEvent, ttw);
}
BOOLEAN	devctrl_isShutdown()
{
	BOOLEAN		res;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_sIolock, &lh);
	res = g_shutdown;
	sl_unlock(&lh);

	return res;
}

// list push/pop
NTSTATUS devctrl_pushEventQueryLisy(int code)
{
	NTSTATUS status = STATUS_SUCCESS;
	PNF_QUEUE_ENTRY pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;
	// Send to I/O(Read) Buffer
	switch (code)
	{
	case NF_DATALINKMAC_LAYER_PACKET:
	case NF_ESTABLISHED_LAYER_PACKET:
	case NF_TCPREDIRECT_LAYER_PACKET:
	case NF_UDP_SEND:
	case NF_UDP_RECV:
	{
		pQuery = (PNF_QUEUE_ENTRY)ExAllocateFromNPagedLookasideList(&g_IoQueryList);
		if (!pQuery)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		pQuery->code = code;
		sl_lock(&g_sIolock, &lh);
		InsertHeadList(&g_IoQueryHead, &pQuery->entry);
		sl_unlock(&lh);
	}
	break;
	default:
		break;
	}
	// keSetEvent
	KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);
	return status;
}
NTSTATUS devtrl_popDataLinkData(UINT64* pOffset)
{
	NTSTATUS status = STATUS_SUCCESS;
	PNF_DATALINK_DATA pdatalinkbuf = NULL;
	PNF_DATALINK_BUFFER pEntry = NULL;
	KLOCK_QUEUE_HANDLE lh;
	PNF_DATA	pData;
	UINT64		dataSize = 0;
	ULONG		pPacketlens = 0;

	pdatalinkbuf = datalink_get();
	if (!pdatalinkbuf)
		return STATUS_UNSUCCESSFUL;
	
	sl_lock(&pdatalinkbuf->lock, &lh);
	
	do {

		if (IsListEmpty(&pdatalinkbuf->pendedPackets))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	
		pEntry = (PNF_DATALINK_BUFFER)RemoveHeadList(&pdatalinkbuf->pendedPackets);
		if (!pEntry)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		pPacketlens = pEntry->dataLength;
		dataSize = sizeof(NF_DATA) - 1 + pPacketlens;
		if ((g_inBuf.bufferLength - *pOffset) < dataSize)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);
		pData->code = NF_DATALINKMAC_LAYER_PACKET;
		pData->id = 0;
		pData->bufferSize = pEntry->dataLength;

		if (pEntry->dataBuffer) {
			RtlCopyMemory(pData->buffer, pEntry->dataBuffer, pEntry->dataLength);
		}
		
		*pOffset += dataSize;
		status = STATUS_SUCCESS;
	} while (FALSE);

	sl_unlock(&lh);

	if (pEntry)
	{
		if (NT_SUCCESS(status))
		{
			datalinkctx_packfree(pEntry);
		}
		else
		{
			sl_lock(&pdatalinkbuf->lock, &lh);
			InsertHeadList(&pdatalinkbuf->pendedPackets, &pEntry->pEntry);
			sl_unlock(&lh);
		}
	}
	return status;
}
NTSTATUS devtrl_popFlowestablishedData(UINT64* pOffset)
{
	NTSTATUS status = STATUS_SUCCESS;
	PNF_FLOWESTABLISHED_DATA pestablishedbuf = NULL;
	PNF_FLOWESTABLISHED_BUFFER pEntry = NULL;
	KLOCK_QUEUE_HANDLE lh;
	PNF_DATA	pData;
	UINT64		dataSize = 0;
	ULONG		pPacketlens = 0;

	pestablishedbuf = establishedctx_get();
	if (!pestablishedbuf)
		return STATUS_UNSUCCESSFUL;

	sl_lock(&pestablishedbuf->lock, &lh);

	while (!IsListEmpty(&pestablishedbuf->pendedPackets))
	{
		pEntry = (PNF_FLOWESTABLISHED_BUFFER)RemoveHeadList(&pestablishedbuf->pendedPackets);

		pPacketlens = pEntry->dataLength;

		dataSize = sizeof(NF_DATA) - 1 + pPacketlens;
		
		if ((g_inBuf.bufferLength - *pOffset - 1) < dataSize)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);

		pData->code = NF_ESTABLISHED_LAYER_PACKET;
		pData->id = 0;
		pData->bufferSize = pEntry->dataLength;

		if (pEntry->dataBuffer) {
			RtlCopyMemory(pData->buffer, pEntry->dataBuffer, pEntry->dataLength);
		}

		*pOffset += dataSize;

		status = STATUS_SUCCESS;
		break;
	}

	sl_unlock(&lh);

	if (pEntry)
	{
		if (NT_SUCCESS(status))
		{
			establishedctx_packfree(pEntry);
		}
		else
		{
			sl_lock(&pestablishedbuf->lock, &lh);
			InsertHeadList(&pestablishedbuf->pendedPackets, &pEntry->pEntry);
			sl_unlock(&lh);
		}
	}

	return status;
}
NTSTATUS devtrl_popTcpRedirectConnectData(UINT64* pOffset)
{
	NTSTATUS			status = STATUS_SUCCESS;
	PNF_TCPCTX_DATA		pTcpCtxData = NULL;
	PNF_TCP_BUFFER		pEntry = NULL;
	PTCPCTX				pTcpCtxNode = NULL;

	KLOCK_QUEUE_HANDLE	lh;
	PNF_DATA			pData = NULL;
	UINT64				dataSize = 0;

	pTcpCtxData = tcp_Get();
	if (!pTcpCtxData)
		return STATUS_UNSUCCESSFUL;

	sl_lock(&pTcpCtxData->lock, &lh);
	while (!IsListEmpty(&pTcpCtxData->pendedPackets))
	{
		pEntry = (PNF_TCP_BUFFER)RemoveHeadList(&pTcpCtxData->pendedPackets);
		dataSize = sizeof(NF_DATA) - 1 + sizeof(NF_TCP_CONN_INFO);
		if ((g_inBuf.bufferLength - *pOffset - 1) < dataSize) {
			status = STATUS_NO_MEMORY;
			break;
		}

		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);
		if (!pData) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		pData->code = NF_TCPREDIRECT_LAYER_PACKET;
		pData->bufferSize = sizeof(NF_TCP_CONN_INFO);

		pTcpCtxNode = (PTCPCTX)(pEntry->dataBuffer);
		PNF_TCP_CONN_INFO pConnectInfo = (PNF_TCP_CONN_INFO)pData->buffer;
		if (pTcpCtxNode && pConnectInfo) {
			pData->id = pTcpCtxNode->id;
			pConnectInfo->filteringFlag = pTcpCtxNode->filteringFlag;
			pConnectInfo->pflag = pTcpCtxNode->pflag;
			pConnectInfo->processId = pTcpCtxNode->processId;
			pConnectInfo->direction = pTcpCtxNode->direction;
			pConnectInfo->ip_family = pTcpCtxNode->ip_family;
			RtlCopyMemory(pConnectInfo->localAddress, pTcpCtxNode->localAddr, NF_MAX_ADDRESS_LENGTH);
			RtlCopyMemory(pConnectInfo->remoteAddress, pTcpCtxNode->remoteAddr, NF_MAX_ADDRESS_LENGTH);
			*pOffset += dataSize;
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	sl_unlock(&lh);

	if (pEntry)
	{
		if (NT_SUCCESS(status))
		{
			tcp_packfree(pEntry);
		}
		else
		{
			sl_lock(&pTcpCtxData->lock, &lh);
			InsertHeadList(&pTcpCtxData->pendedPackets, &pEntry->pEntry);
			sl_unlock(&lh);
		}
	}
	return status;
}
NTSTATUS devtrl_popUdpPacketData(UINT64* pOffset, const int nCode) 
{
	NTSTATUS			status = STATUS_SUCCESS;
	PNF_UDPPEND_PACKET	pUdpPendData = NULL;
	PNF_UDP_BUFFER		pEntry = NULL;

	KLOCK_QUEUE_HANDLE	lh;
	PNF_DATA			pData = NULL;
	UINT64				dataSize = 0;

	ULONG				uoffset = 0;

	pUdpPendData = udp_Get();
	if (!pUdpPendData)
		return STATUS_UNSUCCESSFUL;

	sl_lock(&pUdpPendData->lock, &lh);
	while (!IsListEmpty(&pUdpPendData->pendedPackets))
	{
		pEntry = (PNF_UDP_BUFFER)RemoveHeadList(&pUdpPendData->pendedPackets);
		if (!pEntry || !pEntry->dataBuffer || !pEntry->dataLength) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		PNF_UDP_PACKET pPacket = (PNF_UDP_PACKET)pEntry->dataBuffer;
		if(!pPacket) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		/* NF_DATA + OPTION + REMOTEADDR + CONTROLDATA + UDPDATA*/
		const ULONG uExterSize = sizeof(NF_UDP_PACKET_OPTIONS) + NF_MAX_ADDRESS_LENGTH + pPacket->options.controlDataLength + pPacket->dataLength;
		dataSize = sizeof(NF_DATA) - 1 + uExterSize;
		if ((g_inBuf.bufferLength - *pOffset - 1) < dataSize) {
			status = STATUS_NO_MEMORY;
			break;
		}

		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);
		if (!pData) {
			status = STATUS_NO_MEMORY;
			break;
		}

		pData->id = pPacket->id;
		pData->code = nCode;
		pData->bufferSize = uExterSize;

		// Copy Option
		RtlCopyMemory(pData->buffer, &pPacket->options, sizeof(NF_UDP_PACKET_OPTIONS));
		uoffset += sizeof(NF_UDP_PACKET_OPTIONS);

		// Copy RemoteAddr
		RtlCopyMemory(pData->buffer + uoffset, pPacket->remoteAddr, NF_MAX_ADDRESS_LENGTH);
		uoffset += NF_MAX_ADDRESS_LENGTH;

		// Copy ControlData
		if (pPacket->options.controlDataLength > 0) {
			RtlCopyMemory(pData->buffer + uoffset, pPacket->controlData, pPacket->options.controlDataLength);
			uoffset += pPacket->options.controlDataLength;
		}

		// Copy UDPData
		if (pPacket->dataBuffer && pPacket->dataLength) {
			RtlCopyMemory(pData->buffer + uoffset, pPacket->dataBuffer, pPacket->dataLength);
			uoffset += pPacket->dataLength;
		}

		*pOffset += dataSize;
		status = STATUS_SUCCESS;
		break;
	}
	sl_unlock(&lh);

	if (pEntry)
	{
		if (NT_SUCCESS(status))
		{
			udp_freebuf(pEntry, 0);
		}
		else
		{
			sl_lock(&pUdpPendData->lock, &lh);
			InsertHeadList(&pUdpPendData->pendedPackets, &pEntry->pEntry);
			sl_unlock(&lh);
		}
	}
	return status;
}

// read thread 
UINT64 devctrl_fillBuffer()
{
	PNF_QUEUE_ENTRY	pEntry;
	UINT64		offset = 0;
	NTSTATUS	status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_sIolock, &lh);

	while (!IsListEmpty(&g_IoQueryHead))
	{
		pEntry = (PNF_QUEUE_ENTRY)RemoveHeadList(&g_IoQueryHead);

		sl_unlock(&lh);

		switch (pEntry->code)
		{
		case NF_DATALINKMAC_LAYER_PACKET:
		{
			status = devtrl_popDataLinkData(&offset);
		}
		break;
		case NF_ESTABLISHED_LAYER_PACKET:
		{
			// pop flowctx data
			status = devtrl_popFlowestablishedData(&offset);
		}
		break;
		case NF_TCPREDIRECT_LAYER_PACKET:
		{
			status = devtrl_popTcpRedirectConnectData(&offset);
		}
		break;
		case NF_UDP_SEND:
		case NF_UDP_RECV:
		{
			status = devtrl_popUdpPacketData(&offset, pEntry->code);
		}
		break;
		default:
			ASSERT(0);
			status = STATUS_SUCCESS;
		}

		sl_lock(&g_sIolock, &lh);

		if (!NT_SUCCESS(status))
		{
			InsertHeadList(&g_IoQueryHead, &pEntry->entry);
			break;
		}

		ExFreeToNPagedLookasideList(&g_IoQueryList, pEntry);
	}

	sl_unlock(&lh);
	return offset;
}
void devctrl_serviceReads()
{
	PIRP                irp = NULL;
	PLIST_ENTRY         pIrpEntry;
	BOOLEAN             foundPendingIrp = FALSE;
	PNF_READ_RESULT		pResult = NULL;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_sIolock, &lh);

	if (IsListEmpty(&g_pendedIoRequests) || IsListEmpty(&g_IoQueryHead))
	{
		sl_unlock(&lh);
		return;
	}

	pIrpEntry = g_pendedIoRequests.Flink;
	while (pIrpEntry != &g_pendedIoRequests)
	{
		irp = CONTAINING_RECORD(pIrpEntry, IRP, Tail.Overlay.ListEntry);

		if (IoSetCancelRoutine(irp, NULL))
		{
			// 移除
			RemoveEntryList(pIrpEntry);
			foundPendingIrp = TRUE;
			break;
		}
		else
		{
			pIrpEntry = pIrpEntry->Flink;
		}
	}

	sl_unlock(&lh);

	if (!foundPendingIrp)
	{
		return;
	}

	pResult = (PNF_READ_RESULT)VerifiMmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
	if (!pResult)
	{
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return;
	}

	pResult->length = devctrl_fillBuffer();

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(NF_READ_RESULT);
	IoCompleteRequest(irp, IO_NO_INCREMENT);

}
void devctrl_ioThread(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);
	for (;;)
	{
		KeWaitForSingleObject(
			&g_ioThreadEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		if (devctrl_isShutdown())
		{
			break;
		}

		devctrl_serviceReads();
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

// inject thread
//void devctrl_tcpInjectPackets(PTCPCTX pTcpCtx)
//{
//	KLOCK_QUEUE_HANDLE lh;
//	NF_PACKET* pPacket;
//	LIST_ENTRY packets;
//	NTSTATUS status;
//	PNET_BUFFER_LIST pnbl;
//
//	KdPrint((DPREFIX"devctrl_tcpInjectPackets[%I64u]\n", pTcpCtx->id));
//
//	sl_lock(&pTcpCtx->lock, &lh);
//
//	if (pTcpCtx->closed)
//	{
//		KdPrint((DPREFIX"devctrl_tcpInjectPackets[%I64u]: closed connection\n", pTcpCtx->id));
//		sl_unlock(&lh);
//		return;
//	}
//
//	InitializeListHead(&packets);
//
//	while (!IsListEmpty(&pTcpCtx->injectPackets))
//	{
//		pPacket = (PNF_PACKET)RemoveHeadList(&pTcpCtx->injectPackets);
//		InsertTailList(&packets, &pPacket->entry);
//	}
//
//	sl_unlock(&lh);
//
//	while (!IsListEmpty(&packets))
//	{
//		pPacket = (PNF_PACKET)RemoveHeadList(&packets);
//
//		if (pPacket->isClone)
//		{
//			if (pPacket->streamData.flags & FWPS_STREAM_FLAG_SEND)
//			{
//				pPacket->streamData.flags |= FWPS_STREAM_FLAG_SEND_NODELAY;
//			}
//			else
//				if ((pPacket->streamData.flags & FWPS_STREAM_FLAG_RECEIVE) &&
//					!(pPacket->streamData.flags & FWPS_STREAM_FLAG_RECEIVE_DISCONNECT))
//				{
//					pPacket->streamData.flags |= FWPS_STREAM_FLAG_RECEIVE_PUSH;
//				}
//
//			__try {
//				status = FwpsStreamInjectAsync(g_injectionHandle,
//					0,
//					0,
//					pTcpCtx->flowHandle,
//					pPacket->calloutId,
//					pTcpCtx->layerId,
//					pPacket->streamData.flags,
//					pPacket->streamData.netBufferListChain,
//					pPacket->streamData.dataLength,
//					(FWPS_INJECT_COMPLETE)devctrl_tcpCloneInjectCompletion,
//					0);
//			}
//			__except (EXCEPTION_EXECUTE_HANDLER)
//			{
//				status = STATUS_UNSUCCESSFUL;
//			}
//
//			KdPrint((DPREFIX"devctrl_tcpInjectPackets[%I64u] clone inject status=%x\n", pTcpCtx->id, status));
//
//			if (status == STATUS_SUCCESS && pPacket->streamData.netBufferListChain)
//			{
//				pPacket->streamData.netBufferListChain = NULL;
//			}
//
//			tcpctx_freePacket(pPacket);
//		}
//		else
//		{
//			pnbl = pPacket->streamData.netBufferListChain;
//
//			if (pnbl)
//			{
//				tcpctx_addRef(pTcpCtx);
//			}
//
//			InterlockedIncrement(&g_injectCount);
//			KdPrint((DPREFIX"g_injectCount=%d\n", g_injectCount));
//
//			__try {
//
//				status = FwpsStreamInjectAsync(g_injectionHandle,
//					0,
//					0,
//					pTcpCtx->flowHandle,
//					pPacket->calloutId,
//					pTcpCtx->layerId,
//					pPacket->streamData.flags,
//					pPacket->streamData.netBufferListChain,
//					pPacket->streamData.dataLength,
//					(FWPS_INJECT_COMPLETE)devctrl_tcpInjectCompletion,
//					pPacket);
//			}
//			__except (EXCEPTION_EXECUTE_HANDLER)
//			{
//				status = STATUS_UNSUCCESSFUL;
//			}
//
//			KdPrint((DPREFIX"devctrl_tcpInjectPackets[%I64u] inject status=%x\n", pTcpCtx->id, status));
//
//			if ((status != STATUS_SUCCESS) || !pnbl)
//			{
//				if (pPacket->streamData.flags & FWPS_STREAM_FLAG_SEND)
//				{
//					devctrl_pushTcpData(pTcpCtx->id, NF_TCP_CAN_SEND, NULL, NULL);
//				}
//				else
//				{
//					devctrl_pushTcpData(pTcpCtx->id, NF_TCP_CAN_RECEIVE, NULL, NULL);
//				}
//
//				if (pnbl)
//				{
//					tcpctx_release(pTcpCtx);
//				}
//
//				tcpctx_freePacket(pPacket);
//
//				InterlockedDecrement(&g_injectCount);
//
//				KdPrint((DPREFIX"g_injectCount=%d\n", g_injectCount));
//			}
//		}
//	}
//
//}
void devctrl_injectReads()
{
	PLIST_ENTRY	pEntry = NULL;
	PTCPCTX		pTcpCtx = NULL;
	KLOCK_QUEUE_HANDLE lh;
	for (;;)
	{
		sl_lock(&g_sTInjectQueue, &lh);
		if (IsListEmpty(&g_tInjectQueue)) {
			sl_unlock(&lh);
			break;
		}

		// Get R3 Inject Packet
		pEntry = RemoveHeadList(&g_tInjectQueue);
		if (pEntry) {
			pTcpCtx = CONTAINING_RECORD(pEntry, TCPCTX, injectQueueEntry);
			if (pTcpCtx)
				pTcpCtx->inInjectQueue = FALSE;
		}

		sl_unlock(&lh);

		//devctrl_tcpInjectPackets(pTcpCtx);

		if (pTcpCtx) {
			tcp_release(pTcpCtx);
			pTcpCtx = NULL;
		}
	}
}
void devctrl_injectThread(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);
	while (1)
	{
		KeWaitForSingleObject(
			&g_threadIoEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		if (devctrl_isShutdown())
		{
			break;
		}

		devctrl_injectReads();
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}


HANDLE	devctrl_GetUdpInjectionHandle()
{
	return g_udpInjectionHandle;
}
HANDLE	devctrl_GetUdpNwV4InjectionHandle()
{
	return g_udpNwInjectionHandleV4;
}
HANDLE	devctrl_GetUdpNwV6InjectionHandle()
{
	return g_udpNwInjectionHandleV6;
}