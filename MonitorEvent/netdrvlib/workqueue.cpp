#include <Windows.h>
#include "sync.h"
#include "nfevents.h"
#include "nfdriver.h"
#include "workqueue.h"
#include "singGlobal.h"
#include "tcpctx.h"

const int TCP_TIMEOUT_CHECK_PERIOD = 5 * 1000;

static AutoEventHandle		g_ioPostEvent;
static AutoEventHandle		g_ioEvent;
static AutoEventHandle		g_stopEvent;
static NF_EventHandler*		g_pEventHandler = NULL;
static AutoCriticalSection	g_cs;
static DWORD				g_nThreads = 1;

static HANDLE				g_hWorkhDevice = NULL;
static NF_BUFFERS*			g_workBuffer = NULL;

#include "EventQueue.h"

static EventQueue<NFEvent>		g_eventQueue;
static EventQueue<NFEventOut>	g_eventQueueOut;

static AutoEventHandle			g_workThreadStartedEvent;
static AutoEventHandle			g_workThreadStoppedEvent;

// ReadFile Driver Buffer
static void OnReadHandleEventDispath(PNF_DATA pData)
{
	AutoLock lock(g_cs);

	if (!g_pEventHandler)
		return;

	switch (pData->code)
	{
	case NF_ESTABLISHED_LAYER_PACKET:
	{
		// push established - event
		g_pEventHandler->EstablishedPacket(pData->buffer, pData->bufferSize);
	}
	break;
	case NF_DATALINKMAC_LAYER_PACKET:
	{
		g_pEventHandler->DatalinkPacket(pData->buffer, pData->bufferSize);
		// push datalink - event
	}
	break;
	case NF_TCPREDIRECT_LAYER_PACKET:
	{
		if (pData->buffer && pData->bufferSize) {
			g_pEventHandler->TcpredirectPacket(pData->buffer, pData->bufferSize);
			PNF_DATA pRediRectData = (PNF_DATA)mempool::mp_alloc(sizeof(NF_DATA) - 1 + sizeof(NF_TCP_CONN_INFO));
			if (pRediRectData)
			{
				pRediRectData->id = pData->id;
				pRediRectData->code = NF_TCP_CONNECT_REQUEST;
				pRediRectData->bufferSize = sizeof(NF_TCP_CONN_INFO);
				memcpy(pRediRectData->buffer, &pData->buffer, sizeof(NF_TCP_CONN_INFO));
				SingletNetMonx::instance()->devctrl_writeio(pRediRectData);
				mempool::mp_free(pRediRectData);
			}
		}
	}
	break;
	case NF_UDP_SEND:
	{
		if (pData->buffer && pData->bufferSize)
			g_pEventHandler->UdpSend(pData->id, pData->buffer, pData->bufferSize);
	}
	break;
	case NF_UDP_RECV:
	{
		if (pData->buffer && pData->bufferSize)
			g_pEventHandler->UdpRecv(pData->id, pData->buffer, pData->bufferSize);
	}
	break;
	}
}

const bool InitWorkQueue(PVOID64 Eventhandle)
{
	bool status = false;
	// 获取驱动句柄
	do {

		g_hWorkhDevice = SingletNetMonx::instance()->get_Driverhandler();
		if (NULL == g_hWorkhDevice)
			break;

		// 获取共享内存buffer
		g_workBuffer = (NF_BUFFERS*)SingletNetMonx::instance()->get_nfBufferPtr();
		if (!g_workBuffer || !(*g_workBuffer).inBufLen || !(*g_workBuffer).outBufLen)
			break;

		// 获取事件句柄
		g_pEventHandler = (NF_EventHandler*)Eventhandle;
		if (!g_pEventHandler)
			break;

		status = true;
	} while (false);
	return status;
}

DWORD WINAPI ReadWorkThread(LPVOID lpThreadParameter)
{
	OVERLAPPED ol;
	PNF_DATA pData = NULL;
	DWORD dwRes = 0;
	DWORD readBytes = 0;
	NF_READ_RESULT rr;
	HANDLE events[] = { g_ioEvent, g_stopEvent };
	DWORD waitTimeout = 0;
	bool abortBatch = false;
	int i = 0;

	OutputDebugString(L"[HadesNetMon] Entry WorkThread");
	mempool::mempools_init();
	SetEvent(g_workThreadStartedEvent);
	g_eventQueue.init(g_nThreads);
	g_eventQueueOut.init(1);

	for (;;)
	{
		waitTimeout = 10;
		abortBatch = false;

		g_eventQueue.suspend(true);

		for (i = 0; i < 8; i++)
		{
			readBytes = 0;
			RtlSecureZeroMemory(&ol, sizeof(ol));
			ol.hEvent = g_ioEvent;

			if (!ReadFile(g_hWorkhDevice, &rr, sizeof(rr), NULL, &ol))
			{
				if (GetLastError() != ERROR_IO_PENDING)
				{
					OutputDebugString(L"[HadesNetMon] ReadFile Error!");
					goto finish;
				}
			}

			for (;;)
			{
				dwRes = WaitForMultipleObjects(
					sizeof(events) / sizeof(events[0]),
					events,
					FALSE,
					waitTimeout);

				if (dwRes == WAIT_TIMEOUT)
				{
					waitTimeout = TCP_TIMEOUT_CHECK_PERIOD;
					g_eventQueue.suspend(false);
					g_eventQueueOut.processEvents();
					g_eventQueue.processEvents();
					abortBatch = true;
					continue;
				}
				if (dwRes != WAIT_OBJECT_0)
				{
					goto finish;
				}

				dwRes = WaitForSingleObject(g_stopEvent, 0);
				if (dwRes == WAIT_OBJECT_0)
				{
					goto finish;
				}

				if (!GetOverlappedResult(g_hWorkhDevice, &ol, &readBytes, FALSE))
				{
					goto finish;
				}

				break;
			}

			readBytes = (DWORD)rr.length;
			if (readBytes > (*g_workBuffer).inBufLen)
			{
				readBytes = (DWORD)(*g_workBuffer).inBufLen;
			}

			pData = (PNF_DATA)(*g_workBuffer).inBuf;
			while (readBytes >= (sizeof(NF_DATA) - 1))
			{
				OnReadHandleEventDispath(pData);

				if ((pData->code == NF_DATALINKMAC_LAYER_PACKET ||
					pData->code == NF_ESTABLISHED_LAYER_PACKET ||
					pData->code == NF_TCPREDIRECT_LAYER_PACKET ||
					pData->code == NF_UDP_SEND ||
					pData->code == NF_UDP_RECV) &&
					pData->bufferSize < 1400)
				{
					abortBatch = true;
				}

				if (readBytes < (sizeof(NF_DATA) - 1 + pData->bufferSize))
				{
					break;
				}

				readBytes -= sizeof(NF_DATA) - 1 + pData->bufferSize;
				pData = (PNF_DATA)(pData->buffer + pData->bufferSize);
			}
			if (abortBatch)
				break;
		}

		g_eventQueue.suspend(false);
		g_eventQueueOut.processEvents();
		g_eventQueue.processEvents();
		g_eventQueue.wait(8000);
		g_eventQueueOut.wait(64000);
	}

finish:
	if (g_hWorkhDevice)
		CancelIo(g_hWorkhDevice);
	g_eventQueue.free();
	g_eventQueueOut.free();
	SetEvent(g_workThreadStoppedEvent);

	OutputDebugString(L"[HadesNetMon] ReadFile Thread Exit");
	return 0;
}