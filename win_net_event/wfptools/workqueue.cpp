#include <Windows.h>
#include "sync.h"
#include "nfevents.h"
#include "nfdriver.h"
#include "devctrl.h"
#include "workqueue.h"

const int TCP_TIMEOUT_CHECK_PERIOD = 5 * 1000;

static AutoEventHandle		g_ioPostEvent;
static AutoEventHandle		g_ioEvent;
static AutoEventHandle		g_stopEvent;
static NF_EventHandler*		g_pEventHandler = NULL;
static AutoCriticalSection	g_cs;
static DWORD				g_nThreads = 1;

static DevctrlIoct			g_devctl;
static AutoHandle*			g_workhDevice = NULL;
static NF_BUFFERS*			g_workBuffer = NULL;

#include "EventQueue.h"

static EventQueue<NFEvent>		g_eventQueue;
static EventQueue<NFEventOut>	g_eventQueueOut;

static AutoEventHandle		g_workThreadStartedEvent;
static AutoEventHandle		g_workThreadStoppedEvent;

bool nf_InitWorkQueue(PVOID64 Eventhandle)
{
	bool status = false;
	// 获取驱动句柄
	do {

		g_workhDevice = (AutoHandle*)g_devctl.get_Driverhandler();
		if (!g_workhDevice && !(*g_workhDevice))
			break;

		// 获取共享内存buffer
		g_workBuffer = (NF_BUFFERS*)g_devctl.get_nfBufferPtr();
		if (!g_workBuffer && !(*g_workBuffer).inBufLen && !(*g_workBuffer).outBufLen)
			break;

		// 获取事件句柄
		g_pEventHandler = (NF_EventHandler*)Eventhandle;
		if (!g_pEventHandler)
			break;

		status = true;

	} while (false);

	return status;
}

static void handleEventDispath(PNF_DATA pData)
{
	AutoLock lock(g_cs);

	if (!g_pEventHandler)
		return;

	switch (pData->code)
	{
	case NF_ESTABLISHED_LAYER_PACKET:
	{
		// push established - event
		g_pEventHandler->establishedPacket(pData->buffer, pData->bufferSize);
	}
	break;
	case NF_DATALINKMAC_LAYER_PACKET:
	{
		g_pEventHandler->datalinkPacket(pData->buffer, pData->bufferSize);
		// push datalink - event
	}
	break;
	case NF_TCPREDIRECT_LAYER_PACKET:
	{
		// connobj_alloc(pData->id, (PNF_TCP_CONN_INFO)pData->buffer);
		AutoUnlock unlock(g_cs);
		g_eventQueue.push(pData);

		//g_pEventHandler->tcpredirectPacket(pData->buffer, pData->bufferSize);
	}
	break;
	}
}

// ReadFile Driver Buffer
DWORD WINAPI nf_workThread(LPVOID lpThreadParameter)
{
	DWORD readBytes;
	PNF_DATA pData;
	OVERLAPPED ol;
	DWORD dwRes;
	NF_READ_RESULT rr;
	HANDLE events[] = { g_ioEvent, g_stopEvent };
	DWORD waitTimeout;
	bool abortBatch;
	int i;

	OutputDebugString(L"Entry WorkThread");

	SetEvent(g_workThreadStartedEvent);
	g_eventQueue.init(g_nThreads);
	g_eventQueueOut.init(1);

	for (;;)
	{
		waitTimeout = 10;
		abortBatch = false;

		g_eventQueue.suspend(true);

		// 异步去读
		for (i = 0; i < 8; i++)
		{
			readBytes = 0;

			memset(&ol, 0, sizeof(ol));

			ol.hEvent = g_ioEvent;

			if (!ReadFile(*g_workhDevice, &rr, sizeof(rr), NULL, &ol))
			{
				if (GetLastError() != ERROR_IO_PENDING)
				{
					OutputDebugString(L"ReadFile Error!");
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

				if (!GetOverlappedResult(*g_workhDevice, &ol, &readBytes, FALSE))
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
				handleEventDispath(pData);

				if ((pData->code == NF_DATALINKMAC_LAYER_PACKET ||
					pData->code == NF_ESTABLISHED_LAYER_PACKET) &&
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

	CancelIo(*g_workhDevice);
	g_eventQueue.free();
	g_eventQueueOut.free();
	SetEvent(g_workThreadStoppedEvent);

	OutputDebugString(L"ReadFile Thread Exit");
	return 0;
}