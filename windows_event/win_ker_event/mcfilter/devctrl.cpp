// Devctrl.cpp
//		负责和驱动交互
//		处理驱动传递过来的established_layer & mac_frame_layer 数据
#include <Windows.h>

#include "sync.h"
#include "nfevents.h"
#include "devctrl.h"

#include <fltuser.h>

#define TCP_TIMEOUT_CHECK_PERIOD	5 * 1000

#define FSCTL_DEVCTRL_BASE      FILE_DEVICE_NETWORK

#define CTL_DEVCTRL_ENABLE_MONITOR \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_STOP_MONITOR \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_OPEN_SHAREMEM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_DISENTABLE_MONITOR \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)

static NF_BUFFERS			g_nfBuffers;
static DWORD				g_nThreads = 1;
static HANDLE				g_hDevice_old;
static AutoHandle			g_hDevice;
static AutoEventHandle		g_ioPostEvent;
static AutoEventHandle		g_ioEvent;
static AutoEventHandle		g_stopEvent;
static DWORD WINAPI	nf_workThread(LPVOID lpThreadParameter);
static NF_EventHandler* g_pEventHandler = NULL;
static char	g_driverName[MAX_PATH] = { 0 };
HANDLE	g_deviceHandle;

static AutoCriticalSection	g_cs;

static AutoEventHandle		g_workThreadStartedEvent;
static AutoEventHandle		g_workThreadStoppedEvent;

enum IoctCode
{
	NF_PROCESS_INFO = 1,
	NF_THREAD_INFO,
	NF_IMAGEGMOD_INFO,
	NF_REGISTERTAB_INFO,
	NF_FILE_INFO,
	NF_SESSION_INFO
};

PVOID DevctrlIoct::get_eventhandler()
{
	return g_pEventHandler;
}

DevctrlIoct::DevctrlIoct()
{
}

DevctrlIoct::~DevctrlIoct()
{
}

int DevctrlIoct::devctrl_init()
{
	m_devhandler = NULL;
	m_threadobjhandler = NULL;
	m_alpcthreadobjhandler = NULL;
	m_dwthreadid = 0;
	g_deviceHandle = NULL;
	return 1;
}

int DevctrlIoct::devctrl_workthread()
{
	// start thread
	m_threadobjhandler = CreateThread(
		NULL, 
		0, 
		nf_workThread,
		0, 
		0, 
		&m_dwthreadid
	);
	if (!m_threadobjhandler)
		return 0;
	return 1;
}

int DevctrlIoct::devctrl_opendeviceSylink(const char* devSylinkName)
{
	if (!devSylinkName && (0 >= strlen(devSylinkName)))
		return -1;
	
	// 1. Use IOCTL Driver
	HANDLE hDevice = CreateFileA(
		devSylinkName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hDevice == INVALID_HANDLE_VALUE)
		return -1;

	//// 2. Open Minifilter Driver Port
	//HANDLE hDevice = INVALID_HANDLE_VALUE;
	//HRESULT hResult = S_OK;
	//hResult = FilterConnectCommunicationPort(L"\\KernelMiniPort", 0, NULL, 0, NULL, &hDevice);
	//if (IS_ERROR(hResult)) {
	//	OutputDebugString(L"FilterConnectCommunicationPort fail!\n");
	//	return hResult;
	//}

	m_devhandler = hDevice;
	g_deviceHandle = hDevice;
	return 1;
}

int DevctrlIoct::devctrl_InitshareMem()
{
	AutoLock lock(g_cs);

	if (m_devhandler == INVALID_HANDLE_VALUE)
	{
		return NF_STATUS_FAIL;
	}
	else
	{
		OutputDebugString(L"Attach m_devhandler Success");
		g_hDevice.Attach(m_devhandler);
		strncpy(g_driverName, "driver", sizeof(g_driverName));
	}

	DWORD dwBytesReturned = 0;
	memset(&g_nfBuffers, 0, sizeof(g_nfBuffers));

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	memset(&ol, 0, sizeof(ol));
	ol.hEvent = hEvent;

	if (!DeviceIoControl(g_hDevice,
		CTL_DEVCTRL_OPEN_SHAREMEM,
		NULL, 0,
		(LPVOID)&g_nfBuffers, sizeof(g_nfBuffers),
		NULL, &ol))
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			g_hDevice.Close();
			return NF_STATUS_FAIL;
		}
	}

	if (!GetOverlappedResult(g_hDevice, &ol, &dwBytesReturned, TRUE))
	{
		g_hDevice.Close();
		return NF_STATUS_FAIL;
	}

	if (dwBytesReturned != sizeof(g_nfBuffers))
	{
		g_hDevice.Close();
		return NF_STATUS_FAIL;
	}

	return 1;
}

int DevctrlIoct::devctrl_waitSingeObject()
{
	if(m_alpcthreadobjhandler)
		WaitForSingleObject(m_alpcthreadobjhandler, INFINITE);
	return 1;
}

void DevctrlIoct::devctrl_clean()
{
	// Send Driver Clean
	// devctrl_sendioct();

	if (m_devhandler)
	{
		CloseHandle(m_devhandler);
		m_devhandler = NULL;
	}

	if (m_threadobjhandler)
	{
		TerminateThread(m_threadobjhandler, 0);
		CloseHandle(m_threadobjhandler);
		m_threadobjhandler = NULL;
	}
}

int DevctrlIoct::devctrl_OnMonitor()
{
	return devctrl_sendioct(CTL_DEVCTRL_ENABLE_MONITOR);
}

int DevctrlIoct::devctrl_sendioct(const int ioctcode)
{
	DWORD dSize;

	if (!m_devhandler)
		return -1;

	OutputDebugString(L"devctrl_sendioct entablMonitor");
	BOOL status = DeviceIoControl(
		m_devhandler,
		ioctcode,
		NULL,
		0,
		NULL,
		0,
		&dSize,
		NULL
	);
	if (!status)
	{
		OutputDebugString(L"devctrl_sendioct Error End");
		return -2;
	}	
	return 1;
}

int DevctrlIoct::devctrl_writeio()
{
	return 0;
}

static void handleEventDispath(PNF_DATA pData)
{
	switch (pData->code)
	{
	case NF_PROCESS_INFO:
	{
		// push established - event
		g_pEventHandler->processPacket(pData->buffer, pData->bufferSize);
	}
	break;
	case NF_THREAD_INFO:
	{
		g_pEventHandler->threadPacket(pData->buffer, pData->bufferSize);
		// push datalink - event
	}
	break;
	case NF_IMAGEGMOD_INFO:
	{
		g_pEventHandler->imagemodPacket(pData->buffer, pData->bufferSize);
	}
	break;
	case NF_REGISTERTAB_INFO:
	{
		g_pEventHandler->registerPacket(pData->buffer, pData->bufferSize);
	}
	break;
	case NF_FILE_INFO:
	{
		g_pEventHandler->filePacket(pData->buffer, pData->bufferSize);
	}
	break;
	case NF_SESSION_INFO:
	{
		g_pEventHandler->sessionPacket(pData->buffer, pData->bufferSize);
	}
	break;
	}
}

// ReadFile Driver Buffer
static DWORD WINAPI nf_workThread(LPVOID lpThreadParameter)
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

	for (;;)
	{
		waitTimeout = 10;
		abortBatch = false;

		// 异步去读
		for (i = 0; i < 8; i++)
		{
			readBytes = 0;

			memset(&ol, 0, sizeof(ol));

			ol.hEvent = g_ioEvent;

			if (!ReadFile(g_hDevice, &rr, sizeof(rr), NULL, &ol))
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
					abortBatch = true;
					continue;
				}
				else if (dwRes != WAIT_OBJECT_0)
				{
					goto finish;
				}

				dwRes = WaitForSingleObject(g_stopEvent, 0);
				if (dwRes == WAIT_OBJECT_0)
				{
					goto finish;
				}

				if (!GetOverlappedResult(g_hDevice, &ol, &readBytes, FALSE))
				{
					goto finish;
				}

				break;
			}

			readBytes = (DWORD)rr.length;

			if (readBytes > g_nfBuffers.inBufLen)
			{
				readBytes = (DWORD)g_nfBuffers.inBufLen;
			}

			pData = (PNF_DATA)g_nfBuffers.inBuf;

			while (readBytes >= (sizeof(NF_DATA) - 1))
			{
				handleEventDispath(pData);

				if ((pData->code == NF_PROCESS_INFO ||
					pData->code == NF_THREAD_INFO ||
					pData->code == NF_IMAGEGMOD_INFO ||
					pData->code == NF_REGISTERTAB_INFO ||
					pData->code == NF_FILE_INFO ||
					pData->code == NF_SESSION_INFO)
					&&
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
	}

finish:

	CancelIo(g_hDevice);
	SetEvent(g_workThreadStoppedEvent);

	OutputDebugString(L"ReadFile Thread Exit");
	return 0;
}

void DevctrlIoct::nf_setEventHandler(PVOID64 pHandler)
{
	g_pEventHandler = (NF_EventHandler*)pHandler;
}