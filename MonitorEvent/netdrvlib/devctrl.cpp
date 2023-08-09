// Devctrl.cpp
//		负责和驱动交互
//		处理驱动传递过来的Established_layer & mac_frame_layer 数据
#include <Windows.h>
#include "sync.h"
#include "nfevents.h"
#include "nfdriver.h"
#include "workqueue.h"
#include "devctrl.h"

static HANDLE				g_hDeviceHandle = NULL;
static NF_BUFFERS			g_nfBuffers;
static AutoHandle			g_hDevice;

static AutoEventHandle		g_stopEvent;
static AutoEventHandle		g_ioPostEvent;
static AutoEventHandle		g_ioEvent;
static AutoCriticalSection	g_csPost;

HANDLE DevctrlIoct::get_Driverhandler()
{
	return (g_hDeviceHandle != NULL) ? g_hDeviceHandle : NULL;
}

PVOID64 DevctrlIoct::get_nfBufferPtr()
{
	return &g_nfBuffers;
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
	g_hDeviceHandle = NULL;
	return 1;
}

int DevctrlIoct::devctrl_workthread()
{
	// start thread
	m_threadobjhandler = CreateThread(
		NULL, 
		0, 
		ReadWorkThread,
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
	if (!devSylinkName || (0 >= strlen(devSylinkName)))
		return -1;
	
	// Open Driver
	const HANDLE hDevice = CreateFileA(
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

	m_devhandler = hDevice;
	g_hDeviceHandle = hDevice;
	g_hDevice.Attach(m_devhandler);
	return 1;
}

int DevctrlIoct::devctrl_InitshareMem()
{
	if (m_devhandler == INVALID_HANDLE_VALUE)
	{
		return NF_STATUS_FAIL;
	}

	DWORD dwBytesReturned = 0;
	RtlZeroMemory(&g_nfBuffers, sizeof(g_nfBuffers));

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	RtlZeroMemory(&ol, sizeof(ol));
	ol.hEvent = hEvent;

	if (!DeviceIoControl(
		g_hDevice,
		CTL_DEVCTRL_OPEN_SHAREMEM,
		NULL, 0,
		(LPVOID)&g_nfBuffers,
		sizeof(g_nfBuffers),
		NULL,
		&ol))
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

int DevctrlIoct::devctrl_writeio(PNF_DATA pData)
{
	OVERLAPPED ol;
	DWORD dwRes;
	DWORD dwWritten = 0;
	HANDLE events[] = { g_ioPostEvent, g_stopEvent };
	NF_READ_RESULT rr;

	rr.length = sizeof(NF_DATA) + pData->bufferSize - 1;
	if (rr.length > g_nfBuffers.outBufLen)
	{
		return NF_STATUS_IO_ERROR;
	}
	if (g_hDevice == INVALID_HANDLE_VALUE || !g_nfBuffers.outBuf)
		return NF_STATUS_NOT_INITIALIZED;

	AutoLock lock(g_csPost);
	RtlCopyMemory((void*)g_nfBuffers.outBuf, pData, (size_t)rr.length);
	RtlSecureZeroMemory(&ol, sizeof(ol));
	ol.hEvent = g_ioPostEvent;
	if (!WriteFile(g_hDevice, &rr, sizeof(rr), NULL, &ol))
	{
		if (GetLastError() != ERROR_IO_PENDING)
			return NF_STATUS_IO_ERROR;
	}

	// Wait for completion
	for (;;)
	{
		dwRes = WaitForMultipleObjects(
			sizeof(events) / sizeof(events[0]),
			events,
			FALSE,
			INFINITE);

		if (dwRes != WAIT_OBJECT_0)
		{
			CancelIo(g_hDevice);
			return NF_STATUS_FAIL;
		}

		dwRes = WaitForSingleObject(g_stopEvent, 0);
		if (dwRes == WAIT_OBJECT_0)
		{
			CancelIo(g_hDevice);
			return NF_STATUS_FAIL;
		}

		if (!GetOverlappedResult(g_hDevice, &ol, &dwWritten, FALSE))
		{
			return NF_STATUS_FAIL;
		}

		break;
	}
	return (dwWritten) ? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}