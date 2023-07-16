// Devctrl.cpp
//		负责和驱动交互
//		处理驱动传递过来的established_layer & mac_frame_layer 数据
#include <Windows.h>

#include "sync.h"
#include "devctrl.h"
#include "nfevents.h"
#include "nfdriver.h"
#include "workqueue.h"

static HANDLE				g_deviceHandle = NULL;
static NF_BUFFERS			g_nfBuffers;
static AutoHandle			g_hDevice;
static AutoHandle			g_hDevice_work;
static char					g_driverName[MAX_PATH] = { 0 };

PVOID64 DevctrlIoct::get_Driverhandler()
{
	if (g_deviceHandle == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	else
	{
		g_hDevice_work.Attach(g_deviceHandle);
	}
	return &g_hDevice_work;
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
	g_deviceHandle = hDevice;
	return 1;
}

int DevctrlIoct::devctrl_InitshareMem()
{
	// AutoLock lock(m_cs);

	if (m_devhandler == INVALID_HANDLE_VALUE)
	{
		return NF_STATUS_FAIL;
	}
	else
	{
		OutputDebugString(L"Attach m_devhandler Success");
		g_hDevice.Attach(m_devhandler);
		strncpy_s(g_driverName, "wfpdriver", sizeof(g_driverName));
	}

	DWORD dwBytesReturned = 0;
	RtlZeroMemory(&g_nfBuffers, sizeof(g_nfBuffers));

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	RtlZeroMemory(&ol, sizeof(ol));
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