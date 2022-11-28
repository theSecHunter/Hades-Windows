// Devctrl.cpp
//		负责和驱动交互
//		处理驱动传递过来的established_layer & mac_frame_layer 数据
#include <Windows.h>
#include "sync.h"
#include "nfevents.h"
#include <xstring>
#include <vector>
#include "ArkDrvlib.h"

#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib, "Tdh.lib")
using namespace std;

#define TCP_TIMEOUT_CHECK_PERIOD	5 * 1000
#define FSCTL_DEVCTRL_BASE      FILE_DEVICE_NETWORK


static NF_BUFFERS			g_nfBuffers;
static DWORD				g_nThreads = 1;
static HANDLE				g_hDevice_old;
static AutoHandle			g_hDevice;
static AutoEventHandle		g_ioPostEvent;
static AutoEventHandle		g_ioEvent;
static AutoEventHandle		g_stopEvent;
static NF_EventHandler*		g_pEventHandler = NULL;
static char					g_driverName[MAX_PATH] = { 0 };
static bool					g_exitthread = false;
static DWORD WINAPI	nf_workThread(LPVOID lpThreadParameter);

static AutoCriticalSection	g_cs;
static AutoEventHandle		g_workThreadStartedEvent;
static AutoEventHandle		g_workThreadStoppedEvent;

// Grpc task Queue_buffer ptr
static std::queue<UPubNode*>*	g_KernelQueue_Ptr = NULL;
static std::mutex*				g_KernelQueueCs_Ptr = NULL;
static HANDLE                   g_KjobQueue_Event = NULL;

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

void DevctrlIoct::kf_setqueuetaskptr(std::queue<UPubNode*>& qptr) { g_KernelQueue_Ptr = &qptr; }
void DevctrlIoct::kf_setqueuelockptr(std::mutex& qptrcs) { g_KernelQueueCs_Ptr = &qptrcs; }
void DevctrlIoct::kf_setqueueeventptr(HANDLE& eventptr) { g_KjobQueue_Event = eventptr; }

int DevctrlIoct::devctrl_init()
{
	m_devhandler = NULL;
	m_threadobjhandler = NULL;
	m_alpcthreadobjhandler = NULL;
	m_dwthreadid = 0;
	g_exitthread = false;
	return 1;
}
void DevctrlIoct::devctrl_stopthread()
{
	g_exitthread = true;
	Sleep(100);
	if (m_threadobjhandler)
	{
		WaitForSingleObject(m_threadobjhandler, 1000);
		TerminateThread(m_threadobjhandler, 0);
		CloseHandle(m_threadobjhandler);
		m_threadobjhandler = NULL;
	}
}
void DevctrlIoct::devctrl_startthread()
{
	g_exitthread = false;
	devctrl_workthread(NULL, false);
}
void DevctrlIoct::devctrl_free()
{
	devctrl_stopthread();
	if (g_hDevice.m_h)
	{
		g_hDevice.Close();
	}
	Sleep(100);
}

int DevctrlIoct::devctrl_workthread(LPVOID grpcobj, const bool flag)
{
	if (flag)
		return 1;
	// start thread
	m_threadobjhandler = CreateThread(
		NULL, 
		0, 
		nf_workThread,
		grpcobj,
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

	m_devhandler = hDevice;
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
		strncpy_s(g_driverName, "driver", sizeof(g_driverName));
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
int DevctrlIoct::devctrl_OnMonitor()
{
	//SetEvent(g_HadesMonStopEvent);
	DWORD InSize = 0;
	DWORD OutSize = 0;
	DWORD dwSize = 0;
	return devctrl_sendioct(CTL_DEVCTRL_ENABLE_MONITOR, NULL, InSize, NULL, OutSize, dwSize);
}
int DevctrlIoct::devctrl_OffMonitor()
{
	// 发送暂停I/O消息
	DWORD InSize = 0;
	DWORD OutSize = 0;
	DWORD dwSize = 0;
	return devctrl_sendioct(CTL_DEVCTRL_DISENTABLE_MONITOR, NULL, InSize, NULL, OutSize, dwSize);
}
int DevctrlIoct::devctrl_OnIpsMonitor()
{
	DWORD InSize = 0;
	DWORD OutSize = 0;
	DWORD dwSize = 0;
	return devctrl_sendioct(CTL_DEVCTRL_ENABLE_IPS_MONITOR, NULL, InSize, NULL, OutSize, dwSize);
}
int DevctrlIoct::devctrl_OffIpsMonitor()
{
	DWORD InSize = 0;
	DWORD OutSize = 0;
	DWORD dwSize = 0;
	return devctrl_sendioct(CTL_DEVCTRL_DISENTABLE_IPS_MONITOR, NULL, InSize, NULL, OutSize, dwSize);
}
int DevctrlIoct::devctrl_SetIpsProcessNameList(const DWORD code, const wchar_t* buf)
{
	DWORD dwBytesReturned;
	AutoLock lock(g_cs);
	if (g_hDevice == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	if (!buf)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (DeviceIoControl(g_hDevice,
		code,
		(LPVOID)buf, (lstrlenW(buf) + 1) * sizeof(WCHAR),
		NULL, 0,
		&dwBytesReturned, NULL))
	{
		return TRUE;
	}
	return FALSE;
}
int DevctrlIoct::devctrl_SetIpsFilterMods(const DWORD32 code, const int mods)
{
	DWORD dwBytesReturned;
	AutoLock lock(g_cs);
	if (g_hDevice == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	if (mods <= 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (DeviceIoControl(g_hDevice,
		code,
		(LPVOID)&mods, sizeof(DWORD32),
		NULL, 0,
		&dwBytesReturned, NULL))
	{
		return TRUE;
	}
	return FALSE;
}

bool DevctrlIoct::devctrl_sendioct(
	const int ioctcode,
	LPVOID lpInBuffer,
	DWORD InBufSize,
	LPVOID lpOutBuffer,
	DWORD OutBufSize,
	DWORD& dSize
	)
{
	if (!g_hDevice.m_h)
		return false;

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	memset(&ol, 0, sizeof(ol));
	ol.hEvent = hEvent;

	BOOL status = DeviceIoControl(
		g_hDevice,
		ioctcode,
		lpInBuffer,
		InBufSize,
		lpOutBuffer,
		OutBufSize,
		NULL,
		&ol
	);
	DWORD dwBytesReturned = 0;
	if (!GetOverlappedResult(g_hDevice, &ol, &dwBytesReturned, TRUE))
	{
		g_hDevice.Close();
		return NF_STATUS_FAIL;
	}

	if (dwBytesReturned != OutBufSize)
	{
		g_hDevice.Close();
		return NF_STATUS_FAIL;
	}
	return true;
}

int DevctrlIoct::devctrl_writeio()
{
	return 0;
}
bool GetFileSign(LPCWSTR lpFilePath, vector<wstring>& signs)
{
	bool bRet = false;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	DWORD dwEncoding = 0;
	bRet = CryptQueryObject(CERT_QUERY_OBJECT_FILE, lpFilePath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, NULL, NULL, &hStore, &hMsg, NULL);
	if (bRet)
	{
		DWORD dwSize = 0;
		if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSize))
		{
			PCMSG_SIGNER_INFO pSignerInfo = NULL;
			pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
			if (pSignerInfo)
			{
				if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSize))
				{
					CERT_INFO certInfo;
					certInfo.Issuer = pSignerInfo->Issuer;
					certInfo.SerialNumber = pSignerInfo->SerialNumber;
					PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
					if (pCertContext)
					{
						TCHAR buf[1024] = { 0 };
						CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, buf, 1024);
						if (buf[0])
						{
							signs.push_back(buf);
							bRet = true;
						}
						CertFreeCertificateContext(pCertContext);
					}
					DWORD n = 0;
					for (; n < pSignerInfo->UnauthAttrs.cAttr; n++)
					{
#define szOID_NESTED_SIGNATURE "1.3.6.1.4.1.311.2.4.1"
						if (!lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_NESTED_SIGNATURE))
						{
							break;
						}
					}
					if (n < pSignerInfo->UnauthAttrs.cAttr)
					{
						PBYTE pbCurrData = pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData;
						DWORD cbCurrData = pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData;
						HCRYPTMSG hNestedMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, 0);
						if (hNestedMsg)
						{
							CONST UCHAR _ProtoCoded[] = { 0x30, 0x82, };
							CONST UCHAR _SignedData[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, };
							while (pbCurrData > (BYTE*)pSignerInfo && pbCurrData < (BYTE*)pSignerInfo + dwSize)
							{
								if (memcmp(pbCurrData + 0, _ProtoCoded, sizeof(_ProtoCoded)) ||
									memcmp(pbCurrData + 6, _SignedData, sizeof(_SignedData)))
								{
									break;
								}
#define XCH_WORD_LITEND(num) \
	(WORD)(((((WORD)num) & 0xFF00) >> 8) | ((((WORD)num) & 0x00FF) << 8))
#define _8BYTE_ALIGN(offset, base) \
	(((offset + base + 7) & 0xFFFFFFF8L) - (base & 0xFFFFFFF8L))
								cbCurrData = XCH_WORD_LITEND(*(WORD*)(pbCurrData + 2)) + 4;
								PBYTE pbNextData = pbCurrData;
								pbNextData += _8BYTE_ALIGN(cbCurrData, (ULONG_PTR)pbCurrData);
								BOOL ret = CryptMsgUpdate(hNestedMsg, pbCurrData, cbCurrData, TRUE);
								pbCurrData = pbNextData;
								if (!ret)
								{
									continue;
								}
								DWORD dwNestedSize = 0;
								if (CryptMsgGetParam(hNestedMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwNestedSize))
								{
									PCMSG_SIGNER_INFO pNestedSignerInfo = NULL;
									pNestedSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwNestedSize);
									if (pNestedSignerInfo)
									{
										if (CryptMsgGetParam(hNestedMsg, CMSG_SIGNER_INFO_PARAM, 0, pNestedSignerInfo, &dwNestedSize))
										{
											HCERTSTORE hNestedStore = CertOpenStore(CERT_STORE_PROV_MSG, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, hNestedMsg);
											if (hNestedStore)
											{
												certInfo.Issuer = pNestedSignerInfo->Issuer;
												certInfo.SerialNumber = pNestedSignerInfo->SerialNumber;
												pCertContext = CertFindCertificateInStore(hNestedStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
												if (pCertContext)
												{
													TCHAR buf[1024] = { 0 };
													CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, buf, 1024);
													if (buf[0])
													{
														signs.push_back(buf);
														bRet = true;
													}
													CertFreeCertificateContext(pCertContext);
												}
												CertCloseStore(hNestedStore, 0);
											}
										}
										LocalFree(pNestedSignerInfo);
									}
								}
							}
							CryptMsgClose(hNestedMsg);
						}
					}
				}
				LocalFree(pSignerInfo);
			}
		}
		if (hMsg) CryptMsgClose(hMsg);
		if (hStore) CertCloseStore(hStore, 0);
	}
	return bRet;
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
static void handleEventDispath_(PNF_DATA pData)
{
	if (pData && (pData->code < 150 || pData->code > 160))
		return;
	const int buflens = sizeof(UPubNode) + pData->bufferSize;
	UPubNode* pubdata = (UPubNode*)new char[buflens];
	if (pubdata && g_KernelQueueCs_Ptr && g_KernelQueue_Ptr && g_KjobQueue_Event)
	{
		RtlZeroMemory(pubdata, buflens);
		pubdata->taskid = pData->code;
		RtlCopyMemory(&pubdata->data[0], pData->buffer, pData->bufferSize);
		// push - setevent
		g_KernelQueueCs_Ptr->lock();
		g_KernelQueue_Ptr->push(pubdata);
		g_KernelQueueCs_Ptr->unlock();
		SetEvent(g_KjobQueue_Event);
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
		if (g_exitthread)
		{
			g_exitthread = false;
			break;
		}

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
				readBytes = (DWORD)g_nfBuffers.inBufLen;
			pData = (PNF_DATA)g_nfBuffers.inBuf;
			while (readBytes >= (sizeof(NF_DATA) - 1))
			{
				//handleEventDispath(pData);
				handleEventDispath_(pData);
				if (g_exitthread)
				{
					g_exitthread = false;
					abortBatch = true;
					break;
				}
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