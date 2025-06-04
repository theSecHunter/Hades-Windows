/*
* ���ս���HadesContrl����Msg������ؿ��غ͹���ʹ��
* HadesContrlMsg --> HadesSvc
*/
#include <Windows.h>
#include "msgloop.h"
#include <exception>

#include "singGloal.h"

const int WM_GETMONITORSTATUS = WM_USER + 504;

LRESULT CALLBACK WndProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	static bool kStatus = false;
	static bool uStatus = false;
	try
	{
		if (Message == WM_COPYDATA)
		{
			COPYDATASTRUCT* pCopyData = (COPYDATASTRUCT*)lParam;
			switch (pCopyData->dwData)
			{
			case 1:
			{//�û�̬����
				uStatus = SingletonUMon::instance()->GetEtwMonStatus();
				if (false == uStatus)
					SingletonUMon::instance()->uMsg_EtwInit();
				else if (true == uStatus)
					SingletonUMon::instance()->uMsg_EtwClose();
			}
			break;
			case 2:
			{//�ں�̬����
				kStatus = SingletonKerMon::instance()->GetKerMonStatus();
				if (false == SingletonKerMon::instance()->GetKerInitStatus())
					SingletonKerMon::instance()->DriverInit(false); // ��ʼ������read i/o�߳�
				else
				{
					if (false == kStatus)
						SingletonKerMon::instance()->StartReadFileThread();//�������Ҫ��ʼ������Ϊ�������ڹ��� - ֻ�����߳�
				}
				if (false == kStatus)
				{
					OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Enable KernelMonitor Command");
					SingletonKerMon::instance()->OnMonitor();
					OutputDebugString(L"[HadesSvc] GetKerMonStatus Enable KernelMonitor Success");
				}
				else if (true == kStatus)
				{
					OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Disable KernelMonitor Command");
					SingletonKerMon::instance()->OffMonitor();
					OutputDebugString(L"[HadesSvc] GetKerMonStatus Disable KernelMonitor Success");
					if ((true == SingletonKerMon::instance()->GetKerInitStatus()) && (false == SingletonKerMon::instance()->GetKerBeSnipingStatus()))
						SingletonKerMon::instance()->DriverFree();
					else
						SingletonKerMon::instance()->StopReadFileThread(); // ������Ϊ����״̬�£��ر��߳� - ��ֹ�·�I/O
				}
			}
			break;
			case 3:
			{//��Ϊ����
				if (false == SingletonKerMon::instance()->GetKerInitStatus())
					SingletonKerMon::instance()->DriverInit(true);// ��ʼ��������read i/o�߳�
				kStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
				if (false == kStatus)
				{
					OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Send Enable KernelMonitor Command");
					SingletonKerMon::instance()->OnBeSnipingMonitor();
					OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Enable KernelMonitor Success");
				}
				else if (true == kStatus)
				{
					OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Disable Disable KernelMonitor Command");
					SingletonKerMon::instance()->OffBeSnipingMonitor();
					OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Disable KernelMonitor Success");
					if ((true == SingletonKerMon::instance()->GetKerInitStatus()) && (false == SingletonKerMon::instance()->GetKerMonStatus()))
						SingletonKerMon::instance()->DriverFree();
				}
			}
			break;
			default:
				break;
			}
		}
		else if (Message == WM_GETMONITORSTATUS)
		{// ��ȡ��ǰ���״̬
			do
			{
				HWND m_ControlHwnd = FindWindow(L"HadesMainWindow", NULL);
				if (!m_ControlHwnd)
					break;
				const bool bUStatus = SingletonUMon::instance()->GetEtwMonStatus();
				const DWORD dwId = bUStatus ? 0x20 : 0x21;
				::PostMessage(m_ControlHwnd, WM_GETMONITORSTATUS, dwId, NULL);
				const bool bkStatus = SingletonKerMon::instance()->GetKerMonStatus();
				const DWORD dwId1 = bkStatus ? 0x22 : 0x23;
				::PostMessage(m_ControlHwnd, WM_GETMONITORSTATUS, dwId1, NULL);
				const bool bkMStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
				const DWORD dwId2 = bkMStatus ? 0x24 : 0x25;
				::PostMessage(m_ControlHwnd, WM_GETMONITORSTATUS, dwId2, NULL);
			} while (false);				
		}
	}
	catch (const std::exception&)
	{
	}
	return DefWindowProc(hWnd, Message, wParam, lParam);
}
static DWORD WINAPI pInitWinReg(LPVOID lpThreadParameter)
{
	WNDCLASS wnd;
	wnd.style = CS_VREDRAW | CS_HREDRAW;
	wnd.lpfnWndProc = WndProc;
	wnd.cbClsExtra = NULL;
	wnd.cbWndExtra = NULL;
	wnd.hInstance = NULL;
	wnd.hIcon = NULL;
	wnd.hCursor = NULL;
	wnd.hbrBackground = (HBRUSH)COLOR_WINDOW;
	wnd.lpszMenuName = NULL;
	wnd.lpszClassName = TEXT("HadesSvc");
	RegisterClass(&wnd);
	HWND hWnd = CreateWindow(
		TEXT("HadesSvc"),
		TEXT("HadesSvc"),
		WS_OVERLAPPEDWINDOW,
		10, 10, 500, 300,
		NULL,
		NULL,
		NULL,
		NULL
	);
	if (!hWnd)
	{
		OutputDebugString(L"[HadesSvc] HadesSvc���ڴ���ʧ��");
		return 0;
	}
	ShowWindow(hWnd, SW_HIDE);
	UpdateWindow(hWnd);
	MSG  msg = {};
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

WinMsgLoop::WinMsgLoop()
{
	CreateThread(NULL, 0, pInitWinReg, 0, 0, 0);
}
WinMsgLoop::~WinMsgLoop()
{
}