#include "../HpTcpSvc.h"
#include "MainWindow.h"
#include "DriverManager.h"
#include "../Systeminfolib.h"
#include <usysinfo.h>
#include <TlHelp32.h>
#include <mutex>
#include <WinUser.h>
#include <UserEnv.h>
#include <stdio.h>
#include <time.h>
#include "../resource.h"
#pragma comment(lib,"Userenv.lib")

const int WM_SHOWTASK = WM_USER + 501;
const int WM_ONCLOSE = WM_USER + 502;
const int WM_ONOPEN = WM_USER + 503;
const int WM_GETMONITORSTATUS = WM_USER + 504;
const int WM_IPS_PROCESS = WM_USER + 600;

// Hades状态锁
static std::mutex			g_hadesStatuscs;
// Start线程锁
static std::mutex			g_startprocesslock;
// 动态定时器需要
static USysBaseInfo			g_DynSysBaseinfo;
// 驱动管理
static DriverManager		g_DrvManager;
const std::wstring			g_drverName = L"sysmondriver";

static HpTcpSvc				g_tcpsvc;


bool IsProcessExist(LPCTSTR lpProcessName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	BOOL bResult = Process32First(hProcessSnap, &pe32);
	bool bExist = false;
	string strExeName;
	while (bResult)
	{
		if (lstrcmpi(pe32.szExeFile, lpProcessName) == 0)
		{
			bExist = true;
			break;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return bExist;
}
std::wstring GetWStringByChar(const char* szString)
{
	std::wstring wstrString = L"";
	try
	{
		if (szString != NULL)
		{
			std::string str(szString);
			wstrString.assign(str.begin(), str.end());
		}
	}
	catch (const std::exception&)
	{
		return wstrString;
	}

	return wstrString;
}

// HpSocket Init
static DWORD WINAPI StartIocpWorkNotify(LPVOID lpThreadParameter)
{
	g_tcpsvc.hpsk_init();
	return 0;
}

// 检测驱动是否安装
bool DrvCheckStart()
{
	std::wstring pszCmd = L"sc start sysmondriver";
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	int nSeriverstatus = g_DrvManager.nf_GetServicesStatus(g_drverName.c_str());
	switch (nSeriverstatus)
	{
		// 正在运行
	case SERVICE_CONTINUE_PENDING:
	case SERVICE_RUNNING:
	case SERVICE_START_PENDING:
	{
		OutputDebugString(L"Driver Running");
		break;
	}
	break;
	// 已安装 - 未运行
	case SERVICE_STOPPED:
	case SERVICE_STOP_PENDING:
	{
		GetStartupInfo(&si);
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;
		// 启动命令行
		PROCESS_INFORMATION pi;
		CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
		Sleep(3000);
		nSeriverstatus = g_DrvManager.nf_GetServicesStatus(g_drverName.c_str());
		if (SERVICE_RUNNING == nSeriverstatus)
		{
			OutputDebugString(L"sc Driver Running");
			break;
		}
		else
		{
			OutputDebugString(L"sc Driver Install Failuer");
			return false;
		}
	}
	break;
	case 0x424:
	{//仅未安装驱动的时候提醒
		const int nret = MessageBox(NULL, L"开启内核采集需要安装驱动，系统并未安装\n示例驱动没有签名,请自行打签名或者关闭系统驱动签名认证安装.\n是否进行驱动安装开启内核态采集\n", L"提示", MB_OKCANCEL | MB_ICONWARNING);
		if (nret == 1)
		{
			wchar_t output[MAX_PATH] = { 0, };
			wsprintf(output, L"[Hades] SysMaver: %d SysMiver: %d", SYSTEMPUBLIC::sysattriinfo.verMajorVersion, SYSTEMPUBLIC::sysattriinfo.verMinorVersion);
			OutputDebugStringW(output);

			if (!g_DrvManager.nf_DriverInstall_Start(SYSTEMPUBLIC::sysattriinfo.verMajorVersion, SYSTEMPUBLIC::sysattriinfo.verMinorVersion, SYSTEMPUBLIC::sysattriinfo.Is64))
			{
				MessageBox(NULL, L"驱动安装失败，请您手动安装再次开启内核态采集", L"提示", MB_OKCANCEL);
				return false;
			}
		}
		else
			return false;
	}
	break;
	default:
		return false;
	}
	return true;
}

// 结束进程
void killProcess(const wchar_t* const processname)
{

	HANDLE hSnapshort = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshort == INVALID_HANDLE_VALUE)
	{
		return;
	}

	// 获得线程列表  
	PROCESSENTRY32 stcProcessInfo;
	stcProcessInfo.dwSize = sizeof(stcProcessInfo);
	BOOL  bRet = Process32First(hSnapshort, &stcProcessInfo);
	while (bRet)
	{
		if (lstrcatW(stcProcessInfo.szExeFile, processname) == 0)
		{
			HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, stcProcessInfo.th32ProcessID);
			::TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
			break;
		}
		bRet = Process32Next(hSnapshort, &stcProcessInfo);
	}

	CloseHandle(hSnapshort);
}
// 启动进程
bool StartHadesAgentProcess()
{
	// 启动
	wchar_t szModule[1024] = { 0, };
	GetModuleFileName(NULL, szModule, sizeof(szModule) / sizeof(char));
	std::wstring dirpath = szModule;
	if (0 >= dirpath.size())
		return false;
	int offset = dirpath.rfind(L"\\");
	if (0 >= offset)
		return false;
	dirpath = dirpath.substr(0, offset + 1);

	std::wstring cmdline;
	cmdline += dirpath;

	HANDLE hToken = NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	void* Environ;
	if (!CreateEnvironmentBlock(&Environ, hToken, FALSE))
		Environ = NULL;

	RtlZeroMemory(&si, sizeof(STARTUPINFO));
	RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	si.lpReserved = NULL;
	si.lpDesktop = NULL;
	si.lpTitle = NULL;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.cbReserved2 = NULL;
	si.lpReserved2 = NULL;

	// Start HadesAgent.exe
#ifdef _WIN64
	cmdline += L"HadesAgent64.exe";
#else
	cmdline += L"HadesAgent.exe";
#endif
	BOOL ok = CreateProcess(cmdline.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (Environ)
		DestroyEnvironmentBlock(Environ);
	if (ok) {

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	return ok;
}

// Agent/Svc/监控状态刷新
void MainWindow::UpdateHadesSvcStatus()
{
	try
	{
#ifdef _WIN64
		if (!IsProcessExist(L"HadesSvc64.exe"))
#else
		if (!IsProcessExist(L"HadesSvc.exe"))
#endif
		{
			if (!m_hadesSvcStatus)
				return;
			m_pImage_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerSvcConnectImg")));
			m_pConnectSvc_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerSvcConnectStatus")));
			m_pImage_lab->SetBkImage(L"img/normal/winmain_connectfailuer1.png");
			m_pConnectSvc_lab->SetText(L"HadesSvc未加载");
			g_hadesStatuscs.lock();
			m_hadesSvcStatus = false;
			g_hadesStatuscs.unlock();
			// Set View Button
			::PostMessage(m_hWnd, WM_GETMONITORSTATUS, 0x26, NULL);
		}
		else
		{
			if (m_hadesSvcStatus)
				return;
			m_pImage_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerSvcConnectImg")));
			m_pConnectSvc_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerSvcConnectStatus")));
			m_pImage_lab->SetBkImage(L"img/normal/winmain_connectsuccess.png");
			m_pConnectSvc_lab->SetText(L"HadesSvc已加载");
			g_hadesStatuscs.lock();
			m_hadesSvcStatus = true;
			g_hadesStatuscs.unlock();
		}
	}
	catch (const std::exception&)
	{

	}
}
void MainWindow::UpdateHadesAgentStatus()
{
	try
	{
		// 检测HadesAgent进程是否存在
#ifdef _WIN64
		if (!IsProcessExist(L"HadesAgent64.exe"))
#else
		if (!IsProcessExist(L"HadesAgent.exe"))
#endif
		{
			if (!m_hadesAgentStatus)
				return;
			m_pAgentImage_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerAgentConnectImg")));
			m_pAgentConnectSvc_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerAgentConnectStatus")));
			m_pAgentImage_lab->SetBkImage(L"img/normal/winmain_connectfailuer1.png");
			m_pAgentConnectSvc_lab->SetText(L"HadesAgent未加载");
			g_hadesStatuscs.lock();
			m_hadesAgentStatus = false;
			g_hadesStatuscs.unlock();
		}
		else
		{
			if (m_hadesAgentStatus)
				return;
			m_pAgentImage_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerAgentConnectImg")));
			m_pAgentConnectSvc_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerAgentConnectStatus")));
			m_pAgentImage_lab->SetBkImage(L"img/normal/winmain_connectsuccess.png");
			m_pAgentConnectSvc_lab->SetText(L"HadesAgent已加载");
			g_hadesStatuscs.lock();
			m_hadesAgentStatus = true;
			g_hadesStatuscs.unlock();
		}
	}
	catch (const std::exception&)
	{

	}
}
void MainWindow::UpdateMonitorSvcStatus(LPARAM lParam)
{
	try
	{
		const int dStatusId = (DWORD)lParam;
		if (!dStatusId && (0x20 <= dStatusId) && (0x26 >= dStatusId))
			return;
		// 用户态监控
		static COptionUI* pUOption = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("MainMonUserBtn")));
		static COptionUI* pKOption = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("MainMonKerBtn")));
		static COptionUI* pMOption = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("MainMonBeSnipingBtn")));
		switch (dStatusId)
		{
		case 0x20:
			pUOption->Selected(true);
			break;
		case 0x21:
			pUOption->Selected(false);
			break;
		case 0x22:
			pKOption->Selected(true);
			break;
		case 0x23:
			pKOption->Selected(false);
			break;
		case 0x24:
			pMOption->Selected(true);
			break;
		case 0x25:
			pMOption->Selected(false);
			break;
		case 0x26:
			pUOption->Selected(false);
			pKOption->Selected(false);
			pMOption->Selected(false);
			break;
		default:
			break;
		}
	}
	catch (const std::exception&)
	{

	}
}

// 注:GoAgent没有使用CreateEvent事件，这里也不用事件等待和定时器了 - 线程中5s检测一次
// HadesAgent状态展示
void MainWindow::GetHadesAgentStatus()
{
	//检测HadesAgent是否挂了
	for (;;)
	{
		UpdateHadesAgentStatus();
		Sleep(5000);
	}
}
static DWORD WINAPI HadesAgentActiveEventNotify(LPVOID lpThreadParameter)
{
	(reinterpret_cast<MainWindow*>(lpThreadParameter))->GetHadesAgentStatus();
	return 0;
}
// HadesSvc状态展示
void MainWindow::GetHadesSvcStatus()
{
	// 检测HadesSvc进程是否存在
	for (;;)
	{
		UpdateHadesSvcStatus();
		Sleep(5000);
	}
}
static DWORD WINAPI HadesSvcActiveEventNotify(LPVOID lpThreadParameter)
{
	(reinterpret_cast<MainWindow*>(lpThreadParameter))->GetHadesSvcStatus();
	return 0;
}
// 监控状态展示
void MainWindow::GetMonitorStatus()
{
	// 检测HadesSvc正在使用的监控服务
	for (;;)
	{
		HWND m_SvcHwnd = FindWindow(L"HadesSvc", L"HadesSvc");
		if (m_SvcHwnd)
			::PostMessage(m_SvcHwnd, WM_GETMONITORSTATUS, NULL, NULL);
		Sleep(5000);
	}
}
static DWORD WINAPI HadesMonitorNotify(LPVOID lpThreadParameter)
{
	(reinterpret_cast<MainWindow*>(lpThreadParameter))->GetMonitorStatus();
	return 0;
}

CDuiString MainWindow::GetSkinFile()
{
	return _T("MainWindow.xml");
}
CDuiString MainWindow::GetSkinFolder()
{
	return _T("");
}
LPCTSTR MainWindow::GetWindowClassName() const
{
	return _T("HadesMainWindow");
}

void MainWindow::InitWindows()
{
	try
	{
		//初始化数据
		Systeminfolib libobj;
		CLabelUI* pCurrentUser_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("mainwin_currentuser_lab")));
		pCurrentUser_lab->SetText(GetWStringByChar(SYSTEMPUBLIC::sysattriinfo.currentUser.c_str()).c_str());
		CLabelUI* pCpu_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("mainwin_cpu_lab")));
		pCpu_lab->SetText(GetWStringByChar(SYSTEMPUBLIC::sysattriinfo.cpuinfo.c_str()).c_str());
		CLabelUI* pSysver_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("mainwin_sysver_lab")));
		pSysver_lab->SetText(GetWStringByChar(SYSTEMPUBLIC::sysattriinfo.verkerlinfo.c_str()).c_str());
		CLabelUI* pMainbocard_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("mainwin_mainbocard_lab")));
		if (!SYSTEMPUBLIC::sysattriinfo.mainboard.empty())
			pMainbocard_lab->SetText(GetWStringByChar(SYSTEMPUBLIC::sysattriinfo.mainboard[0].c_str()).c_str());
		CLabelUI* pBattery_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("mainwin_battery_lab")));
		if (!SYSTEMPUBLIC::sysattriinfo.monitor.empty())
			pBattery_lab->SetText(GetWStringByChar(SYSTEMPUBLIC::sysattriinfo.monitor[0].c_str()).c_str());

		m_pImage_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerSvcConnectImg")));
		m_pConnectSvc_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerSvcConnectStatus")));
#ifdef _WIN64
		if (!IsProcessExist(L"HadesSvc64.exe"))
#else
		if (!IsProcessExist(L"HadesSvc.exe"))
#endif
		{
			m_pImage_lab->SetBkImage(L"img/normal/winmain_connectfailuer1.png");
			m_pConnectSvc_lab->SetText(L"HadesSvc未加载");
			g_hadesStatuscs.lock();
			m_hadesSvcStatus = false;
			g_hadesStatuscs.unlock();
		}
		else
		{
			m_pImage_lab->SetBkImage(L"img/normal/winmain_connectsuccess.png");
			m_pConnectSvc_lab->SetText(L"HadesSvc已加载");
			g_hadesStatuscs.lock();
			m_hadesSvcStatus = true;
			g_hadesStatuscs.unlock();
		}

		m_pAgentImage_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerAgentConnectImg")));
		m_pAgentConnectSvc_lab = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("ServerAgentConnectStatus")));
#ifdef _WIN64
		if (!IsProcessExist(L"HadesAgent64.exe"))
#else
		if (!IsProcessExist(L"HadesAgent.exe"))
#endif
		{
			m_pAgentImage_lab->SetBkImage(L"img/normal/winmain_connectfailuer1.png");
			m_pAgentConnectSvc_lab->SetText(L"HadesAgent未加载");
			g_hadesStatuscs.lock();
			m_hadesAgentStatus = false;
			g_hadesStatuscs.unlock();
		}
		else
		{
			m_pAgentImage_lab->SetBkImage(L"img/normal/winmain_connectsuccess.png");
			m_pAgentConnectSvc_lab->SetText(L"HadesAgent已加载");
			g_hadesStatuscs.lock();
			m_hadesAgentStatus = true;
			g_hadesStatuscs.unlock();
		}

		pMainOptemp = static_cast<CHorizontalLayoutUI*>(m_PaintManager.FindControl(_T("MainOptemperature_VLayout")));
		pMainOpcpu = static_cast<CHorizontalLayoutUI*>(m_PaintManager.FindControl(_T("MainOpCpu_VLayout")));
		pMainOpbox = static_cast<CHorizontalLayoutUI*>(m_PaintManager.FindControl(_T("MainOpBox_VLayout")));
		pMainOptemp->SetVisible(false);
		pMainOpbox->SetVisible(false);
		pMainOpcpu->SetVisible(true);
	}
	catch (const std::exception&)
	{

	}
}
void MainWindow::AddTrayIcon() {
	memset(&m_trayInfo, 0, sizeof(NOTIFYICONDATA));
	m_trayInfo.cbSize = sizeof(NOTIFYICONDATA);
	m_trayInfo.hIcon = ::LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_SMALL));
	m_trayInfo.hWnd = m_hWnd;
	lstrcpy(m_trayInfo.szTip, _T("Hades"));
	m_trayInfo.uCallbackMessage = WM_SHOWTASK;
	m_trayInfo.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	Shell_NotifyIcon(NIM_ADD, &m_trayInfo);
	ShowWindow(SW_HIDE);
}
LRESULT MainWindow::OnTrayIcon(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	if (lParam == WM_LBUTTONDOWN)
	{
		Shell_NotifyIcon(NIM_DELETE, &m_trayInfo);
		ShowWindow(SW_SHOWNORMAL);
	}
	if (lParam == WM_RBUTTONDOWN)
	{
		POINT pt; 
		GetCursorPos(&pt);
		SetForegroundWindow(m_hWnd);
		HMENU hMenu;
		hMenu = CreatePopupMenu();
		AppendMenu(hMenu, MF_STRING, WM_ONCLOSE, _T("退出"));
		AppendMenu(hMenu, MF_STRING, WM_ONOPEN, _T("打开主界面"));
		int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD, pt.x, pt.y, NULL, m_hWnd, NULL);
		if (cmd == WM_ONCLOSE)
		{
			m_trayInfo.hIcon = NULL;	
			::PostQuitMessage(0);
		}
		else if (cmd == WM_ONOPEN)
		{
			ShowWindow(SW_SHOW);
		}
		Shell_NotifyIcon(NIM_DELETE, &m_trayInfo);
	}
	bHandled = true;
	return 0;
}
LRESULT MainWindow::OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	LRESULT lRes = __super::OnCreate(uMsg, wParam, lParam, bHandled);

	// Create Meue
	m_pMenu = new Menu();
	m_pMenu->Create(m_hWnd, _T(""), WS_POPUP, WS_EX_TOOLWINDOW);
	m_pMenu->ShowWindow(false);

	// 初始化界面数据
	InitWindows();
	
	// 检测HadesAgent上线
	CreateThread(NULL, NULL, HadesAgentActiveEventNotify, this, 0, 0);
	Sleep(100);

	// 检测HadesSvc上线
	CreateThread(NULL, NULL, HadesSvcActiveEventNotify, this, 0, 0);
	Sleep(100);

	// 检测监控状态
	CreateThread(NULL, NULL, HadesMonitorNotify, this, 0, 0);
	Sleep(100);
	
	// 设置定时器,刷新界面数据(cpu,mem)
	SetTimer(m_hWnd, 1, 1000, NULL);
	
	// 启动HpSocketServer等待HadesSvc - HpSocket用于行为拦截交互
	CreateThread(NULL, NULL, StartIocpWorkNotify, this, 0, 0);
	return lRes;
}
LRESULT MainWindow::OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	KillTimer(m_hWnd, 1);
	Sleep(100);
	// 界面退出是否将HadesSvc退出?
	//const auto exithandSvc = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Global\\HadesSvc_EVNET_EXIT");
	//if (exithandSvc)
	//{
	//	SetEvent(exithandSvc);
	//	CloseHandle(exithandSvc);
	//}
	
	// 退出HpSocket
	auto IocpExEvt = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"HpStopTcpSvcEvent");
	if (IocpExEvt)
	{
		SetEvent(IocpExEvt);
		Sleep(100);
		CloseHandle(IocpExEvt);
	}
	return __super::OnClose(uMsg, wParam, lParam, bHandled);
}

void MainWindow::FlushData()
{
	try
	{
		//cpu
		const double cpuutilize = g_DynSysBaseinfo.GetSysDynCpuUtiliza();
		CString m_Cpusyl;
		m_Cpusyl.Format(L"CPU: %0.2lf", cpuutilize);
		m_Cpusyl += "%";
		CLabelUI* pCpuut = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("winmain_layout_cpuinfo")));
		pCpuut->SetText(m_Cpusyl.GetBuffer());

		//memory
		const DWORD dwMem = g_DynSysBaseinfo.GetSysDynSysMem();
		// 当前占用率 Occupancy rate
		CString m_MemoryBFB;
		m_MemoryBFB.Format(L"内存: %u", dwMem);
		m_MemoryBFB += "%";
		CLabelUI* pMem = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("winmain_layout_memory")));
		pMem->SetText(m_MemoryBFB.GetBuffer());
	}
	catch (const std::exception&)
	{

	}
}
static DWORD WINAPI ThreadFlush(LPVOID lpThreadParameter)
{
	(reinterpret_cast<MainWindow*>(lpThreadParameter))->FlushData();
	return 0;
}
LRESULT MainWindow::OnTimer(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	QueueUserWorkItem(ThreadFlush, this, WT_EXECUTEDEFAULT);
	bHandled = false;
	return 0;
}

void MainWindow::Notify(TNotifyUI& msg)
{
	CDuiString strClassName = msg.pSender->GetClass();
	CDuiString strControlName = msg.pSender->GetName();

	if (msg.sType == DUI_MSGTYPE_WINDOWINIT);
	else if (msg.sType == DUI_MSGTYPE_CLICK)
	{
		if (strClassName == DUI_CTR_BUTTON)
		{
			if (strControlName == _T("MainCloseBtn"))
			{
				const int nret = MessageBox(m_hWnd, L"点击关闭,您希望是否隐藏至托盘？", L"提示", MB_OKCANCEL | MB_ICONWARNING);
				if (1 == nret)
					AddTrayIcon();
				else
					Close();
			}
			else if (strControlName == _T("MainMenuBtn"))
			{//菜单
				int xPos = msg.pSender->GetPos().left - 36;
				int yPos = msg.pSender->GetPos().bottom;
				POINT pt = { xPos, yPos };
				ClientToScreen(m_hWnd, &pt);
				m_pMenu->ShowWindow(true);
				::SetWindowPos(m_pMenu->GetHWND(), NULL, pt.x, pt.y, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
			}
			//最小化
			else if (strControlName == _T("MainMinsizeBtn"))
			{
				::ShowWindow(m_hWnd, SW_MINIMIZE);
			}
			else if (strControlName == _T("StartHadesAgentExe"))
			{
#ifdef _WIN64
				if (!IsProcessExist(L"HadesAgent64.exe"))
#else
				if (!IsProcessExist(L"HadesAgent.exe"))
#endif
				{
					if(StartHadesAgentProcess())
						MessageBox(m_hWnd, L"成功代理HadesAgent成功", L"提示", MB_OK);
					else
						MessageBox(m_hWnd, L"创建代理HadesAgent失败,请联系管理员", L"提示", MB_OK);
				}
				else
				{
					MessageBox(m_hWnd, L"HadesAgent已启动，如有问题联系排查", L"提示", MB_OK);
				}
			}
		}
		else if (strClassName == DUI_CTR_OPTION)
		{
			if (_tcscmp(static_cast<COptionUI*>(msg.pSender)->GetGroup(), _T("MainOpView")) == 0)
			{

				if (strControlName == _T("MainMontemperatureOpt"))
				{
					// MainOptemperature_VLayout
					pMainOptemp->SetVisible(true);
					pMainOpcpu->SetVisible(false);
					pMainOpbox->SetVisible(false);
				}
				else if (strControlName == _T("MainMonCpuOpt"))
				{
					// MainOpCpu_VLayout
					pMainOptemp->SetVisible(false);
					pMainOpcpu->SetVisible(true);
					pMainOpbox->SetVisible(false);
				}
				else if (strControlName == _T("MainMonBoxOpt"))
				{
					// MainOpBox_VLayout
					pMainOptemp->SetVisible(false);
					pMainOpcpu->SetVisible(false);
					pMainOpbox->SetVisible(true);
				}
			}
			else if (strControlName == _T("MainMonUserBtn"))
			{//下发用户态监控指令
				//COptionUI* pOption = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("MainMonUserBtn")));
				//if (!pOption)
				//	return;
				//if (false == m_hadesSvcStatus)
				//{
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"请先连接Grpc上报平台，后点击采集", L"提示", MB_OK);
				//	return;
				//}
				//HWND m_SvcHwnd = FindWindow(L"HadesSvc", L"HadesSvc");
				//COPYDATASTRUCT c2_;
				//c2_.dwData = 1;
				//c2_.cbData = 0;
				//c2_.lpData = NULL;
				////发送消息
				//::SendMessage(m_SvcHwnd, WM_COPYDATA, NULL, (LPARAM)&c2_);
			}
			else if (strControlName == _T("MainMonKerBtn"))
			{//下发内核态监控指令
				//COptionUI* pOption = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("MainMonKerBtn")));
				//if (!pOption)
				//	return;
				//if (false == m_hadesSvcStatus)
				//{
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"请先连接Grpc上报平台，后点击采集", L"提示", MB_OK);
				//	return;
				//}
				//if (SYSTEMPUBLIC::sysattriinfo.verMajorVersion < 6)
				//{
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"当前系统驱动模式不兼容，请保证操作系统win7~win10之间", L"提示", MB_OK);
				//	return;
				//}
				//const bool nret = DrvCheckStart();
				//if (true == nret)
				//{
				//	HWND m_SvcHwnd = FindWindow(L"HadesSvc", L"HadesSvc");
				//	COPYDATASTRUCT c2_;
				//	c2_.dwData = 2;
				//	c2_.cbData = 0;
				//	c2_.lpData = NULL;
				//	::SendMessage(m_SvcHwnd, WM_COPYDATA, NULL, (LPARAM)&c2_);
				//}
				//else {
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"内核态监控启动失败\n请使用cmd: sc query/delete hadesmondrv查看驱动状态\ndelete删除后请重新开启。", L"提示", MB_OK);
				//}
			}
			else if (strControlName == _T("MainMonBeSnipingBtn"))
			{//拦截恶意行为
				//COptionUI* pOption = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("MainMonBeSnipingBtn")));
				//if (!pOption)
				//	return;
				//if (false == m_hadesSvcStatus)
				//{
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"请先连接Grpc上报平台，后点击采集", L"提示", MB_OK);
				//	return;
				//}
				//if (SYSTEMPUBLIC::sysattriinfo.verMajorVersion < 6)
				//{
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"当前系统驱动模式不兼容，请保证操作系统win7~win10之间", L"提示", MB_OK);
				//	return;
				//}
				//const bool nret = DrvCheckStart();
				//if (true == nret)
				//{
				//	HWND m_SvcHwnd = FindWindow(L"HadesSvc", L"HadesSvc");
				//	COPYDATASTRUCT c2_;
				//	c2_.dwData = 3;
				//	c2_.cbData = 0;
				//	c2_.lpData = NULL;
				//	::SendMessage(m_SvcHwnd, WM_COPYDATA, NULL, (LPARAM)&c2_);
				//}
				//else {
				//	pOption->Selected(true);
				//	MessageBox(m_hWnd, L"内核态监控启动失败\n请使用cmd: sc query/delete hadesmondrv查看驱动状态\ndelete删除后请重新开启。", L"提示", MB_OK);
				//}
			}
		}
	}
}
LRESULT MainWindow::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LRESULT lRes = 0;
	BOOL bHandled = TRUE;
	return __super::HandleMessage(uMsg, wParam, lParam);
}
LRESULT MainWindow::HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	LRESULT lRes = 0;
	bHandled = TRUE;

	switch (uMsg) {
	case WM_TIMER: lRes = OnTimer(uMsg, wParam, lParam, bHandled); break;	// 刷新界面数据
	case WM_SHOWTASK: OnTrayIcon(uMsg, wParam, lParam, bHandled); break;	// 托盘处理
	case WM_GETMONITORSTATUS: UpdateMonitorSvcStatus(wParam); break;		// 处理监控状态
	case WM_IPS_PROCESS: break;
	default:
		bHandled = FALSE;
		break;
	}
	if (bHandled) return lRes;
	return __super::HandleCustomMessage(uMsg, wParam, lParam, bHandled);
}