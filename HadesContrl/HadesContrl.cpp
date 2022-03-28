// HadesContrl.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "HadesContrl.h"

#include "Wnd/MainWindow.h"

#include "resource.h"

using namespace DuiLib;

#define MAX_LOADSTRING 100

BOOL EnableShutDownPriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tkp = { 0 };
	//打开当前程序的权限令牌  
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}
	//获得某一特定权限的权限标识LUID，保存在tkp中  
	if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	//调用AdjustTokenPrivileges来提升我们需要的系统权限  
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	return TRUE;
}

void LoadResourceZip()
{
	HRSRC hResource = ::FindResource(CPaintManagerUI::GetResourceDll(), MAKEINTRESOURCE(IDR_ZIPRES1), L"ZIPRES");
	if (hResource == NULL)
		return;
	DWORD dwSize = 0;
	HGLOBAL hGlobal = ::LoadResource(CPaintManagerUI::GetResourceDll(), hResource);
	if (hGlobal == NULL)
	{
		::FreeResource(hResource);
		return;
	}
	dwSize = ::SizeofResource(CPaintManagerUI::GetResourceDll(), hResource);
	if (dwSize == 0)
		return;
	LPBYTE lpResourceZIPBuffer = new BYTE[dwSize];
	if (lpResourceZIPBuffer != NULL)
	{
		::CopyMemory(lpResourceZIPBuffer, (LPBYTE)::LockResource(hGlobal), dwSize);
	}
	::FreeResource(hResource);
	CPaintManagerUI::SetResourceZip(lpResourceZIPBuffer, dwSize);
}

/*
@Main Entry
	Load Log View Dlg && Load Base Win
*/
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	//获得系统的版本信息，让我们后面确定是否需要提升系统权限  
	OSVERSIONINFO osvi = { 0 };
	//获得参数的大小，以提供给GetVersionEx来判断这是一个新版本的OSVERSIONINFO，还是旧版本的  
	//新版本是OSVERSIONINFOEX。扩充版本  
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx(&osvi))
	{
		return FALSE;
	}
	//检查操作系统的版本，如果是NT类型的系统，需要提升系统权限  
	if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		EnableShutDownPriv();
	}
#if defined(WIN32) && !defined(UNDER_CE)
	HRESULT Hr = ::CoInitialize(NULL);
#else
	HRESULT Hr = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
#endif
	if (FAILED(Hr)) return 0;

	CPaintManagerUI::SetInstance(hInstance);

	LoadResourceZip();


	// 初始化窗口
	MainWindow mainwin;
	mainwin.Create(NULL, L"HadesMainWindow", UI_WNDSTYLE_DIALOG, WS_EX_WINDOWEDGE);
	mainwin.CenterWindow();
	mainwin.ShowModal();

	//CPaintManagerUI::MessageLoop();
	return 0;
}