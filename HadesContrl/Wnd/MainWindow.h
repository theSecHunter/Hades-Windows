#pragma once
#include <UIlib.h>
#include "Menu.h"

using namespace DuiLib;

class MainWindow : public WindowImplBase
{
public:

	LPCTSTR GetWindowClassName() const;
	CDuiString GetSkinFile();
	CDuiString GetSkinFolder();

	void Notify(TNotifyUI& msg);
	LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
	LRESULT HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	LRESULT OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	LRESULT OnTimer(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	
	void FlushData();
	void AddTrayIcon();
	void HadesSvcDaemon();
	void GetHadesSvctStatus();
	void GetHadesSvcConnectStatus();
	LRESULT OnTrayIcon(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

private:
	bool m_hadesSvcStatus = false;
	Menu* m_pMenu = nullptr;
	CLabelUI* m_pImage_lab = nullptr;
	CLabelUI* m_pConnectSvc_lab = nullptr;
	HANDLE m_HadesConnectStatus = nullptr;
	CHorizontalLayoutUI* pMainOptemp = nullptr;
	CHorizontalLayoutUI* pMainOpcpu = nullptr;
	CHorizontalLayoutUI* pMainOpbox = nullptr;
	NOTIFYICONDATA m_trayIcon;
};

