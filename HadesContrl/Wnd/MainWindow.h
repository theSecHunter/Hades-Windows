#pragma once
#include <UIlib.h>
#include "Menu.h"
#include <xstring>
#include <shellapi.h>

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
	
	void InitWindows();
	void FlushData();
	void AddTrayIcon();
	void GetHadesSvcStatus();
	void UpdateHadesSvcStatus();
	void GetHadesAgentStatus();
	void UpdateHadesAgentStatus();
	void GetMonitorStatus();
	void UpdateMonitorSvcStatus(LPARAM lParam);
	LRESULT OnTrayIcon(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

private:
	std::wstring m_cmdline;
	bool m_hadesSvcStatus = false;
	bool m_hadesAgentStatus = false;
	Menu* m_pMenu = nullptr;
	CLabelUI* m_pImage_lab = nullptr;
	CLabelUI* m_pConnectSvc_lab = nullptr;
	CLabelUI* m_pAgentImage_lab = nullptr;
	CLabelUI* m_pAgentConnectSvc_lab = nullptr;
	CHorizontalLayoutUI* pMainOptemp = nullptr;
	CHorizontalLayoutUI* pMainOpcpu = nullptr;
	CHorizontalLayoutUI* pMainOpbox = nullptr;
	NOTIFYICONDATA m_trayInfo;
};

