#pragma once
#include <UIlib.h>
#include "public.h"
#include <mutex>

using namespace DuiLib;

class MessageBoxDlg : public WindowImplBase
{
public:
	inline
		MessageBoxDlg(PMSG_DLGBUFFER& msg, char*& msginfo) { m_msgOption = msg; m_msginfo = msginfo; }

	LPCTSTR GetWindowClassName() const;
	CDuiString GetSkinFile();
	CDuiString GetSkinFolder();
	LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	inline
		LRESULT OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		return __super::OnClose(uMsg, wParam, lParam, bHandled);
	}
	void buttonEventModifyStatus();
	void MsgBoxTimerDefuleCloseNotify();
	void Notify(TNotifyUI& msg);

private:
	int taskId = 0;
	char* m_msginfo = nullptr;
	PMSG_DLGBUFFER m_msgOption = nullptr;

	bool m_buttonevent = false;
	std::mutex m_buttonevent_cs;

	HANDLE m_msgboxtunertr = nullptr;
};

