#pragma once
#include <UIlib.h>
#include "public.h"

using namespace DuiLib;

class MessageBoxDlg : public WindowImplBase
{
public:
	inline
		MessageBoxDlg(PMSG_DLGBUFFER& msg) { m_msgOption = msg; }

	LPCTSTR GetWindowClassName() const;
	CDuiString GetSkinFile();
	CDuiString GetSkinFolder();

	inline
		LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		if (!m_msgOption) return 0;
		return __super::OnCreate(uMsg, wParam, lParam, bHandled);
	}
	inline
		LRESULT OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		return __super::OnClose(uMsg, wParam, lParam, bHandled);
	}
	void Notify(TNotifyUI& msg);

private:
	PMSG_DLGBUFFER m_msgOption = nullptr;
};

