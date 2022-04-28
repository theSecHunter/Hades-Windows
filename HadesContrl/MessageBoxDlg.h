#pragma once
#include <UIlib.h>

using namespace DuiLib;

class MessageBoxDlg : public WindowImplBase
{
public:
	LPCTSTR GetWindowClassName() const;
	CDuiString GetSkinFile();
	CDuiString GetSkinFolder();

	inline
		LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		LRESULT lRes = __super::OnCreate(uMsg, wParam, lParam, bHandled);
		return lRes;
	}
	inline
		LRESULT OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		return __super::OnClose(uMsg, wParam, lParam, bHandled);
	}
	void Notify(TNotifyUI& msg);
};

