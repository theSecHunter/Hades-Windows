#pragma once
#include <UIlib.h>

using namespace DuiLib;

class AboutUsWindow : public WindowImplBase
{
public:
	inline
		LPCTSTR GetWindowClassName() const { return _T("AboutUsWindow"); }
	inline
		CDuiString GetSkinFile() { return _T("AboutUsWindow.xml"); }
	inline
		CDuiString GetSkinFolder() { return _T(""); }
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
	LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
};

