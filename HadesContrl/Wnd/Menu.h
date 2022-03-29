#pragma once
#include <UIlib.h>

using namespace DuiLib;

class Menu : public WindowImplBase
{
public:
	LPCTSTR GetWindowClassName() const;
	CDuiString GetSkinFile();
	CDuiString GetSkinFolder();

	UINT GetClassStyle() const;
	void Notify(TNotifyUI& msg);

	LRESULT OnKillFocus(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	void SetAuthorityShow(bool bShow);
};

