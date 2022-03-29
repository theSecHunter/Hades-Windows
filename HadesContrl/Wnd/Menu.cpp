#include "Menu.h"

LPCTSTR Menu::GetWindowClassName() const
{
	return _T("Menu");
}

CDuiString Menu::GetSkinFile()
{
	return _T("Menu.xml");
}

CDuiString Menu::GetSkinFolder()
{
	return _T("");
}

UINT Menu::GetClassStyle() const
{
	return UI_CLASSSTYLE_FRAME | CS_DBLCLKS;
}

void Menu::Notify(TNotifyUI& msg)
{
	CDuiString strControlName = msg.pSender->GetName();
	if (msg.sType == DUI_MSGTYPE_CLICK)
	{
		if (strControlName == _T("AboutBtn"))
		{
			//AboutUsWindow auWnd;
			//auWnd.Create(GetParent(m_hWnd), _T("关于我们"), UI_WNDSTYLE_DIALOG, WS_EX_WINDOWEDGE);
			//auWnd.CenterWindow();
			//auWnd.ShowModal();
		}
	}
}

LRESULT Menu::OnKillFocus(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	ShowWindow(false);
	bHandled = FALSE;
	return 0;
}

void Menu::SetAuthorityShow(bool bShow)
{
	m_PaintManager.FindControl(_T("AboutBtn"))->SetVisible(bShow);
	if (bShow)
		ResizeClient(100, 128);
	else
		ResizeClient(100, 96);
}