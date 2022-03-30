#include "AboutUsWindow.h"

void AboutUsWindow::Notify(TNotifyUI& msg)
{
	CDuiString strClassName = msg.pSender->GetClass();
	CDuiString strControlName = msg.pSender->GetName();

	if (msg.sType == DUI_MSGTYPE_WINDOWINIT);
	else if (msg.sType == DUI_MSGTYPE_CLICK)
	{
		if (strClassName == DUI_CTR_BUTTON)
		{
			if (strControlName == _T("AboutWinCloseBtn"))
				Close();
			else if (strControlName == _T("GithubLinkBtn"))
			{
				HINSTANCE hRslt = ShellExecute(NULL, L"open", L"https://github.com/theSecHunter", NULL, NULL, SW_SHOWNORMAL);
				if (hRslt <= (HINSTANCE)HINSTANCE_ERROR)
					hRslt = ShellExecute(NULL, L"open", L"IEXPLORE", L"https://github.com/theSecHunter", NULL, SW_SHOWNORMAL);
			}
		}
	}
}

LRESULT AboutUsWindow::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LRESULT lRes = 0;
	BOOL bHandled = TRUE;
	return __super::HandleMessage(uMsg, wParam, lParam);;
}