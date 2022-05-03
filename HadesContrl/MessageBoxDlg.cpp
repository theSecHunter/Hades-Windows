#include "MessageBoxDlg.h"


LPCTSTR MessageBoxDlg::GetWindowClassName() const
{
	return _T("MessageBoxDlg");
}

CDuiString MessageBoxDlg::GetSkinFile()
{
	return _T("MessageBoxDlg.xml");
}
CDuiString MessageBoxDlg::GetSkinFolder()
{
	return _T("");
}

void MessageBoxDlg::Notify(TNotifyUI& msg)
{
	CDuiString strClassName = msg.pSender->GetClass();
	CDuiString strControlName = msg.pSender->GetName();

	if (msg.sType == DUI_MSGTYPE_WINDOWINIT);
	else if (msg.sType == DUI_MSGTYPE_CLICK)
	{
		if (strClassName == DUI_CTR_BUTTON)
		{
			if (strControlName == _T("MsgWin_MaliciousBehavior_Stop"))
			{
				m_msgOption->options = 1;
				Close();
			}
			else if (strControlName == _T("MsgWin_MaliciousBehavior_Allow"))
			{
				m_msgOption->options = 2;
				Close();
			}
			else if (strControlName == _T("MsgWin_MaliciousBehavior_ProcessKill"))
			{
				m_msgOption->options = 3;
				Close();
			}
		}
	}
}