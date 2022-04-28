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

}