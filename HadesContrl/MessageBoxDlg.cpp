#include "MessageBoxDlg.h"
#include <Psapi.h>
#include <Windows.h>
#include <xstring>

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

void ShowProcName(uint32_t pid, wchar_t* processpath)
{
	//必须具有的权限
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (processHandle == NULL) {
		return;
	}
	//auto len = GetModuleBaseName(processHandle, NULL, processpath, MAX_PATH);
	//if (len == 0) {
	//	printf("Get base namefailed, err: %u", GetLastError());
	//}
	//printf("%s\n", tempProcName);
	auto len = GetModuleFileNameEx(processHandle, NULL, processpath, MAX_PATH);
	//printf("%s\n", tempProcName);
	//GetProcessImageFileName(processHandle, tempProcName, MAX_PATH);
	//printf("%s\n", tempProcName);
	//CloseHandle(processHandle);
}
void MessageBoxDlg::MsgBoxTimerDefuleCloseNotify()
{
	CLabelUI* pButtonStrtimer = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("MsgWin_MaBe_Stop")));
	if (!pButtonStrtimer)
		return;
	int timer = 10;
	wchar_t timerwString[MAX_PATH] = { 0, };
	while (true)
	{
		if (true == m_buttonevent || timer == 1)
			break;
		wsprintf(timerwString, L"阻止(%ds)", timer--);
		pButtonStrtimer->SetText(timerwString);
		Sleep(1000);
	}
	// false意味着用户没有点击
	if (false == m_buttonevent)
	{
		m_msgOption->options = 1;
		Close();
	}
	return;
}
static DWORD WINAPI MsgBoxTimerDefuleCloseThread(LPVOID lpThreadParameter)
{
	MessageBoxDlg* msglib = (MessageBoxDlg*)lpThreadParameter;
	if (msglib)
		msglib->MsgBoxTimerDefuleCloseNotify();
	return 0;
}
LRESULT MessageBoxDlg::OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	LRESULT lRes = __super::OnCreate(uMsg, wParam, lParam, bHandled);
	do {
		if (!m_msgOption || !m_msginfo)
			break;
		taskId = m_msgOption->options;
		// 进程
		if (IPS_PROCESSSTART == taskId)
		{
			PPROCESSINFO procinfo = (PPROCESSINFO)m_msginfo;
			if (!procinfo)
				break;
			// parentpid to parentpname
			CLabelUI* pLabSrcStr = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("MsgWin_MaBe_SrcProcess")));
			if (!pLabSrcStr)
				break;
			wchar_t processPathName[MAX_PATH] = { 0, };
			ShowProcName(procinfo->parentprocessid, processPathName);
			pLabSrcStr->SetText(processPathName);
			CLabelUI* pLabDrcStr = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("MsgWin_MaBe_DestProcess")));
			if (!pLabDrcStr)
				break;
			if(!lstrlenW(procinfo->commandLine))
				pLabDrcStr->SetText(procinfo->queryprocesspath);
			else
				pLabDrcStr->SetText(procinfo->commandLine);
			CLabelUI* pLabDescribe = static_cast<CLabelUI*>(m_PaintManager.FindControl(_T("MsgWin_MaBe_Describe")));
			if (!pLabDescribe)
				break;
			pLabDescribe->SetText(L"敏感进程执行");
			// Wait
			m_msgboxtunertr = CreateThread(NULL, 0, MsgBoxTimerDefuleCloseThread, this, 0, NULL);
		}
	} while (false);
	return lRes;
}

void MessageBoxDlg::buttonEventModifyStatus()
{
	m_buttonevent = true;
	// 隐藏窗口 - 等待回调结束
	::ShowWindow(m_hWnd, SW_HIDE);
	if (m_msgboxtunertr)
	{
		WaitForSingleObject(m_msgboxtunertr, 2000);
		CloseHandle(m_msgboxtunertr);
		m_msgboxtunertr = nullptr;
	}
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
			if (strControlName == _T("MsgWin_MaBe_Stop"))
			{
				m_msgOption->options = 1;
				buttonEventModifyStatus();
				Close();
			}
			else if (strControlName == _T("MsgWin_MaBe_Allow"))
			{
				m_msgOption->options = 2;
				buttonEventModifyStatus();
				Close();
			}
			else if (strControlName == _T("MsgWin_MaBe_ProcessKill"))
			{
				m_msgOption->options = 3;
				buttonEventModifyStatus();
				Close();
			}
		}
	}
}