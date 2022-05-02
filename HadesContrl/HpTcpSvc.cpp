#include "framework.h"
#include "HpTcpSvc.h"
#include "MessageBoxDlg.h"

HpTcpSvc::HpTcpSvc()
{
}

HpTcpSvc::~HpTcpSvc()
{
}

bool HpTcpSvc::hpsk_init()
{
	try
	{
		// 1. Create listener object
		m_listener = new HpTcpSvc;
		if (!m_listener)
			return false;
		// 2. Create component object (and binding with listener object)
		CTcpPullServerPtr s_pserver(m_listener);
		// 3. Start component object
		if (!s_pserver->Start(L"127.0.0.1", 10246))
			exit(1);
		// 4. wating stop event
		HANDLE stopevent = CreateEvent(NULL, FALSE, FALSE, L"HpStopTcpSvcEvent");
		if (!stopevent)
			return false;
		WaitForSingleObject(stopevent, INFINITE);
		if (s_pserver)
			s_pserver->Stop();
		CloseHandle(stopevent);
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

EnHandleResult HpTcpSvc::OnPrepareListen(ITcpServer* pSender, SOCKET soListen)
{
	return HR_OK;
}
EnHandleResult HpTcpSvc::OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient)
{
	return HR_OK;
}
EnHandleResult HpTcpSvc::OnHandShake(ITcpServer* pSender, CONNID dwConnID)
{
	return HR_OK;
}
EnHandleResult HpTcpSvc::OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength)
{
	if (!pSender || !dwConnID)
		return HR_ERROR;

	// 处理单指令消息
	if (sizeof(const int) == iLength) 
	{
		const int taskid = *((int*)dwConnID);
		switch (taskid)
		{
		case IPS_PROCESSSTART: 
		{
			int options = 0;
			MSG_DLGBUFFER* pMsgbuf = (MSG_DLGBUFFER*)new MSG_DLGBUFFER;
			do {
				if (!pMsgbuf)
					break;
				MessageBoxDlg msgdlg(pMsgbuf);
				msgdlg.Create(NULL, L"", UI_WNDSTYLE_DIALOG, WS_EX_WINDOWEDGE);
				msgdlg.CenterWindow();
				msgdlg.ShowModal();
				// 根据对象判断是否允许
				if (!pMsgbuf)
					break;
				options = pMsgbuf->options;
			} while (0);
			if (pMsgbuf)
			{
				delete pMsgbuf;
				pMsgbuf = nullptr;
			}
			pSender->Send(dwConnID, (const BYTE*)&options, sizeof(int));
		}
		break;
		}

	}
	return HR_OK;
}
EnHandleResult HpTcpSvc::OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	return HR_OK;
}
EnHandleResult HpTcpSvc::OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	return HR_OK;
}
EnHandleResult HpTcpSvc::OnShutdown(ITcpServer* pSender)
{
	return HR_OK;
}