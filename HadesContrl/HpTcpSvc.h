#pragma once
#ifndef _HPTCPSVC_H
#define _HPTCPSVC_H

#include <HPSocket.h>

class HpTcpSvc : public CTcpServerListener //ITcpServerListener
{
public:
	HpTcpSvc();
	~HpTcpSvc();

	bool hpsk_init();
	virtual EnHandleResult OnPrepareListen(ITcpServer* pSender, SOCKET soListen);
	virtual EnHandleResult OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient);
	virtual EnHandleResult OnHandShake(ITcpServer* pSender, CONNID dwConnID);
	virtual EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength);
	virtual EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	virtual EnHandleResult OnShutdown(ITcpServer* pSender);

private:
	HpTcpSvc* m_listener = nullptr;
};


#endif // !_HPTCPSVC_H

