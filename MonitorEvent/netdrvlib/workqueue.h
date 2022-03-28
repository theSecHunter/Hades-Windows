#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

enum IoctCode
{
	NF_DATALINKMAC_LAYER_PACKET = 1,
	NF_ESTABLISHED_LAYER_PACKET,
	NF_TCPREDIRECT_LAYER_PACKET
};

DWORD WINAPI	nf_workThread(LPVOID lpThreadParameter);
bool			nf_InitWorkQueue(PVOID64 Eventhandle);

#endif // !_WORKQUEUE_H
