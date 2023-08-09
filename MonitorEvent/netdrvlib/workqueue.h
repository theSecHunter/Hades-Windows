#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

const bool		InitWorkQueue(PVOID64 Eventhandle);
DWORD WINAPI	ReadWorkThread(LPVOID lpThreadParameter);

#endif // !_WORKQUEUE_H
