#ifndef _NF_API_H
#define _NF_API_H

extern "C"
{
	__declspec(dllexport) int NetInit(void);
	__declspec(dllexport) int NetGetProcessInfo(UINT32* Locaaddripv4, unsigned long localport, int protocol, PVOID64 getbuffer);
	__declspec(dllexport) int NetMonitor(int code);
}

#endif