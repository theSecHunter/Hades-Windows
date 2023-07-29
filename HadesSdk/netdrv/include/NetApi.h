#ifndef _NF_API_H
#define _NF_API_H

extern "C"
{
	__declspec(dllexport) int NetInit(void);
	__declspec(dllexport) int NetGetProcessInfo(unsigned int* Locaaddripv4, unsigned long localport, int protocol, void* pGetbuffer);
	__declspec(dllexport) int NetMonitor(int code);
}

#endif