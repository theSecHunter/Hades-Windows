#ifndef _NF_API_H
#define _NF_API_H

extern "C"
{
	__declspec(dllexport) int nf_Init(void);
	__declspec(dllexport) int nf_GetProcessInfo(UINT32* Locaaddripv4, unsigned long localport, int protocol, PVOID64 getbuffer);
	__declspec(dllexport) int nf_Monitor(int code);
}

#endif