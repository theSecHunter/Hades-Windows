#ifndef _NF_API_H
#define _NF_API_H

extern "C"
{
	__declspec(dllexport) int nf_init(void);
	// NFAPI_API void NFAPI_CC nf_getprocessinfo();
	__declspec(dllexport) int nf_getprocessinfo(__int32* Locaaddripv4, unsigned long localport, int protocol, __int64 getbuffer);
	__declspec(dllexport) int nf_monitor(int code);
}

#endif