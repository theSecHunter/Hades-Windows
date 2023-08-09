#ifndef _NF_API_H
#define _NF_API_H

extern "C"
{
	__declspec(dllexport) int NetNdrInitEx(void);
	__declspec(dllexport) void NetNdrCloseEx(void);
	__declspec(dllexport) bool GetNetNdrStusEx(void);
	__declspec(dllexport) int NetNdrGetProcessInfoEx(unsigned int* Locaaddripv4, unsigned long localport, int protocol, void* pGetbuffer);
	__declspec(dllexport) int NetNdrMonitorEx(int code);
}

#endif