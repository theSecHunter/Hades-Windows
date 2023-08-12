#ifndef _NF_API_H
#define _NF_API_H

extern "C"
{
	__declspec(dllexport) int	NetNdrInitEx(void);
	__declspec(dllexport) void	NetNdrCloseEx(void);
	__declspec(dllexport) bool	GetNetNdrStusEx(void);
	__declspec(dllexport) int	NetNdrMonitorEx(int code);

	__declspec(dllexport) void	NetNdrRuleClear(void);
	__declspec(dllexport) void	NetNdrSetDenyRule(const char* cRuleName, const char* cIpAddress, const char* cProtocol, const char* cPortArray, const char* cAction);
	__declspec(dllexport) void	NetNdrSetConnectRule(const char* cRuleName, const char* cRedirectIp, const int iRedrectPort, const char* cProtocol, const char* cProcessName);
}

#endif