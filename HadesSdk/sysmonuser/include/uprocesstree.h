#pragma once
class UProcess
{
public:
	UProcess();
	~UProcess();

	BOOL uf_EnumProcess(LPVOID pData);
	BOOL uf_GetProcessInfo(const DWORD dwPID, LPVOID pData);
};