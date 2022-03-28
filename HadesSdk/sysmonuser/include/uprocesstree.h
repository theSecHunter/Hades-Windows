#pragma once
class UProcess
{
public:
	UProcess();
	~UProcess();

	BOOL uf_EnumProcess(LPVOID outbuf);
	BOOL uf_GetProcessInfo(const DWORD pid, LPVOID outbuf);

private:

};