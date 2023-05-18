#pragma once
class ArkProcessInfo
{
public:
	ArkProcessInfo();
	~ArkProcessInfo();

	bool nf_GetProcessInfo();
	bool nf_KillProcess();
	bool nf_DumpProcessMem();
	bool nf_EnumProcess(LPVOID pData, const DWORD proessinfoSize);
	bool nf_GetProcessMod(DWORD dwPiD, LPVOID pData, const DWORD proessinfoSize);
};

