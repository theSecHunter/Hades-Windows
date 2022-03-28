#pragma once
class ArkProcessInfo
{
public:
	ArkProcessInfo();
	~ArkProcessInfo();

	bool nf_GetProcessInfo();
	bool nf_KillProcess();
	bool nf_DumpProcessMem();
	bool nf_EnumProcess(LPVOID outBuf, const DWORD proessinfosize);
	bool nf_GetProcessMod(DWORD Pid, LPVOID outBuf, const DWORD proessinfosize);
};

