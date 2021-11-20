#pragma once
class ArkProcessInfo
{
public:
	ArkProcessInfo();
	~ArkProcessInfo();

	bool nf_EnumProcess();
	bool nf_GetProcessInfo();
	bool nf_GetProcessMod(DWORD Pid);
	bool nf_KillProcess();
	bool nf_DumpProcessMem();
};

