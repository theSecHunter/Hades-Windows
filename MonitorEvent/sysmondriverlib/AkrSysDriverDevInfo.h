#pragma once
class AkrSysDriverDevInfo
{
public:
	AkrSysDriverDevInfo();
	~AkrSysDriverDevInfo();

	bool nf_EnumSysMod(LPVOID outBuf, const DWORD proessinfosize);
	bool nf_GetDriverInfo();
	bool nf_DumpDriverInfo();

};

