#pragma once
class AkrSysDriverDevInfo
{
public:
	AkrSysDriverDevInfo();
	~AkrSysDriverDevInfo();

	bool nf_EnumSysMod(LPVOID pData, const DWORD proessinfoSize);
	bool nf_GetDriverInfo();
	bool nf_DumpDriverInfo();

};

