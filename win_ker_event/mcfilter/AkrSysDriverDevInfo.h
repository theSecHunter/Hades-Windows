#pragma once
class AkrSysDriverDevInfo
{
public:
	AkrSysDriverDevInfo();
	~AkrSysDriverDevInfo();

	bool nf_EnumSysMod();
	bool nf_GetDriverInfo();
	bool nf_DumpDriverInfo();

};

