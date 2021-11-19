#pragma once
class AkrSysDriverDevInfo
{
public:
	AkrSysDriverDevInfo();
	~AkrSysDriverDevInfo();

	bool nf_EnumDriver();
	bool nf_GetDriverInfo();
	bool nf_DumpDriverInfo();

};

