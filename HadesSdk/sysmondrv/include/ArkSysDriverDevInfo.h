#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) AkrSysDriverDevInfo
	{
	public:
		AkrSysDriverDevInfo();
		~AkrSysDriverDevInfo();

		const bool nf_EnumSysMod(LPVOID pData, const DWORD proessinfoSize);
		const bool nf_GetDriverInfo();
		const bool nf_DumpDriverInfo();

	};

#ifdef __cplusplus
}
#endif

