#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkSsdt
	{
	public:
		ArkSsdt();
		~ArkSsdt();

		const bool nf_init();
		const bool nf_GetSysCurrentSsdtData(LPVOID pData, const DWORD SSdtinfoSize);
	};

#ifdef __cplusplus
}
#endif
