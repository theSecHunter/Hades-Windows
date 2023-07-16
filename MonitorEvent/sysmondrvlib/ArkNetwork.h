#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkNetwork
	{
	public:
		ArkNetwork();
		~ArkNetwork();

		const int nf_GetNteworkProcessInfo(LPVOID pData, const DWORD64 NetworkinfoSize);
	};

#ifdef __cplusplus
}
#endif
