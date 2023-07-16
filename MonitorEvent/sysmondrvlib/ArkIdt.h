#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkIdt
	{
	public:
		ArkIdt();
		~ArkIdt();

		const bool nf_init();
		const bool nf_GetIdtData(LPVOID pData, const DWORD IdtinfoSize);
	};

#ifdef __cplusplus
}
#endif

