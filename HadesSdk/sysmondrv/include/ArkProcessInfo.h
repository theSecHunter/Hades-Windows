#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkProcessInfo
	{
	public:
		ArkProcessInfo();
		~ArkProcessInfo();

		const bool nf_GetProcessInfo();
		const bool nf_KillProcess();
		const bool nf_DumpProcessMem();
		const bool nf_EnumProcess(LPVOID pData, const DWORD proessinfoSize);
		const bool nf_GetProcessMod(DWORD dwPiD, LPVOID pData, const DWORD proessinfoSize);
	};

#ifdef __cplusplus
}
#endif
