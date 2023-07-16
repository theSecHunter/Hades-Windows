#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkFsd
	{
	public:
		ArkFsd();
		~ArkFsd();

		const bool nf_GetFsdInfo(LPVOID pData, const DWORD FsdinfoSize);
	};

#ifdef __cplusplus
}
#endif
