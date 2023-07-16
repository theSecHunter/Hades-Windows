#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkMouseKeyBoard
	{
	public:
		ArkMouseKeyBoard();
		~ArkMouseKeyBoard();

		const int nf_GetMouseKeyInfoData(LPVOID pData, const DWORD MouseKeyboardinfoSize);
	};

#ifdef __cplusplus
}
#endif

