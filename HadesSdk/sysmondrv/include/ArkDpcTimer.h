#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkDpcTimer
	{
	public:
		ArkDpcTimer();
		~ArkDpcTimer();

		const bool nf_GetDpcTimerData(LPVOID pData, const DWORD DpcTimerinfoSize);
	};

#ifdef __cplusplus
}
#endif

