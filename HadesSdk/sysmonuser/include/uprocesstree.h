#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) UProcess
	{
	public:
		UProcess();
		~UProcess();

		const bool uf_EnumProcess(LPVOID pData);
		const bool uf_GetProcessInfo(const DWORD dwPID, LPVOID pData);
	};

#ifdef __cplusplus
}
#endif

