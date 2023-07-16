#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) UAutoStart
	{
	public:
		UAutoStart();
		~UAutoStart();

		const bool uf_EnumAutoStartask(LPVOID pData, const DWORD dwSize);
	};

#ifdef __cplusplus
}
#endif