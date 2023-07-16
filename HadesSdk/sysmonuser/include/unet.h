#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) UNetWork
	{
	public:
		UNetWork();
		~UNetWork();

		const bool uf_EnumNetwork(LPVOID pData);
	};

#ifdef __cplusplus
}
#endif