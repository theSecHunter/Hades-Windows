#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) UServerSoftware
	{
	public:
		UServerSoftware();
		~UServerSoftware();
		const bool uf_EnumAll(LPVOID outbuf);

	private:
		const DWORD EnumService(LPVOID pData);
		const DWORD EnumSoftware(LPVOID pData);
		const DWORD EnumSoftwareWo64(LPVOID pData, const int iCount);
		const UINT DetermineContextForAllProducts();
	};

#ifdef __cplusplus
}
#endif
