#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) USysUser
	{
	public:
		USysUser();
		~USysUser();

		const bool uf_EnumSysUser(LPVOID pData);
	};

#ifdef __cplusplus
}
#endif


